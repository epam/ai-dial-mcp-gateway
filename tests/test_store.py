"""Tests for the registration endpoint and the durable registration store.

The store exists for one scenario: a client caches the id it was issued, and a restart
must not invalidate it. So the tests here are the scenarios that scenario decomposes into
— a registration survives a restart; it is persisted before the response is returned; a
lost store self-heals by re-registration; a corrupt one refuses startup; the cap refuses
new registrations without touching existing ones — plus the flag semantics, which decide
whether any of it is reachable at all.

Every test builds its own app over its own store file, because the store is process
state: sharing one between two configurations is the thing these tests exist to rule out.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path

import gateway.routes
import gateway.store
import pytest
from fastapi.testclient import TestClient
from gateway.errors import ConfigurationError
from gateway.state import new_client_id
from gateway.store import RegistrationError, RegistrationStore
from pydantic import ValidationError

from tests.conftest import (
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    make_client,
    make_settings,
    runtime_of,
    surface_settings,
)

# A second registered redirect URI, for the tests that check a client's list is honored.
SECOND_REDIRECT_URI = "http://127.0.0.1:8766/second-callback"

# The cap a bounded-store test configures, small so it is reached in a few requests.
SMALL_CAP = 2

# The four fields a record is allowed to carry. Asserted as a set, so a record that grows
# a field — a secret, most importantly — fails here.
RECORD_FIELDS = {"client_id", "redirect_uris", "client_name", "created_at"}

# The POSIX mode an owner-only file carries. Stated as a number so the assertion names it.
OWNER_ONLY_MODE = 0o600

# The window `client_id_issued_at` must fall inside for a registration made now. An epoch
# seconds value outside it means the conversion answered some other instant — an ISO-8601
# string's own epoch, a zero, or a millisecond count — so the bound is what makes the
# type assertion an assertion about the *value* rather than only about its class.
ISSUED_AT_EPOCH_LOW = 1_700_000_000
ISSUED_AT_EPOCH_HIGH = 2_000_000_000

# The client id the idempotent-branch test holds the route to. The route mints its own id
# on every request, so pinning the id is what makes the second registration one for an
# already-stored client rather than a second new one.
RE_REGISTERED_CLIENT_ID = "a-client-id-already-in-the-store"

# The instant the store's clock is pinned to for the same-instant tests, and its epoch
# form. Pinning the clock is what makes the property decisive: the store records its
# instant truncated to whole seconds, so a response that sampled a second `now()` would
# usually land in the same second as the record and pass by coincidence. Against a clock
# pinned years away, the same assertion fails against any value but the stored instant.
STORED_INSTANT = datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)
STORED_INSTANT_EPOCH = 1_577_934_245


class _PinnedStoreClock:
    """The store's `datetime`, pinned to one instant, for the same-instant tests.

    Only `now` is implemented, because `now` is the only member the store's write path
    uses; a member this class does not carry would fail loudly in the test rather than
    silently read the real clock.
    """

    @staticmethod
    def now(tz: object | None = None) -> datetime:
        return STORED_INSTANT


def registration_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "redirect_uris": [LOOPBACK_REDIRECT_URI],
        "client_name": "A dynamically registered client",
    }
    body.update(overrides)
    return body


def epoch_of(iso_instant: str) -> int:
    """An ISO-8601 instant as the epoch seconds RFC 7591 asks the response to carry.

    The test's own spelling of the conversion, written here rather than imported from the
    gateway: an assertion that called the implementation to produce its expected value
    would agree with the implementation by construction, including when both are wrong.
    """
    return int(datetime.fromisoformat(iso_instant).timestamp())


# The shape an ISO-8601 string has and an epoch number does not. Used by the
# negative-control test, which has to derive a value that the fix converts away and an
# unfixed pass-through would emit — an assertion of "not a number" alone would pass
# against a response that carried no issued-at member at all.
_ISO_8601 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def assert_conformant_issued_at(
    body: dict[str, object], record: dict[str, object]
) -> None:
    """The registration response's issued-at member, as RFC 7591 §3.2.1 defines it.

    Two properties, each naming a distinct way the member can be wrong: the JSON type (a
    strict client rejects the whole document on a type mismatch) and equality with the
    *stored* record's instant (the same-instant property, which a second `now()` on the
    response path would fail). The value's plausibility as a "now" is a separate assertion
    a caller makes against a clock it knows, because these tests pin the store's clock
    and so have no "now" to compare against.

    `bool` is excluded explicitly: it is an `int` in Python, and a `true` at this member
    is not the number any client asked for.
    """
    issued_at = body["client_id_issued_at"]
    assert isinstance(issued_at, int), (
        f"client_id_issued_at must be a JSON number of epoch seconds; got "
        f"{type(issued_at).__name__}: {issued_at!r}"
    )
    assert not isinstance(issued_at, bool), (
        f"client_id_issued_at must be a JSON number, not a boolean: {issued_at!r}"
    )
    assert issued_at == epoch_of(str(record["created_at"])), (
        f"client_id_issued_at answers {issued_at!r} but the stored record was created at "
        f"{record['created_at']!r} ({epoch_of(str(record['created_at']))!r}); the "
        f"response must answer the instant the store recorded"
    )


# ------------------------------------------------------------------- flag semantics


def test_registration_is_disabled_by_default(surface_client: TestClient) -> None:
    """Off by default: the endpoint answers the documented disabled-error.

    The status is 404 rather than a 400: the metadata document advertises no registration
    endpoint at all, so from a client's side this path does not exist.
    """
    response = surface_client.post("/dial/register", json=registration_body())

    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response.json()["error"] == "invalid_request"
    assert "not enabled" in response.json()["error_description"]


def test_a_disabled_registration_allocates_nothing(surface_client: TestClient) -> None:
    """A refused registration must not leave a record behind."""
    surface_client.post("/dial/register", json=registration_body())

    assert runtime_of(surface_client).registrations.path.exists() is False


def test_registration_is_accepted_while_enabled(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The positive control for the disabled branch above."""
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json=registration_body())

    assert response.status_code == HTTPStatus.CREATED
    body = response.json()
    assert body["redirect_uris"] == [LOOPBACK_REDIRECT_URI]
    assert body["token_endpoint_auth_method"] == "none"
    assert body["grant_types"] == ["authorization_code"]
    assert "client_secret" not in body


def test_the_registration_response_answers_an_epoch_number_for_the_stored_instant(
    private_key_pem: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RFC 7591 §3.2.1: `client_id_issued_at` is a number, and the stored record's instant.

    The type is asserted because a schema-strict client rejects the *entire* response
    document on a type mismatch — so a string here is not a cosmetic defect but a
    registration that never completes for the client class this endpoint exists for.

    The store's clock is pinned years away from now, which is what makes the same-instant
    assertion decisive: the record's instant is truncated to whole seconds, so against the
    real clock a response that sampled a second `now()` would usually land in the same
    second and pass. Against a pinned clock the only value that satisfies the assertion is
    the stored instant itself.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))
    monkeypatch.setattr(gateway.store, "datetime", _PinnedStoreClock)

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json=registration_body())
        stored = json.loads(store_path.read_text(encoding="utf-8"))

    assert response.status_code == HTTPStatus.CREATED
    body = response.json()
    record = stored[body["client_id"]]
    assert_conformant_issued_at(body, record)
    assert body["client_id_issued_at"] == STORED_INSTANT_EPOCH


def test_the_response_answers_the_stored_instant_and_not_the_time_of_the_request(
    private_key_pem: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative control, run against the real response: a second `now()` would fail.

    The property that separates the fix from a plausible wrong fix is *which* instant is
    answered. So this test derives the instant a response-site `datetime.now()` would have
    answered, asserts that it is a perfectly plausible epoch number (so the control is
    about the choice and not about the value being malformed), and asserts that the served
    member is the stored instant and not that one. A converted-but-sampled-fresh value
    fails here, which is the whole reason the conversion reads the record.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))
    monkeypatch.setattr(gateway.store, "datetime", _PinnedStoreClock)

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json=registration_body())
        stored = json.loads(store_path.read_text(encoding="utf-8"))

    body = response.json()
    record = stored[body["client_id"]]
    # What the response would have answered had it sampled its own time: the real clock,
    # not the pinned one, which is the difference under test.
    now_epoch = int(datetime.now(UTC).timestamp())

    assert ISSUED_AT_EPOCH_LOW <= now_epoch <= ISSUED_AT_EPOCH_HIGH
    assert_conformant_issued_at(body, record)
    assert body["client_id_issued_at"] == STORED_INSTANT_EPOCH
    assert body["client_id_issued_at"] != now_epoch


def test_the_issued_at_assertion_rejects_the_pre_fix_string(
    private_key_pem: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative-control pattern itself: the assertion can fail, and the defect fails it.

    A regression test whose assertion cannot fail is a test that reports green against any
    code at all. This one re-derives the value the defect-era response carried — the stored
    ISO-8601 string, forwarded verbatim — confirms the fixture really is that value, and
    asserts the suite's own helper refuses it. If the helper were loosened to accept a
    string, this test fails, so the type check cannot silently stop checking.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))
    monkeypatch.setattr(gateway.store, "datetime", _PinnedStoreClock)

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json=registration_body())
        stored = json.loads(store_path.read_text(encoding="utf-8"))

    body = response.json()
    record = stored[body["client_id"]]
    pre_fix_value = record["created_at"]

    # The control is the defect itself: the pass-through the fix converts away.
    assert isinstance(pre_fix_value, str)
    assert _ISO_8601.match(pre_fix_value) is not None
    assert body["client_id_issued_at"] != pre_fix_value
    with pytest.raises(AssertionError):
        assert_conformant_issued_at({"client_id_issued_at": pre_fix_value}, record)


def test_the_idempotent_branch_answers_the_stored_instant_as_a_number(
    private_key_pem: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-registration of an existing client id answers the record's own instant.

    The route mints a fresh client id on every request, so the idempotent branch of
    `RegistrationStore.add` is not reachable over the wire — the branch is exercised at
    store level below, and this test reaches it through the route by pinning the id the
    route generates (`monkeypatch` on `gateway.routes.new_client_id`). Pinning the id is
    what makes the second POST a re-registration rather than a second new registration:
    a test that merely posted twice would take the new-registration branch twice and
    would say nothing about this one.

    The store's clock is pinned and the served member is asserted against the
    literal `STORED_INSTANT_EPOCH`: the second response must answer the first
    registration's stored instant exactly. Because the pinned instant is years
    away from the real clock, a response-site `now()` cannot land on it — a
    sampled-fresh conversion fails this test outright, with no straddling-seconds
    coincidence to hide behind.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))
    monkeypatch.setattr(gateway.store, "datetime", _PinnedStoreClock)
    monkeypatch.setattr(
        gateway.routes, "new_client_id", lambda: RE_REGISTERED_CLIENT_ID
    )

    with make_client(settings, private_key_pem) as client:
        first = client.post("/dial/register", json=registration_body())
        second = client.post(
            "/dial/register",
            json=registration_body(
                redirect_uris=["http://127.0.0.1:8766/re-registration"]
            ),
        )
        stored = json.loads(store_path.read_text(encoding="utf-8"))

    assert first.status_code == HTTPStatus.CREATED
    assert second.status_code == HTTPStatus.CREATED
    record = stored[RE_REGISTERED_CLIENT_ID]

    # The record is returned unchanged, so the re-registration cannot take over another
    # registrant's redirect URIs — and the response answers that existing record.
    assert record["redirect_uris"] == [LOOPBACK_REDIRECT_URI]
    assert_conformant_issued_at(second.json(), record)
    assert second.json()["client_id_issued_at"] == first.json()["client_id_issued_at"]
    assert second.json()["client_id_issued_at"] == STORED_INSTANT_EPOCH
    # A second registration would have made the store's map grow; it did not.
    assert set(stored) == {RE_REGISTERED_CLIENT_ID}


def test_re_registering_an_existing_client_id_answers_its_stored_instant_as_a_number(
    tmp_path: Path,
) -> None:
    """The idempotent branch at store level, where it is actually reachable.

    `RegistrationStore.add` returns an existing record unchanged, and the route always
    mints a fresh client id, so nothing in a running deployment walks this branch through
    the endpoint — the guarantee is one a future caller inherits, so it is stated here as
    well as through the route by the test above.

    What is asserted is the property the response boundary depends on: the returned record
    still carries the *first* registration's instant, so a response built from it (the
    route's own conversion) answers that instant rather than the time of the second call.
    If the store rewrote `created_at` on a re-registration, the wire answer would silently
    become the later time on this branch only.
    """
    store_path = tmp_path / "store.json"
    store = RegistrationStore(make_settings(dcr_store_path=str(store_path)))
    client_id = new_client_id()

    first = store.add(client_id, [LOOPBACK_REDIRECT_URI], "first")
    first_instant = first["created_at"]
    second = store.add(client_id, [SECOND_REDIRECT_URI], "second")

    assert second["created_at"] == first_instant
    assert second["redirect_uris"] == first["redirect_uris"]
    # The store's own format, unchanged: the record a re-registration returns holds the
    # instant as the ISO-8601 string the store writes, not as a wire-shaped number. The
    # conversion is the route's, and doing it here would make the branch answer a number
    # while every other reader of the file still expects the string.
    assert isinstance(second["created_at"], str)
    assert _ISO_8601.match(second["created_at"]) is not None
    assert ISSUED_AT_EPOCH_LOW <= epoch_of(second["created_at"]) <= ISSUED_AT_EPOCH_HIGH


def test_a_registration_without_redirect_uris_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    """Without redirect URIs the client id could never complete a flow.

    Refusing here means the client learns at registration rather than at its first
    sign-in attempt, where the reason would be far less clear.
    """
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json={"client_name": "no redirects"})

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "redirect_uris" in response.json()["error_description"]


def test_an_empty_redirect_uri_list_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json={"redirect_uris": []})

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_a_non_string_redirect_uri_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json={"redirect_uris": [1234]})

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_a_non_json_body_is_refused(private_key_pem: str, tmp_path: Path) -> None:
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register",
            content=b"not json",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "JSON object" in response.json()["error_description"]


def test_a_non_object_body_is_refused(private_key_pem: str, tmp_path: Path) -> None:
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json=[1, 2, 3])

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_a_non_string_client_name_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register", json=registration_body(client_name={"nested": "object"})
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST


# -------------------------------------------------------- the durability scenarios


def test_a_registration_survives_a_restart(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The scenario the store exists for: a cached client id must keep working.

    The second app is built over the same file, which is what a restart is — a new
    process reading the state the previous one left.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with make_client(settings, private_key_pem) as first:
        client_id = first.post("/dial/register", json=registration_body()).json()[
            "client_id"
        ]

    with make_client(settings, private_key_pem) as restarted:
        response = restarted.get(
            "/dial/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "code_challenge": "a-challenge",
                "code_challenge_method": "S256",
                "resource": runtime_of(restarted).settings.toolset_resource_uri(
                    "notion"
                ),
            },
        )

    assert response.status_code == HTTPStatus.FOUND


def test_a_registration_is_persisted_before_the_response(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The response is the client's cue to cache the id, so the file must already hold it.

    Asserted by reading the store file the moment the response arrives, with no second
    request in between — the window the guarantee is about.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with make_client(settings, private_key_pem) as client:
        client_id = client.post("/dial/register", json=registration_body()).json()[
            "client_id"
        ]
        on_disk = json.loads(store_path.read_text(encoding="utf-8"))

    assert client_id in on_disk


def test_a_lost_store_self_heals_through_re_registration(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The loss semantics, end to end: reject as unregistered, re-register, continue.

    A missing store is not a corrupt one — the first run of a deployment has none — so it
    starts empty. The client that holds the cached id gets the unregistered-client
    refusal on its next authorization request, re-registers, and proceeds; no human action
    and no token invalidation, because issued tokens are self-contained.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with make_client(settings, private_key_pem) as first:
        client_id = first.post("/dial/register", json=registration_body()).json()[
            "client_id"
        ]

    store_path.unlink()

    authorize_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": "a-challenge",
        "code_challenge_method": "S256",
        "resource": "http://localhost:8090/dial/notion/mcp",
    }

    with make_client(settings, private_key_pem) as after_loss:
        rejected = after_loss.get("/dial/authorize", params=authorize_params)
        # The refusal names the client as unregistered, which is what the client acts on.
        assert rejected.json()["error"] == "invalid_client"

        new_client_id = after_loss.post(
            "/dial/register", json=registration_body()
        ).json()["client_id"]
        accepted = after_loss.get(
            "/dial/authorize", params={**authorize_params, "client_id": new_client_id}
        )

    assert accepted.status_code == HTTPStatus.FOUND
    # The id the harness held is gone, and the fresh one works: the loss costs one
    # re-registration round-trip and nothing else.
    assert new_client_id != client_id


def test_a_registration_is_inert_while_dcr_is_disabled(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The store is preserved while off, and the registration does not resolve.

    Dormant rather than deleted: the flag gates resolution as well as the endpoint, so a
    stored registration is neither used nor lost while the flag is off.
    """
    store_path = tmp_path / "store.json"
    enabled = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with make_client(enabled, private_key_pem) as client:
        client_id = client.post("/dial/register", json=registration_body()).json()[
            "client_id"
        ]

    disabled = surface_settings(dcr_enabled=False, dcr_store_path=str(store_path))
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": "a-challenge",
        "code_challenge_method": "S256",
        "resource": "http://localhost:8090/dial/notion/mcp",
    }

    with make_client(disabled, private_key_pem) as client:
        response = client.get("/dial/authorize", params=params)
        stored = json.loads(store_path.read_text(encoding="utf-8"))

    assert response.json()["error"] == "invalid_client"
    # Preserved unchanged, so re-enabling restores it exactly as it was.
    assert client_id in stored


def test_re_enabling_restores_a_dormant_registration(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The other half of dormancy: re-enabling resolves the stored registration again."""
    store_path = tmp_path / "store.json"
    enabled = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with make_client(enabled, private_key_pem) as client:
        client_id = client.post("/dial/register", json=registration_body()).json()[
            "client_id"
        ]

    # A restart with the flag off, then a restart with it on again.
    with make_client(
        surface_settings(dcr_enabled=False, dcr_store_path=str(store_path)),
        private_key_pem,
    ) as closed:
        closed.post("/dial/register", json=registration_body())

    with make_client(enabled, private_key_pem) as reopened:
        response = reopened.get(
            "/dial/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "code_challenge": "a-challenge",
                "code_challenge_method": "S256",
                "resource": "http://localhost:8090/dial/notion/mcp",
            },
        )

    assert response.status_code == HTTPStatus.FOUND


def test_a_corrupt_store_refuses_startup_naming_the_path(
    private_key_pem: str, tmp_path: Path
) -> None:
    """Fail loudly where silence is the failure mode.

    Starting empty over an unreadable store would invalidate every registered client
    without a trace, and the operator would hear about it from a harness rather than from
    the gateway. The refusal names the path, and the recovery is one command.
    """
    store_path = tmp_path / "store.json"
    store_path.write_text("{ this is not json", encoding="utf-8")
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with pytest.raises(ConfigurationError) as excinfo:
        make_client(settings, private_key_pem).__enter__()

    message = str(excinfo.value)
    assert str(store_path) in message
    assert "rename it aside" in message


def test_a_store_holding_something_other_than_an_object_refuses_startup(
    private_key_pem: str, tmp_path: Path
) -> None:
    store_path = tmp_path / "store.json"
    store_path.write_text("[1, 2, 3]", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="JSON object"):
        make_client(
            surface_settings(dcr_enabled=True, dcr_store_path=str(store_path)),
            private_key_pem,
        ).__enter__()


def test_a_store_holding_a_malformed_record_refuses_startup(
    private_key_pem: str, tmp_path: Path
) -> None:
    store_path = tmp_path / "store.json"
    store_path.write_text(json.dumps({"client": "not a record"}), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="malformed record"):
        make_client(
            surface_settings(dcr_enabled=True, dcr_store_path=str(store_path)),
            private_key_pem,
        ).__enter__()


def test_recovery_from_a_corrupt_store_is_rename_aside_and_restart(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The documented recovery, exercised: the operator renames the file, then restarts.

    The rename is also the acknowledgment of the loss — after it, harnesses re-register
    on their next sign-in.
    """
    store_path = tmp_path / "store.json"
    store_path.write_text("{ not json", encoding="utf-8")
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    store_path.rename(tmp_path / "store.corrupt.json.bak")

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json=registration_body())

    assert response.status_code == HTTPStatus.CREATED


def test_reaching_the_cap_refuses_new_registrations(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The cap is a plain-language refusal naming the limit and the operator's options."""
    settings = surface_settings(
        dcr_enabled=True,
        dcr_store_path=str(tmp_path / "store.json"),
        dcr_max_registrations=SMALL_CAP,
    )

    with make_client(settings, private_key_pem) as client:
        for _ in range(SMALL_CAP):
            assert (
                client.post("/dial/register", json=registration_body()).status_code
                == HTTPStatus.CREATED
            )
        refused = client.post("/dial/register", json=registration_body())

    assert refused.status_code == HTTPStatus.BAD_REQUEST
    assert str(SMALL_CAP) in refused.json()["error_description"]


def test_the_cap_leaves_existing_registrations_untouched(
    private_key_pem: str, tmp_path: Path
) -> None:
    """Nothing is evicted to make room.

    Evicting the oldest would invalidate a possibly live client — the same loss as a
    dropped store, but silent — so the cap refuses instead.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(
        dcr_enabled=True,
        dcr_store_path=str(store_path),
        dcr_max_registrations=SMALL_CAP,
    )

    with make_client(settings, private_key_pem) as client:
        client_ids = [
            client.post("/dial/register", json=registration_body()).json()["client_id"]
            for _ in range(SMALL_CAP)
        ]
        client.post("/dial/register", json=registration_body())

    stored = json.loads(store_path.read_text(encoding="utf-8"))

    assert set(stored) == set(client_ids)


# ------------------------------------------------------------------- store mechanics


def test_a_save_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    """A crash may leave a temporary file; a completed save may not.

    The atomic save is a temporary file plus a rename, so the temporary is the one thing
    that could accumulate — one per save, silently, until the volume fills.
    """
    store_path = tmp_path / "store.json"
    settings = make_settings(dcr_store_path=str(store_path))
    store = RegistrationStore(settings)

    store.add(new_client_id(), [LOOPBACK_REDIRECT_URI], "a client")

    leftovers = [path.name for path in tmp_path.iterdir() if path.name != "store.json"]
    assert leftovers == []
    assert store_path.exists()


def test_a_record_carries_exactly_the_four_fields(tmp_path: Path) -> None:
    """No secret is ever stored, and the field set is asserted so one cannot creep in."""
    store_path = tmp_path / "store.json"
    settings = make_settings(dcr_store_path=str(store_path))
    store = RegistrationStore(settings)

    client_id = new_client_id()
    record = store.add(client_id, [LOOPBACK_REDIRECT_URI], "a client")

    assert set(record) == RECORD_FIELDS
    stored = json.loads(store_path.read_text(encoding="utf-8"))
    assert set(stored[client_id]) == RECORD_FIELDS


def test_the_store_file_is_owner_only_where_the_platform_has_posix_modes(
    tmp_path: Path,
) -> None:
    """Client ids and redirect URIs are not credentials, and not public either.

    The mode is asserted only on a platform that implements POSIX permission bits. The
    store runs in the Linux container, where the mode is what the write sets; on Windows
    `chmod` only toggles the read-only flag, so asserting a mode there would be asserting
    a number the filesystem does not enforce — and a test that passes on a filesystem
    that ignores it is worse than no test.
    """
    store_path = tmp_path / "store.json"
    store = RegistrationStore(make_settings(dcr_store_path=str(store_path)))

    store.add(new_client_id(), [LOOPBACK_REDIRECT_URI], "a client")

    if os.name != "posix":
        pytest.skip("POSIX permission bits are not implemented on this platform")
    mode = store_path.stat().st_mode & 0o777
    assert mode == OWNER_ONLY_MODE


def _refuse_mode_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every `chmod` fail the way a filesystem without POSIX modes makes it fail.

    `EPERM` is the answer the store's own container gets on the compose file's
    Windows-host bind mount: the mount does not implement permission changes at all, so no
    file there can be given a mode. Patched globally because the failure belongs to the
    filesystem, not to the store — the save's `chmod` is simply the first caller to meet it.
    """

    def refuse(self: Path, mode: int, **kwargs: object) -> None:
        raise PermissionError(1, "Operation not permitted", str(self))

    monkeypatch.setattr(Path, "chmod", refuse)


def test_a_refused_mode_change_does_not_refuse_the_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The mode is hardening; the rename is the durability. Only the rename can refuse.

    On a volume whose filesystem does not implement POSIX permission changes, the mode
    cannot be set on any file — so treating a refused `chmod` as fatal would make DCR
    unusable on a whole class of deployment for the sake of the weaker of the save's two
    properties. The registration proceeds, and the operator learns about the mode from the
    log rather than from a client's failed sign-in.
    """
    store_path = tmp_path / "store.json"
    store = RegistrationStore(make_settings(dcr_store_path=str(store_path)))
    _refuse_mode_changes(monkeypatch)
    caplog.set_level(logging.WARNING, logger="gateway.store")
    client_id = new_client_id()

    record = store.add(client_id, [LOOPBACK_REDIRECT_URI], "a client")

    assert record["client_id"] == client_id
    # The record is on disk, not merely in memory: the store's own promise holds.
    stored = json.loads(store_path.read_text(encoding="utf-8"))
    assert stored[client_id]["redirect_uris"] == [LOOPBACK_REDIRECT_URI]
    assert store.get(client_id) == record
    # And the warning names the path an operator has to act on, carrying no record content.
    assert "could not be given its owner-only file mode" in caplog.text
    assert str(store_path) in caplog.text
    assert client_id not in caplog.text
    # The save still cleaned up after itself.
    assert [path.name for path in tmp_path.iterdir()] == ["store.json"]


def test_a_refused_mode_change_leaves_the_persisted_records_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mode outcome is a property of the file, never of its contents.

    A store written on each of the two filesystem kinds holds the same records, so a
    volume that cannot carry the mode is a different protection story, not a different
    store — and a later save on a mode-enforcing volume changes nothing a client sees.
    """
    store_path = tmp_path / "store.json"
    store = RegistrationStore(make_settings(dcr_store_path=str(store_path)))
    first_client_id = new_client_id()
    store.add(first_client_id, [LOOPBACK_REDIRECT_URI], "first")

    _refuse_mode_changes(monkeypatch)
    second_client_id = new_client_id()
    record = store.add(second_client_id, [SECOND_REDIRECT_URI], "second")

    stored = json.loads(store_path.read_text(encoding="utf-8"))
    assert set(stored) == {first_client_id, second_client_id}
    assert stored[first_client_id]["client_name"] == "first"
    assert stored[second_client_id] == record
    # The registration that preceded the mode failure is untouched by it.
    assert store.get(first_client_id) is not None


def test_a_failed_rename_still_refuses_the_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tolerance covers the mode and stops there.

    A rename that fails is the corruption-class failure the store exists to prevent: the
    client would cache an id that the next restart does not know. So it keeps its behavior
    — the registration is refused, the in-memory map does not claim it, and no temporary
    file is left behind for the volume to accumulate.
    """
    store_path = tmp_path / "store.json"
    store = RegistrationStore(make_settings(dcr_store_path=str(store_path)))

    def failing_replace(self: Path, target: object) -> Path:
        raise OSError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "replace", failing_replace)

    with pytest.raises(RegistrationError, match="could not be written"):
        store.add(new_client_id(), [LOOPBACK_REDIRECT_URI], "a client")

    assert not store.is_full()
    assert not store_path.exists()
    assert list(tmp_path.iterdir()) == []


def test_a_missing_store_starts_empty(tmp_path: Path) -> None:
    """The first run of a deployment has no store, and that is not corruption."""
    store = RegistrationStore(
        make_settings(dcr_store_path=str(tmp_path / "never-written.json"))
    )

    assert store.get("anything") is None
    assert not store.is_full()


def test_re_registering_an_existing_client_id_returns_it_unchanged(
    tmp_path: Path,
) -> None:
    """A registrant cannot take over another's redirect URIs by re-registering the id.

    The store is keyed by an id the gateway generates, so this is defense against a
    future caller that passes a caller-supplied one rather than a path a client can take
    today — stated here so that caller inherits the guarantee.
    """
    store = RegistrationStore(
        make_settings(dcr_store_path=str(tmp_path / "store.json"))
    )
    client_id = new_client_id()
    first = store.add(client_id, [LOOPBACK_REDIRECT_URI], "first")

    second = store.add(client_id, [SECOND_REDIRECT_URI], "second")

    assert second["redirect_uris"] == first["redirect_uris"]
    assert second["client_name"] == "first"


def test_a_store_that_cannot_be_written_refuses_the_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A registration is not accepted unless it is durable.

    An id answered but not persisted stops resolving on the next restart, which is
    exactly the failure the store exists to prevent — so the failure is reported at the
    registration instead.
    """
    store = RegistrationStore(
        make_settings(dcr_store_path=str(tmp_path / "store.json"))
    )

    def failing_save() -> None:
        raise OSError

    monkeypatch.setattr(store, "_save", failing_save)

    with pytest.raises(RegistrationError, match="could not be written"):
        store.add(new_client_id(), [LOOPBACK_REDIRECT_URI], "a client")
    # And the in-memory map does not claim a registration the store does not hold.
    assert not store.is_full()


def test_the_cap_counts_stored_registrations(tmp_path: Path) -> None:
    store = RegistrationStore(
        make_settings(
            dcr_store_path=str(tmp_path / "store.json"), dcr_max_registrations=1
        )
    )

    assert not store.is_full()
    store.add(new_client_id(), [LOOPBACK_REDIRECT_URI], None)
    assert store.is_full()


# --------------------------------------------------------- resolution and redirects


def test_an_authorization_request_validates_the_redirect_uri_against_the_stored_record(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The stored record is the registration, so its redirect URIs are the whole rule."""
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        client_id = client.post("/dial/register", json=registration_body()).json()[
            "client_id"
        ]
        accepted = client.get(
            "/dial/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "code_challenge": "a-challenge",
                "code_challenge_method": "S256",
                "resource": "http://localhost:8090/dial/notion/mcp",
            },
        )
        refused = client.get(
            "/dial/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": SECOND_REDIRECT_URI,
                "code_challenge": "a-challenge",
                "code_challenge_method": "S256",
                "resource": "http://localhost:8090/dial/notion/mcp",
            },
        )

    assert accepted.status_code == HTTPStatus.FOUND
    assert refused.json()["error"] == "invalid_request"
    assert "redirect_uri" in refused.json()["error_description"]


def test_a_pre_registered_client_resolves_while_dcr_is_disabled(
    private_key_pem: str, tmp_path: Path
) -> None:
    """Priority order: the first rung never depends on the fallback being enabled."""
    settings = surface_settings(
        dcr_enabled=False, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params={
                "response_type": "code",
                "client_id": PRE_REGISTERED_CLIENT_ID,
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "code_challenge": "a-challenge",
                "code_challenge_method": "S256",
                "resource": "http://localhost:8090/dial/notion/mcp",
            },
        )

    assert response.status_code == HTTPStatus.FOUND


def test_the_registration_endpoint_records_an_audit_event(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Attribution: which client id was registered, and by which path."""
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        client_id = client.post("/dial/register", json=registration_body()).json()[
            "client_id"
        ]

    assert "client_registered" in caplog.text
    assert client_id in caplog.text


def test_a_registration_body_with_extra_fields_is_accepted(
    private_key_pem: str, tmp_path: Path
) -> None:
    """Clients send fields the gateway does not consume, and refusing them would break
    a registration over a field that changes nothing.

    The record's own field set is asserted elsewhere, so what is ignored here cannot
    reach the store.
    """
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register",
            json=registration_body(
                grant_types=["authorization_code"],
                token_endpoint_auth_method="none",
                logo_uri="https://example.test/logo.png",
            ),
        )
        record = json.loads((tmp_path / "store.json").read_text(encoding="utf-8"))

    assert response.status_code == HTTPStatus.CREATED
    assert set(next(iter(record.values()))) == RECORD_FIELDS


# ---------------------------------------------------- the registration body's bounds


def test_an_oversized_registration_body_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    """A body larger than the cap is refused, and the cap is read while reading.

    The endpoint is unauthenticated and takes a body, so a request that is merely large
    must cost the gateway a bounded amount of memory: the cap is what bounds it, and a cap
    applied after the whole body was read would have allocated the memory it exists to
    bound. The body here is well-formed JSON — a client_name an order of magnitude past
    the cap — so the refusal is the size and not the shape.
    """
    store_path = tmp_path / "store.json"
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register",
            json=registration_body(client_name="x" * 100_000),
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "larger than" in response.json()["error_description"]
    # Nothing was persisted: a refused registration leaves no record behind.
    assert store_path.exists() is False


def test_a_registration_at_the_body_cap_is_still_accepted(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The cap bounds size, not legitimate use: a body just under it registers.

    Without this the oversized test above could pass on an endpoint that refused every
    body, which is a broken endpoint rather than a bounded one. The per-record bounds are
    lowered alongside the cap because the two have to agree — a body cap of `4096` with the
    default per-record maxima would advertise a registration the cap could never carry, and
    the settings model refuses that combination outright.
    """
    settings = surface_settings(
        dcr_enabled=True,
        dcr_store_path=str(tmp_path / "store.json"),
        dcr_max_body_bytes=4096,
        dcr_max_redirect_uris=1,
        dcr_max_redirect_uri_length=2048,
        dcr_max_client_name_length=1024,
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register", json=registration_body(client_name="x" * 1000)
        )

    assert response.status_code == HTTPStatus.CREATED
    assert response.json()["client_name"] == "x" * 1000


def test_registration_bounds_the_body_cap_could_not_carry_are_refused() -> None:
    """The two kinds of registration bound must agree, and the model says so at startup.

    The per-record maxima bound what a registration may contain and the body cap bounds
    what may be read, so a maxima the cap cannot carry is a bound that never applies: every
    registration near it is refused as oversized, and the operator who raised it sees no
    error and no effect. The refusal names both settings, because the remedy is one of the
    two values.
    """
    with pytest.raises(ValidationError) as refusal:
        make_settings(
            dcr_max_body_bytes=4096,
            dcr_max_redirect_uris=64,
            dcr_max_redirect_uri_length=2048,
            dcr_max_client_name_length=1024,
        )

    message = str(refusal.value)
    assert "dcr_max_body_bytes" in message
    assert "dcr_max_redirect_uris" in message


def test_the_default_registration_bounds_are_jointly_reachable() -> None:
    """The negative control for the check above: the shipped defaults fit inside the cap.

    A guard that refused everything would pass the test above and break every deployment.
    The largest registration the default maxima permit, plus its JSON, is asserted to fit
    the default cap — so the two defaults are demonstrably one configuration rather than
    two numbers that happen to sit next to each other.
    """
    settings = make_settings()
    largest_permitted = (
        settings.dcr_max_redirect_uris * settings.dcr_max_redirect_uri_length
        + settings.dcr_max_client_name_length
    )

    assert largest_permitted < settings.dcr_max_body_bytes


def test_an_oversized_client_name_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    """A per-record bound, so one accepted registration cannot store an outsized document."""
    settings = surface_settings(
        dcr_enabled=True,
        dcr_store_path=str(tmp_path / "store.json"),
        dcr_max_client_name_length=32,
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register", json=registration_body(client_name="x" * 33)
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "client_name" in response.json()["error_description"]


def test_too_many_redirect_uris_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    settings = surface_settings(
        dcr_enabled=True,
        dcr_store_path=str(tmp_path / "store.json"),
        dcr_max_redirect_uris=2,
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register",
            json=registration_body(
                redirect_uris=[
                    "http://127.0.0.1:8766/callback",
                    "http://127.0.0.1:8766/second",
                    "http://127.0.0.1:8766/third",
                ]
            ),
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "at most 2 URIs" in response.json()["error_description"]


def test_an_oversized_redirect_uri_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    settings = surface_settings(
        dcr_enabled=True,
        dcr_store_path=str(tmp_path / "store.json"),
        dcr_max_redirect_uri_length=64,
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register",
            json=registration_body(
                redirect_uris=["http://127.0.0.1:8766/" + "p" * 100]
            ),
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "at most 64 characters" in response.json()["error_description"]


def test_a_small_valid_registration_is_unaffected_by_the_bounds(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The defaults accept an ordinary registration, so the bounds cost real clients nothing.

    Asserted against the default values rather than configured ones: the bound a deployment
    actually runs with is the one that matters, and a too-tight default would be a
    regression the configured tests would not see.
    """
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post("/dial/register", json=registration_body())

    assert response.status_code == HTTPStatus.CREATED
    assert response.json()["redirect_uris"] == [LOOPBACK_REDIRECT_URI]


# ------------------------------------ the redirect-URI admission rule (task 5.1)

# A plain-`http` redirect on a real host: the collector the authorization response would
# cross in cleartext, refused at every admission site.
HTTP_COLLECTOR_URI = "http://collector.example/callback"
HTTPS_REDIRECT_URI = "https://app.example/callback"


def test_a_non_loopback_http_redirect_uri_is_refused_at_dcr_registration(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The DCR body check is the admission rule's first site.

    A registration carrying a non-loopback plain-`http` URI is refused with a plain-language
    error naming the rule, and no record is stored — the value never reaches the exact-match
    validation, because the rule is an admission rule upstream of the matching.
    """
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register", json=registration_body(redirect_uris=[HTTP_COLLECTOR_URI])
        )
        store_written = runtime_of(client).registrations.path.exists()

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "must be `https`" in response.json()["error_description"]
    # No record was stored, and no store file was even written.
    assert store_written is False


def test_a_loopback_http_redirect_uri_is_admitted_at_dcr_registration(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The RFC 8252 exception at the DCR site: the fielded harness's loopback registration
    passes untouched."""
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register",
            json=registration_body(redirect_uris=[LOOPBACK_REDIRECT_URI]),
        )

    assert response.status_code == HTTPStatus.CREATED
    assert response.json()["redirect_uris"] == [LOOPBACK_REDIRECT_URI]


def test_an_https_redirect_uri_is_admitted_at_dcr_registration(
    private_key_pem: str, tmp_path: Path
) -> None:
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register", json=registration_body(redirect_uris=[HTTPS_REDIRECT_URI])
        )

    assert response.status_code == HTTPStatus.CREATED


def test_a_stored_non_loopback_http_redirect_uri_refuses_startup_at_load(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The store's load path is the admission rule's fourth site.

    Client resolution reads the store without re-checking, so a record admitted before the
    rule landed — or planted on the volume — would otherwise keep a non-loopback plain-`http`
    URI usable after the rule landed. The refusal is the corrupt-store discipline's own
    shape: the gateway refuses to start, naming the record; the recovery is the same —
    the store renamed aside or the record removed, the affected harnesses re-registering.
    """
    store_path = tmp_path / "store.json"
    store_path.write_text(
        json.dumps(
            {
                "a-planted-client": {
                    "client_id": "a-planted-client",
                    "redirect_uris": [HTTP_COLLECTOR_URI],
                    "client_name": "a planted client",
                    "created_at": "2020-01-01T00:00:00+00:00",
                }
            }
        ),
        encoding="utf-8",
    )
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with pytest.raises(ConfigurationError) as excinfo:
        make_client(settings, private_key_pem).__enter__()

    message = str(excinfo.value)
    assert "a-planted-client" in message
    assert HTTP_COLLECTOR_URI in message
    assert "must be `https`" in message


def test_a_stored_loopback_http_record_loads_untouched(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The load path admits what every other site admits: the loopback exception holds here
    too, so a conforming fielded record is untouched."""
    store_path = tmp_path / "store.json"
    store_path.write_text(
        json.dumps(
            {
                "a-loopback-client": {
                    "client_id": "a-loopback-client",
                    "redirect_uris": [LOOPBACK_REDIRECT_URI],
                    "client_name": "a loopback client",
                    "created_at": "2020-01-01T00:00:00+00:00",
                }
            }
        ),
        encoding="utf-8",
    )
    settings = surface_settings(dcr_enabled=True, dcr_store_path=str(store_path))

    with make_client(settings, private_key_pem) as client:
        record = runtime_of(client).registrations.get("a-loopback-client")

    assert record is not None
    assert record["redirect_uris"] == [LOOPBACK_REDIRECT_URI]
