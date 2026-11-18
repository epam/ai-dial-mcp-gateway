"""Tests for the `/dial/authorize` entry.

This endpoint's job is to refuse the requests that cannot lead anywhere, and the refusals
are ordered by what is known at each point: until the client and its redirect URI are
established, an error must not be redirected anywhere (that would be an open redirect),
and after they are, it must be — a client whose OAuth library is waiting for a callback
learns nothing from a JSON body it never sees.

A validated request is answered with the redirect that starts the federation flow: the
browser goes to the identity provider under the gateway's own PKCE client, with the flow
id as the provider's `state` and the verifier's challenge in the URL. The verifier itself
stays on the flow's server-side record, and nothing the client sent — least of all its
`scope` — is relayed.

The `resource` requirement is the other half. One flat authorization server serves every
toolset, so a request that names no resource cannot be addressed to one, and inferring it
would issue a token for a toolset the client never asked about.
"""

from __future__ import annotations

import base64
import json
import logging
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tests.conftest import (
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    make_client,
    runtime_of,
    surface_settings,
)

# The gateway's origin, as the resource URIs and the redirect issuer are built from it.
ORIGIN = "http://localhost:8090"

# A resource this gateway does not serve, for the unknown-target branch.
UNKNOWN_RESOURCE = "http://localhost:8090/dial/not-mapped/mcp"

# A second toolset name, so a test can show two resources are distinguished.
OTHER_TOOLSET = "slack"

# The flow-id shape: 16 random bytes, url-safe base64 with padding stripped.
FLOW_ID_BYTES = 16
FLOW_ID_LENGTH = 22

# How many flows the entropy test allocates. Each one is a rate-limited request, so the
# count is kept under the per-source limit the surface settings allow.
FLOW_ID_SAMPLE_SIZE = 20

# A PKCE verifier and the S256 challenge derived from it. The values are fixed so the
# test does not have to recompute a challenge to make an assertion about the flow.
VERIFIER = "a-fixed-code-verifier-for-the-test-only"


def base_params(**overrides: str) -> dict[str, str]:
    """A well-formed authorization request for the pre-registered client."""
    params = {
        "response_type": "code",
        "client_id": PRE_REGISTERED_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": "challenge-value",
        "code_challenge_method": "S256",
        "resource": f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp",
    }
    params.update(overrides)
    return params


def error_code(response: object) -> str | None:
    """The `error` value of a JSON error body, or `None` when the body is not one."""
    body: Any = getattr(response, "json", lambda: {})()
    return body.get("error") if isinstance(body, dict) else None


def redirected_error(response: object) -> dict[str, list[str]]:
    """The query parameters of a redirected error, keyed by name."""
    location = response.headers.get("location", "")  # type: ignore[attr-defined]
    return parse_qs(urlparse(location).query)


# ------------------------------------------------------------------- the happy path


def redirected_to(response: object) -> dict[str, list[str]]:
    """The query parameters of a successful redirect, keyed by name."""
    location = response.headers.get("location", "")  # type: ignore[attr-defined]
    return parse_qs(urlparse(location).query)


def test_a_valid_request_redirects_to_the_identity_provider(
    surface_client: TestClient,
) -> None:
    """The positive control: what every refusal below is measured against."""
    response = surface_client.get("/dial/authorize", params=base_params())

    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    assert location.startswith(
        f"{runtime_of(surface_client).settings.idp_issuer}/protocol/openid-connect/auth"
    )


def test_the_redirect_requests_only_the_clients_own_scopes(
    surface_client: TestClient,
) -> None:
    """A client's `scope` must never reach this leg.

    A scope the gateway's own identity-provider client does not carry — or that is not a
    client scope in the realm at all — fails the whole authorization leg with an opaque
    error. Whether the request carried one or not, the redirect asks for exactly the
    client's defaults.
    """
    without = redirected_to(surface_client.get("/dial/authorize", params=base_params()))
    with_scope = redirected_to(
        surface_client.get(
            "/dial/authorize", params=base_params(scope="openid profile email")
        )
    )

    assert without["scope"] == ["profile email"]
    assert with_scope["scope"] == ["profile email"]
    assert "openid" not in with_scope["scope"][0]


def test_no_scope_parameter_is_equally_acceptable(surface_client: TestClient) -> None:
    """A client that sends no scope at all is not a client that failed a check."""
    assert surface_client.get("/dial/authorize", params=base_params()).status_code == (
        HTTPStatus.FOUND
    )


def test_the_redirect_carries_a_pkce_challenge_and_no_verifier(
    surface_client: TestClient,
) -> None:
    """The redirect carries the challenge; the verifier stays on the flow's record.

    Putting the verifier on the wire is exactly what PKCE exists to avoid, and this leg is
    no different from the harness's own: the browser carries a challenge and a flow id.
    """
    response = surface_client.get("/dial/authorize", params=base_params())
    params = redirected_to(response)

    assert params["code_challenge_method"] == ["S256"]
    assert params["code_challenge"][0]
    assert params["response_type"] == ["code"]
    assert params["client_id"] == ["dial-mcp-proxy"]

    runtime = runtime_of(surface_client)
    record = runtime.flows.get(runtime.flows.live_ids()[0])
    assert record is not None
    assert record.idp_code_verifier
    assert record.idp_code_verifier not in response.headers["location"]


def test_the_flow_id_is_a_128_bit_random_value(
    private_key_pem: str, tmp_path: Path
) -> None:
    """A guessable flow id is the code-injection chain's first step.

    The id is what a later callback round-trips, and an attacker who could guess one
    could pair their own upstream code with a victim's session. The entropy is asserted
    as a shape and as non-repetition across a sample, which is what a guess has to defeat.
    It is observed on the record rather than in a response body now that the response is a
    redirect, and the property measured is the same one.

    The sample size stays under the per-source rate limit: a test that requested past it
    would be measuring the limiter rather than the id.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=FLOW_ID_SAMPLE_SIZE * 2,
    )

    with make_client(settings, private_key_pem) as client:
        for _ in range(FLOW_ID_SAMPLE_SIZE):
            client.get("/dial/authorize", params=base_params())
        runtime = runtime_of(client)
        ids = list(runtime.flows.live_ids())

    # The negative control for the assertions below: every request allocated a record, so
    # "all distinct" measures the ids rather than an empty list of them.
    assert len(ids) == FLOW_ID_SAMPLE_SIZE
    assert len(set(ids)) == FLOW_ID_SAMPLE_SIZE
    for flow_id in ids:
        assert len(flow_id) == FLOW_ID_LENGTH
        assert len(base64.urlsafe_b64decode(flow_id + "==")) == FLOW_ID_BYTES


def test_the_flow_id_is_the_identity_providers_state(
    surface_client: TestClient,
) -> None:
    """The flow id round-trips through the provider, which is what resolves the callback.

    It is the only thing the browser carries back, so the callback's whole lookup depends
    on this value surviving the leg unchanged.
    """
    response = surface_client.get("/dial/authorize", params=base_params())
    params = redirected_to(response)
    runtime = runtime_of(surface_client)

    assert params["state"][0] in runtime.flows.live_ids()


def test_the_same_request_twice_allocates_two_distinct_flows(
    surface_client: TestClient,
) -> None:
    """Concurrency is the ordinary case: a browser and a retry overlap constantly."""
    first = redirected_to(surface_client.get("/dial/authorize", params=base_params()))
    second = redirected_to(surface_client.get("/dial/authorize", params=base_params()))

    assert first["state"] != second["state"]


# ------------------------------------------------------------- client-side refusals


def test_an_unknown_client_is_refused_directly(surface_client: TestClient) -> None:
    """Before the client is known, its redirect URI is an unvalidated target.

    Redirecting the error there would forward it to an attacker-chosen address, so the
    refusal is answered where it was asked.
    """
    response = surface_client.get(
        "/dial/authorize", params=base_params(client_id="not-a-known-client")
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert error_code(response) == "invalid_client"
    assert "location" not in response.headers


def test_a_missing_client_id_is_refused_directly(surface_client: TestClient) -> None:
    params = base_params()
    del params["client_id"]

    response = surface_client.get("/dial/authorize", params=params)

    assert error_code(response) == "invalid_request"
    assert "location" not in response.headers


def test_a_missing_redirect_uri_is_refused_directly(surface_client: TestClient) -> None:
    params = base_params()
    del params["redirect_uri"]

    response = surface_client.get("/dial/authorize", params=params)

    assert error_code(response) == "invalid_request"
    assert "location" not in response.headers


def test_an_unregistered_redirect_uri_is_refused_directly(
    surface_client: TestClient,
) -> None:
    """Still answered directly: this is the URI an attacker would want the error sent to."""
    response = surface_client.get(
        "/dial/authorize",
        params=base_params(redirect_uri="http://127.0.0.1:9999/attacker"),
    )

    assert error_code(response) == "invalid_request"
    assert "location" not in response.headers


def test_an_unsupported_response_type_is_refused_directly(
    surface_client: TestClient,
) -> None:
    response = surface_client.get(
        "/dial/authorize", params=base_params(response_type="token")
    )

    assert error_code(response) == "invalid_request"
    assert "location" not in response.headers


# ------------------------------------------------------------ client-side redirects


def test_a_missing_code_challenge_is_redirected_to_the_client(
    surface_client: TestClient,
) -> None:
    """PKCE is mandatory: the code is a bearer string in a URL, and this is what binds it."""
    params = base_params()
    del params["code_challenge"]

    response = surface_client.get("/dial/authorize", params=params)

    assert response.status_code == HTTPStatus.FOUND
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)
    assert redirected_error(response)["error"] == ["invalid_request"]


def test_a_plain_code_challenge_method_is_refused(surface_client: TestClient) -> None:
    """`plain` puts the verifier itself on the wire, which is what PKCE exists to avoid."""
    response = surface_client.get(
        "/dial/authorize", params=base_params(code_challenge_method="plain")
    )

    assert redirected_error(response)["error"] == ["invalid_request"]


def test_a_redirected_error_echoes_the_state(surface_client: TestClient) -> None:
    """A client correlates the response with its request by this value."""
    response = surface_client.get(
        "/dial/authorize",
        params=base_params(code_challenge_method="plain", state="client-state-value"),
    )

    assert redirected_error(response)["state"] == ["client-state-value"]


def test_a_redirected_error_carries_the_issuer_for_mix_up_defense(
    surface_client: TestClient,
) -> None:
    """RFC 9207: a client that talks to several servers can tell which one answered."""
    response = surface_client.get(
        "/dial/authorize", params=base_params(code_challenge_method="plain")
    )

    assert redirected_error(response)["iss"] == [ORIGIN]


# ---------------------------------------------------------------- the resource rule


def test_a_missing_resource_is_invalid_target(surface_client: TestClient) -> None:
    """One flat server, many toolsets: the resource is the only disambiguator."""
    params = base_params()
    del params["resource"]

    response = surface_client.get("/dial/authorize", params=params)

    assert redirected_error(response)["error"] == ["invalid_target"]


def test_an_empty_resource_is_treated_as_absent(surface_client: TestClient) -> None:
    """A `?resource=` from a client's string concatenation is not a resource.

    An empty string names no toolset, and accepting it would be the same failure as
    inferring one: a token addressed to a toolset the request never named.
    """
    response = surface_client.get("/dial/authorize", params=base_params(resource=""))

    assert redirected_error(response)["error"] == ["invalid_target"]


def test_an_unknown_resource_is_invalid_target(surface_client: TestClient) -> None:
    response = surface_client.get(
        "/dial/authorize", params=base_params(resource=UNKNOWN_RESOURCE)
    )

    assert redirected_error(response)["error"] == ["invalid_target"]


def test_a_resource_with_a_trailing_slash_is_not_the_same_resource(
    surface_client: TestClient,
) -> None:
    """The resource URI is compared exactly, as the protected-resource document spells it."""
    response = surface_client.get(
        "/dial/authorize",
        params=base_params(resource=f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp/"),
    )

    assert redirected_error(response)["error"] == ["invalid_target"]


def test_a_charset_violating_resource_name_is_invalid_target(
    surface_client: TestClient,
) -> None:
    """A name outside the routed charset has no location that routes it."""
    response = surface_client.get(
        "/dial/authorize",
        params=base_params(resource=f"{ORIGIN}/dial/Notion_MCP/mcp"),
    )

    assert redirected_error(response)["error"] == ["invalid_target"]


@pytest.mark.parametrize("name", ["authorize", "token"])
def test_a_reserved_resource_name_is_invalid_target(
    surface_client: TestClient, name: str
) -> None:
    """A reserved front-door name would be captured by the router's authorization surface."""
    response = surface_client.get(
        "/dial/authorize", params=base_params(resource=f"{ORIGIN}/dial/{name}/mcp")
    )

    assert redirected_error(response)["error"] == ["invalid_target"]


def test_a_dynamic_name_passes_the_guard_with_no_restriction(
    private_key_pem: str, tmp_path: Path
) -> None:
    """With no restriction configured, any guard-passing name resolves — configured or not.

    The endpoint decides the name's shape and its place in the restriction; whether Core
    serves the name is decided later, at the flow's settings read.
    """
    settings = surface_settings(
        toolsets="", dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params=base_params(resource=f"{ORIGIN}/dial/a-dynamic-name/mcp"),
        )
        record = runtime_of(client).flows.get(redirected_to(response)["state"][0])

    assert response.status_code == HTTPStatus.FOUND
    assert record is not None
    assert record.toolset == "a-dynamic-name"


def test_another_toolsets_resource_resolves_to_that_toolset(
    private_key_pem: str, tmp_path: Path
) -> None:
    """Two toolsets, two resources, one server: the resource picks the toolset."""
    settings = surface_settings(
        toolsets={
            TOOLSET_NAME: {"scopes_supported": ["default"]},
            OTHER_TOOLSET: {"scopes_supported": ["default"]},
        },
        dcr_store_path=str(tmp_path / "store.json"),
    )

    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params=base_params(resource=f"{ORIGIN}/dial/{OTHER_TOOLSET}/mcp"),
        )
        record = runtime_of(client).flows.get(redirected_to(response)["state"][0])

    assert response.status_code == HTTPStatus.FOUND
    assert record is not None
    assert record.toolset == OTHER_TOOLSET


def test_one_toolset_inference_accepts_a_request_with_no_resource(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The operator's escape hatch: a deployment that can never serve more than one.

    Explicitly configured, because inferring silently is how a token ends up addressed to
    a toolset the client never named.
    """
    settings = surface_settings(
        gateway_infer_resource_single_toolset=True,
        dcr_store_path=str(tmp_path / "store.json"),
    )
    params = base_params()
    del params["resource"]

    with make_client(settings, private_key_pem) as client:
        response = client.get("/dial/authorize", params=params)
        record = runtime_of(client).flows.get(redirected_to(response)["state"][0])

    assert response.status_code == HTTPStatus.FOUND
    assert record is not None
    assert record.toolset == TOOLSET_NAME


@pytest.mark.parametrize("spelling", ["notio%6E", "notio%6e"])
def test_one_toolset_inference_canonicalizes_a_non_canonical_entry(
    private_key_pem: str, tmp_path: Path, spelling: str
) -> None:
    """The inferred identity is canonical however the operator spelled the entry.

    A guard-passing but non-canonical configured entry — an over-escaped unreserved
    character, or a lowercase-hex escape of it — must not survive raw into the resolved
    path: the flow record's resource, the token audience, and the refresh match all carry
    the one canonical form, so the code grant's canonical-vs-canonical comparison succeeds
    for a deployment that spelled its single entry differently.
    """
    settings = surface_settings(
        gateway_infer_resource_single_toolset=True,
        toolsets={spelling: {}},
        dcr_store_path=str(tmp_path / "store.json"),
    )
    params = base_params()
    del params["resource"]

    with make_client(settings, private_key_pem) as client:
        response = client.get("/dial/authorize", params=params)
        record = runtime_of(client).flows.get(redirected_to(response)["state"][0])

    assert response.status_code == HTTPStatus.FOUND
    assert record is not None
    # Both carried forms are the canonical identity, never the entry's own spelling.
    assert record.toolset == TOOLSET_NAME
    assert record.resource == f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"


def test_one_toolset_inference_with_two_toolsets_refuses_startup(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The flag names a single-toolset deployment, and startup refuses without one.

    With two toolsets there is no "the one toolset" to infer, so enabling inference is a
    contradiction startup catches rather than a guess made per request.
    """
    with pytest.raises(ValidationError) as excinfo:
        surface_settings(
            gateway_infer_resource_single_toolset=True,
            toolsets={
                TOOLSET_NAME: {"scopes_supported": ["default"]},
                OTHER_TOOLSET: {"scopes_supported": ["default"]},
            },
            dcr_store_path=str(tmp_path / "store.json"),
        )

    assert "gateway_infer_resource_single_toolset" in str(excinfo.value)


def test_inference_off_by_default_refuses_a_missing_resource(
    surface_client: TestClient,
) -> None:
    """The default is strict; the inference flag is the only escape."""
    params = base_params()
    del params["resource"]

    response = surface_client.get("/dial/authorize", params=params)

    assert redirected_error(response)["error"] == ["invalid_target"]


# ------------------------------------------------------------- cached and audit paths


def test_a_valid_request_allocates_exactly_one_live_flow(
    surface_client: TestClient,
) -> None:
    """One request, one record: the record is the state a later leg looks up.

    Counted rather than merely returned, so a request that allocated twice — or allocated
    and then discarded — fails here instead of at a callback.
    """
    surface_client.get("/dial/authorize", params=base_params())

    runtime = runtime_of(surface_client)
    assert runtime.flows.live_count() == 1


# ------------------------------------------------------------ the `state` rule (task 4.1)

# The bound the `state` rule sets, restated here so a change to the constant fails a test
# that names the number rather than one that reads it back from the implementation.
STATE_BOUND_BYTES = 2048


def test_an_absent_state_is_tolerated(surface_client: TestClient) -> None:
    """Absent `state` is the tolerated case: the flow allocates exactly as a carrying one's.

    The CSRF binding a client's `state` would do is already carried here by PKCE S256, the
    required and validated `resource`, single-use short-lived codes, and the unguessable
    flow id — so a request without one is accepted, with nothing echoed for a state that
    was never offered.
    """
    response = surface_client.get("/dial/authorize", params=base_params())

    assert response.status_code == HTTPStatus.FOUND
    record = runtime_of(surface_client).flows.get(redirected_to(response)["state"][0])
    assert record is not None
    assert record.state is None


def test_a_carried_state_is_stored_at_allocation_and_echoed_unchanged(
    surface_client: TestClient,
) -> None:
    """The one rule: stored on the record at allocation, echoed back byte-for-byte.

    A value the gateway modified, filtered, or extended would break the correlation the
    client's `state` exists for, so the assertion is exact equality on an awkward value.
    """
    carried = "state/with +odd?chars&and=equals#frag"
    response = surface_client.get("/dial/authorize", params=base_params(state=carried))

    assert response.status_code == HTTPStatus.FOUND
    record = runtime_of(surface_client).flows.get(redirected_to(response)["state"][0])
    assert record is not None
    assert record.state == carried


def test_an_oversized_state_is_refused_before_a_record_exists(
    surface_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """Over the bound, refused `invalid_request` with its own reason and no record.

    The refusal is a pre-allocation refusal: it lands before the client is resolved and
    before any flow record exists, so the record and the redirect echo the bound protects
    are never grown. One audit record carries the fixed-vocabulary reason.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    oversized = "x" * (STATE_BOUND_BYTES + 1)
    before = runtime_of(surface_client).flows.live_count()

    response = surface_client.get(
        "/dial/authorize", params=base_params(state=oversized)
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert error_code(response) == "invalid_request"
    # No record was allocated — the bound lands before the record exists.
    assert runtime_of(surface_client).flows.live_count() == before
    refusals = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
        and json.loads(record.getMessage())["event"] == "flow_refused"
    ]
    assert [r["reason"] for r in refusals] == ["oversized_state"]


def test_a_state_exactly_at_the_bound_is_accepted(surface_client: TestClient) -> None:
    """The bound is a bound, not an off-by-one: exactly the limit is admitted."""
    at_bound = "y" * STATE_BOUND_BYTES

    response = surface_client.get("/dial/authorize", params=base_params(state=at_bound))

    assert response.status_code == HTTPStatus.FOUND
    record = runtime_of(surface_client).flows.get(redirected_to(response)["state"][0])
    assert record is not None
    assert record.state == at_bound
