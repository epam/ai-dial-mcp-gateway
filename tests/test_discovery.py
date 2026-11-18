"""Tests for the discovery documents and the JWKS endpoint.

Two documents with a deliberate split, and each assertion here is about which fact lives
on which one: the authorization server's shape is flat and shared, the toolset's own facts
(resource, upstream scopes) are on its protected-resource document, and neither advertises
a scope the gateway would then enforce.

The protected-resource document is name-derived and kind-less: any guard-passing name is
served, whether or not Core's registry holds it (the mirror property), and the document
carries no authentication-kind extension. That absence is load-bearing: under dynamic
serving this surface has no kind source that would not mean a Core call, so the kind a
flow acts on is Core's, read per flow at the authenticated settings read.

The absent scope list is the other load-bearing assertion. A client echoes what it is
advertised, and an echoed scope reaches the identity-provider leg, where a scope the
gateway's own client does not carry fails the whole authorization — so the gateway
advertises none of its own and echoes the toolset's upstream scopes only where the
restriction pins them.
"""

from __future__ import annotations

import json
import logging
from http import HTTPStatus
from pathlib import Path

import jwt
import pytest
import respx
from fastapi.testclient import TestClient
from gateway.discovery import (
    AUTHORIZATION_SERVER_PATH,
    OPENID_CONFIGURATION_PATH,
    app_protected_resource_path,
    protected_resource_path,
)
from gateway.keys import SigningKey

from tests.conftest import (
    APPS_NAME,
    TOOLSET_NAME,
    make_client,
    surface_settings,
)

# A second toolset, used to show the shared document's endpoints are genuinely shared and
# that each toolset's own document names its own resource.
SECOND_TOOLSET = "slack"

# The per-source limit the apps-discovery limiter test drives past; small so the loop stays
# short, and stated so the assertions name the number they measure against.
DISCOVERY_LIMIT = 5

# The DIAL extension that named the authentication kind before this gateway served the
# dynamic set. It is asserted absent from every served document, by name, so a reintroduced
# enumeration fails here rather than passing as an unknown member.
FORMER_KIND_MEMBER = "dial_authentication_type"


def test_flat_metadata_is_served_at_the_host_root(client: TestClient) -> None:
    """RFC 8414's path for a path-less issuer — the URL a client fetches first."""
    response = client.get(AUTHORIZATION_SERVER_PATH)

    assert response.status_code == HTTPStatus.OK


def test_flat_metadata_names_the_public_origin_as_its_only_issuer(
    client: TestClient,
) -> None:
    """One flat issuer: the origin itself, with no path segment naming a toolset."""
    document = client.get(AUTHORIZATION_SERVER_PATH).json()

    assert document["issuer"] == "http://localhost:8090"
    # The path-less shape is the point: a per-toolset issuer would be a second discovery
    # root, and the harness this serves discovers exactly one.
    assert "/" not in document["issuer"].removeprefix("http://")


def test_flat_metadata_endpoints_are_shared_by_every_toolset(
    client: TestClient,
) -> None:
    """The document is one, so its endpoints are one — not per-toolset URLs."""
    document = client.get(AUTHORIZATION_SERVER_PATH).json()

    assert document["authorization_endpoint"] == "http://localhost:8090/dial/authorize"
    assert document["token_endpoint"] == "http://localhost:8090/dial/token"
    assert document["jwks_uri"] == "http://localhost:8090/dial/jwks.json"
    for value in (
        document["authorization_endpoint"],
        document["token_endpoint"],
        document["jwks_uri"],
    ):
        assert TOOLSET_NAME not in value


def test_flat_metadata_advertises_the_shape_a_client_needs(client: TestClient) -> None:
    """Both grants, S256, no client authentication, and CIMD support.

    The refresh grant is advertised even though the refresh flow is a later group's work:
    the document describes the server, and a client not told it may refresh would discard
    its refresh token and re-run the whole sign-in instead.
    """
    document = client.get(AUTHORIZATION_SERVER_PATH).json()

    assert document["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert document["response_types_supported"] == ["code"]
    assert document["code_challenge_methods_supported"] == ["S256"]
    assert document["token_endpoint_auth_methods_supported"] == ["none"]
    # The flag that steers a capable client away from registration entirely: it presents
    # a client-id document URL and makes no `/register` call.
    assert document["client_id_metadata_document_supported"] is True


def test_flat_metadata_advertises_iss_parameter_support(client: TestClient) -> None:
    """RFC 9207's support member: the advertisement matches the emission.

    The gateway emits `iss` on every authorization response — success and redirected error
    alike — and this member is what tells a client the protection exists. An unadvertised
    behavior is invisible to exactly the clients that would rely on it, so the member's
    presence is normative. It states an existing emission and changes no other member.
    """
    document = client.get(AUTHORIZATION_SERVER_PATH).json()

    assert document["authorization_response_iss_parameter_supported"] is True
    # No other member moved: the document is the same fixed shape with one more member.
    assert document["issuer"] == "http://localhost:8090"
    assert document["code_challenge_methods_supported"] == ["S256"]
    assert "scopes_supported" not in document


def test_flat_metadata_advertises_no_scopes_of_its_own(client: TestClient) -> None:
    """The gateway enforces no scopes, so advertising any would invite them back.

    A client echoes what the resource document advertises, and an echoed scope reaches
    the identity-provider leg, where a scope the gateway's own client does not carry
    fails the whole authorization — so the AS document has no scope list at all.
    """
    document = client.get(AUTHORIZATION_SERVER_PATH).json()

    assert "scopes_supported" not in document


def test_flat_metadata_advertises_no_registration_endpoint_while_dcr_is_off(
    client: TestClient,
) -> None:
    """Off by default: an endpoint that cannot register steers a client onto a path that
    fails one step later, so it is not advertised at all."""
    document = client.get(AUTHORIZATION_SERVER_PATH).json()

    assert "registration_endpoint" not in document


def test_registration_endpoint_appears_only_while_dcr_is_enabled(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The counterpart of the assertion above: enabling DCR is what advertises it."""
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        document = client.get(AUTHORIZATION_SERVER_PATH).json()

    assert document["registration_endpoint"] == "http://localhost:8090/dial/register"


def test_protected_resource_document_names_the_toolset_resource(
    surface_client: TestClient,
) -> None:
    """The document describes exactly the resource the challenge named."""
    response = surface_client.get(protected_resource_path(TOOLSET_NAME))

    assert response.status_code == HTTPStatus.OK
    assert response.json()["resource"] == "http://localhost:8090/dial/notion/mcp"


def test_protected_resource_document_names_the_single_authorization_server(
    surface_client: TestClient,
) -> None:
    """One entry, the flat origin — the same server the shared document describes."""
    document = surface_client.get(protected_resource_path(TOOLSET_NAME)).json()

    assert document["authorization_servers"] == ["http://localhost:8090"]


def test_protected_resource_document_carries_no_authentication_kind(
    surface_client: TestClient,
) -> None:
    """The document is kind-less: under dynamic serving no kind source exists here.

    The kind a flow acts on is Core's, read per flow at the authenticated settings read,
    so echoing one on this unauthenticated document would mean a Core call — which this
    surface deliberately makes none of.
    """
    document = surface_client.get(protected_resource_path(TOOLSET_NAME)).json()

    assert FORMER_KIND_MEMBER not in document


def test_every_served_document_omits_the_authentication_kind(
    private_key_pem: str,
) -> None:
    """Kind-less by construction, in both restriction modes, not just the pinned one.

    The document is built from configuration and the requested path alone; whether the
    toolset is pinned in the restriction or served dynamically, no kind appears.
    """
    pinned = surface_settings(
        toolsets={TOOLSET_NAME: {"scopes_supported": ["default"]}}
    )
    dynamic = surface_settings(toolsets="")

    with make_client(pinned, private_key_pem) as client:
        pinned_doc = client.get(protected_resource_path(TOOLSET_NAME)).json()
    with make_client(dynamic, private_key_pem) as client:
        dynamic_doc = client.get(protected_resource_path(TOOLSET_NAME)).json()

    assert FORMER_KIND_MEMBER not in pinned_doc
    assert FORMER_KIND_MEMBER not in dynamic_doc


def test_protected_resource_document_echoes_the_upstream_scopes_verbatim(
    private_key_pem: str,
) -> None:
    """The upstream scopes belong to the upstream leg, and are echoed as Core publishes.

    They are informational on this document: the upstream authorize URL is built from the
    toolset's public settings, not from anything the client sends. They echo the
    restriction entry's scopes where the toolset is pinned there.
    """
    settings = surface_settings(
        toolsets={TOOLSET_NAME: {"scopes_supported": ["default", "read:workspace"]}}
    )

    with make_client(settings, private_key_pem) as client:
        document = client.get(protected_resource_path(TOOLSET_NAME)).json()

    assert document["scopes_supported"] == ["default", "read:workspace"]


def test_a_pinned_toolset_with_no_scopes_publishes_an_empty_list(
    private_key_pem: str,
) -> None:
    """Absent upstream scopes are an empty list, not a missing member.

    A client reads this member to decide what to ask for; a missing one is a different
    statement from "the upstream advertises none".
    """
    settings = surface_settings(toolsets={TOOLSET_NAME: {}})

    with make_client(settings, private_key_pem) as client:
        document = client.get(protected_resource_path(TOOLSET_NAME)).json()

    assert document["scopes_supported"] == []


def test_a_guard_passing_name_is_served_in_dynamic_mode_with_no_core_call(
    private_key_pem: str,
) -> None:
    """The mirror property: a name Core does not hold is served its document.

    With no restriction configured, every guard-passing name is served — a name Core's
    registry knows and a name it does not are indistinguishable on this surface. The
    document is built from configuration and the requested path alone, so no Core call is
    made at all; the negative control proves it against the transport.
    """
    settings = surface_settings(toolsets="")

    with (
        make_client(settings, private_key_pem) as client,
        respx.mock(assert_all_called=False) as router,
    ):
        response = client.get(protected_resource_path("a-phantom-name"))

        # The negative control: the transport recorder saw nothing, so "no call" is a
        # measurement rather than an empty assertion.
        assert router.calls.call_count == 0

    assert response.status_code == HTTPStatus.OK
    assert (
        response.json()["resource"] == "http://localhost:8090/dial/a-phantom-name/mcp"
    )


def test_a_restriction_excluded_name_is_not_found(private_key_pem: str) -> None:
    """Configured, the restriction decides the served set and excludes the rest."""
    settings = surface_settings(
        toolsets={TOOLSET_NAME: {"scopes_supported": ["default"]}}
    )

    with make_client(settings, private_key_pem) as client:
        response = client.get(protected_resource_path("not-in-the-restriction"))

    assert response.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.parametrize("name", ["token", "authorize"])
def test_a_reserved_name_is_refused_at_discovery(
    private_key_pem: str, name: str
) -> None:
    """A reserved front-door name never names a served toolset."""
    settings = surface_settings(toolsets="")

    with make_client(settings, private_key_pem) as client:
        response = client.get(protected_resource_path(name))

    assert response.status_code == HTTPStatus.NOT_FOUND


def test_a_shape_violating_path_is_refused_at_discovery(
    private_key_pem: str,
) -> None:
    """A path outside the decoded rules has no route the grammar can carry."""
    settings = surface_settings(toolsets="")

    with make_client(settings, private_key_pem) as client:
        response = client.get(protected_resource_path("Notion."))

    assert response.status_code == HTTPStatus.NOT_FOUND


def test_a_multi_segment_path_is_served_its_document(
    private_key_pem: str,
) -> None:
    """A stored toolset's full resource path is served its document, no Core call made.

    The mirror property carried to the resource-path vocabulary: the document is served for
    every guard-passing path whether or not Core's registry holds it.
    """
    settings = surface_settings(toolsets="")

    with make_client(settings, private_key_pem) as client:
        response = client.get(protected_resource_path("toolsets/public/a-phantom-name"))

    assert response.status_code == HTTPStatus.OK
    assert (
        response.json()["resource"]
        == "http://localhost:8090/dial/toolsets/public/a-phantom-name/mcp"
    )


def test_an_encoded_spelling_document_echoes_the_spelling(
    private_key_pem: str,
) -> None:
    """The document's `resource` echoes the offered spelling, while the guard admits it.

    The echo rule (Core's own protected-resource route echoes the requested path): the
    document an offered spelling fetches names that spelling's resource. The guard treats it
    as the one canonical resource it is, so it is served.
    """
    settings = surface_settings(toolsets="")

    with make_client(settings, private_key_pem) as client:
        response = client.get(protected_resource_path("toolsets/public/a%20b"))

    assert response.status_code == HTTPStatus.OK
    assert (
        response.json()["resource"]
        == "http://localhost:8090/dial/toolsets/public/a%20b/mcp"
    )


def test_each_toolset_gets_its_own_protected_resource_document(
    private_key_pem: str,
) -> None:
    """Per-toolset resources, one shared server: the split the design rests on."""
    settings = surface_settings(
        toolsets={
            TOOLSET_NAME: {"scopes_supported": ["default"]},
            SECOND_TOOLSET: {"scopes_supported": ["default"]},
        }
    )

    with make_client(settings, private_key_pem) as client:
        first = client.get(protected_resource_path(TOOLSET_NAME)).json()
        second = client.get(protected_resource_path(SECOND_TOOLSET)).json()
        shared = client.get(AUTHORIZATION_SERVER_PATH).json()

    assert first["resource"] == "http://localhost:8090/dial/notion/mcp"
    assert second["resource"] == "http://localhost:8090/dial/slack/mcp"
    # One server for both, identified identically.
    assert first["authorization_servers"] == second["authorization_servers"]
    assert first["authorization_servers"] == [shared["issuer"]]


def test_unserved_toolset_document_is_not_found(surface_client: TestClient) -> None:
    """A name the guard -- charset, reserved, or restriction -- refuses has no document."""
    response = surface_client.get(protected_resource_path("not-served"))

    assert response.status_code == HTTPStatus.NOT_FOUND


def test_jwks_endpoint_serves_the_public_key(client: TestClient) -> None:
    """What Core fetches to verify the gateway's tokens, by the `kid` in the header."""
    response = client.get("/dial/jwks.json")

    assert response.status_code == HTTPStatus.OK
    document = response.json()
    assert len(document["keys"]) == 1
    jwk = document["keys"][0]
    assert jwk["alg"] == "RS256"
    assert set(jwk) == {"kty", "use", "alg", "kid", "n", "e"}
    # The private components are asserted absent by name as well as by the set above:
    # this is the assertion a future change to the JWK's shape would trip over.
    for private_field in ("d", "p", "q", "dp", "dq", "qi"):
        assert private_field not in jwk


def test_jwks_key_id_matches_what_a_minted_token_carries(
    client: TestClient, private_key_pem: str
) -> None:
    """The published key and the signing key are the same keypair.

    A token whose `kid` Core cannot find in this document is a token Core rejects, so the
    two must agree — asserted through the token's header, which is what Core reads.
    """
    document = client.get("/dial/jwks.json").json()
    token = SigningKey(private_key_pem).sign({"sub": "someone"})

    assert jwt.get_unverified_header(token)["kid"] == document["keys"][0]["kid"]


# ------------------------------------------------------- the apps discovery tier


def test_app_protected_resource_document_names_the_app_resource(
    surface_client: TestClient,
) -> None:
    """The apps document describes exactly the resource the challenge named."""
    response = surface_client.get(app_protected_resource_path(APPS_NAME))

    assert response.status_code == HTTPStatus.OK
    assert response.json()["resource"] == "http://localhost:8090/apps/skills-demo/mcp"


def test_app_protected_resource_document_names_the_single_authorization_server(
    surface_client: TestClient,
) -> None:
    """One entry, the flat origin — the same server the toolset tier names."""
    document = surface_client.get(app_protected_resource_path(APPS_NAME)).json()

    assert document["authorization_servers"] == ["http://localhost:8090"]


def test_app_protected_resource_scopes_are_always_empty(
    surface_client: TestClient,
) -> None:
    """`scopes_supported` is empty for an app: no upstream leg sends scopes on it.

    Echoing the restriction's scopes, as the toolset document does where pinned, would
    advertise parameters no leg can use — so the member is present and empty, never a list.
    """
    document = surface_client.get(app_protected_resource_path(APPS_NAME)).json()

    assert document["scopes_supported"] == []


def test_app_protected_resource_document_carries_no_authentication_kind(
    surface_client: TestClient,
) -> None:
    """An app has no authentication kind, so the document echoes none."""
    document = surface_client.get(app_protected_resource_path(APPS_NAME)).json()

    assert FORMER_KIND_MEMBER not in document


def test_a_guard_passing_app_name_is_served_with_no_core_call(
    private_key_pem: str,
) -> None:
    """The mirror property, apps namespace: a phantom app is served its document.

    With no apps restriction configured, every guard-passing name is served — a name Core's
    registry knows and one it does not are indistinguishable on this surface. The document
    is built from configuration and the requested path alone, so no Core call is made at
    all; the negative control proves it against the transport.
    """
    settings = surface_settings(apps="")

    with (
        make_client(settings, private_key_pem) as client,
        respx.mock(assert_all_called=False) as router,
    ):
        response = client.get(app_protected_resource_path("a-phantom-app"))

        # The negative control: the transport recorder saw nothing, so "no call" is a
        # measurement rather than an empty assertion.
        assert router.calls.call_count == 0

    assert response.status_code == HTTPStatus.OK
    assert response.json()["resource"] == "http://localhost:8090/apps/a-phantom-app/mcp"


def test_a_restriction_excluded_app_is_not_found(private_key_pem: str) -> None:
    """Configured, the apps restriction decides the served set and excludes the rest."""
    settings = surface_settings(apps={APPS_NAME: {}})

    with make_client(settings, private_key_pem) as client:
        response = client.get(app_protected_resource_path("not-in-the-restriction"))

    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response.json() == {"detail": "unknown app"}


def test_a_shape_violating_app_path_is_refused_at_discovery(
    private_key_pem: str,
) -> None:
    """A path outside the decoded rules has no apps route the grammar can carry."""
    settings = surface_settings(apps="")

    with make_client(settings, private_key_pem) as client:
        response = client.get(app_protected_resource_path("Skills."))

    assert response.status_code == HTTPStatus.NOT_FOUND


def test_a_stored_app_path_is_served_its_document(
    private_key_pem: str,
) -> None:
    """A stored app's full resource path (`applications/public/{name}`) is served.

    The stored-app shape — a bucket-scoped resource — is part of the matrix the front door
    serves, not refused as it was under the one-segment vocabulary.
    """
    settings = surface_settings(apps="")

    with make_client(settings, private_key_pem) as client:
        response = client.get(
            app_protected_resource_path("applications/public/a-phantom-app")
        )

    assert response.status_code == HTTPStatus.OK
    assert (
        response.json()["resource"]
        == "http://localhost:8090/apps/applications/public/a-phantom-app/mcp"
    )


def test_the_wider_app_charset_is_served_at_discovery(
    private_key_pem: str,
) -> None:
    """An app name with the wider Core charset (uppercase, a dot) is served.

    `MyApp.v2` is Core's application-name rule, not the old one-segment `[a-z0-9-]` charset,
    so it is a served app path — nothing in the gateway re-implements Core's per-type rules.
    """
    settings = surface_settings(apps="")

    with make_client(settings, private_key_pem) as client:
        response = client.get(app_protected_resource_path("MyApp.v2"))

    assert response.status_code == HTTPStatus.OK
    assert response.json()["resource"] == "http://localhost:8090/apps/MyApp.v2/mcp"


@pytest.mark.parametrize("name", ["token", "authorize"])
def test_a_reserved_toolset_name_is_a_valid_app_name_at_discovery(
    private_key_pem: str, name: str
) -> None:
    """A reserved front-door name is a served app name — the apps namespace has none.

    The toolset guard's reserved names are `/dial/`-scoped authorization-surface segments,
    and an app name occupying `/apps/{name}/…` can never capture them, so such a name is
    served its document here exactly as any other.
    """
    settings = surface_settings(apps="")

    with make_client(settings, private_key_pem) as client:
        response = client.get(app_protected_resource_path(name))

    assert response.status_code == HTTPStatus.OK
    assert response.json()["resource"] == f"http://localhost:8090/apps/{name}/mcp"


def test_the_same_name_serves_distinct_toolset_and_app_documents(
    private_key_pem: str,
) -> None:
    """A name can be both a toolset and an app; the two documents name different resources.

    The registries are disjoint namespaces in Core, so the two surfaces never collide: each
    document names the resource in its own namespace's prefix.
    """
    settings = surface_settings(
        toolsets={TOOLSET_NAME: {"scopes_supported": ["default"]}},
        apps={TOOLSET_NAME: {}},
    )

    with make_client(settings, private_key_pem) as client:
        toolset_doc = client.get(protected_resource_path(TOOLSET_NAME)).json()
        app_doc = client.get(app_protected_resource_path(TOOLSET_NAME)).json()

    assert toolset_doc["resource"] == f"http://localhost:8090/dial/{TOOLSET_NAME}/mcp"
    assert app_doc["resource"] == f"http://localhost:8090/apps/{TOOLSET_NAME}/mcp"


def test_a_burst_of_app_discovery_refusals_is_limited_and_writes_nothing(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The apps discovery route joins the shared limiter with the no-record rule.

    Every guard refusal on this route writes an audit record, so without the limiter an
    unauthenticated caller looping a guard-failing path would grow the operator's log at the
    request rate. Over the limit the request is answered 429 and writes nothing — asserted
    on both halves, since a limiter that still wrote a `rate_limited` record per refused
    request would leave the volume unbounded.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(
        apps="",
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=DISCOVERY_LIMIT,
        gateway_rate_global_per_minute=DISCOVERY_LIMIT * 10,
    )

    with make_client(settings, private_key_pem) as client:
        responses = [
            client.get(app_protected_resource_path("a%7Bb"))
            for _ in range(DISCOVERY_LIMIT + 1)
        ]

    assert all(
        r.status_code == HTTPStatus.NOT_FOUND for r in responses[:DISCOVERY_LIMIT]
    )
    excess = responses[-1]
    assert excess.status_code == HTTPStatus.TOO_MANY_REQUESTS

    audit_records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    assert len(audit_records) == DISCOVERY_LIMIT
    assert all(r["reason"] != "rate_limited" for r in audit_records)
    assert all(r["event"] == "flow_refused" for r in audit_records)


def test_an_app_guard_refusal_is_recorded_with_its_own_reason(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The app guard's refusal classes carry their own fixed-vocabulary tokens.

    A shape violation and a restriction exclusion each land on their own committed token,
    with the offered path truncated per the existing cap — and no reserved class exists on
    this namespace.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(
        apps={APPS_NAME: {}}, dcr_store_path=str(tmp_path / "store.json")
    )

    with make_client(settings, private_key_pem) as client:
        charset = client.get(app_protected_resource_path("Skills."))
        excluded = client.get(app_protected_resource_path("not-in-the-restriction"))

    refusals = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    assert charset.status_code == excluded.status_code == HTTPStatus.NOT_FOUND
    assert refusals[0]["reason"] == "invalid_resource_path"
    assert refusals[0]["name"] == "Skills."
    assert refusals[0]["resource_kind"] == "app"
    assert refusals[1]["reason"] == "restricted_app"
    assert refusals[1]["name"] == "not-in-the-restriction"
    assert refusals[1]["resource_kind"] == "app"


# ------------------------------------------------------- the discovery aliases

# The suffixes the path-insertion forms are driven with: an app resource path, a toolset
# resource path, a multi-segment one, the empty suffix (the trailing slash), percent-encoded
# quote and angle bracket (the characters an echo would have to escape), and a long segment.
# The handler never reads the suffix, so every one must answer the same bytes.
ALIAS_SUFFIXES = [
    f"apps/{APPS_NAME}/mcp",
    f"dial/{TOOLSET_NAME}/mcp",
    "a/b/c/d/e",
    "",
    "%22",
    "%3C",
    "x" * 512,
]

PATH_INSERTION_FAMILIES = [AUTHORIZATION_SERVER_PATH, OPENID_CONFIGURATION_PATH]

# Members an OpenID Provider document requires and the gateway's does not carry: the gateway
# is not an OpenID Provider, so none of these may appear at any alias.
OPENID_PROVIDER_MEMBERS = [
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "userinfo_endpoint",
    "scopes_supported",
]


def alias_paths() -> list[str]:
    """Every alias path the discovery requirement names, one per suffix shape."""
    paths = [OPENID_CONFIGURATION_PATH]
    paths.extend(
        f"{family}/{suffix}"
        for family in PATH_INSERTION_FAMILIES
        for suffix in ALIAS_SUFFIXES
    )
    return paths


@pytest.mark.parametrize("dcr_enabled", [False, True])
def test_every_alias_serves_the_canonical_document_byte_for_byte(
    private_key_pem: str, tmp_path: Path, *, dcr_enabled: bool
) -> None:
    """One builder, one response path: each alias is byte-identical to the canonical body.

    Run with dynamic registration both off and on, so the one member that follows the flag
    (`registration_endpoint`) is shown to follow it at every alias, not only at the
    canonical path. `issuer` is the public origin at each: the path-insertion forms never
    echo their suffix, because the gateway has one issuer and every token carries it.
    """
    settings = surface_settings(
        dcr_enabled=dcr_enabled, dcr_store_path=str(tmp_path / "store.json")
    )
    with make_client(settings, private_key_pem) as client:
        canonical = client.get(AUTHORIZATION_SERVER_PATH)
        assert canonical.status_code == HTTPStatus.OK
        for path in alias_paths():
            response = client.get(path)
            assert response.status_code == HTTPStatus.OK, path
            assert response.content == canonical.content, path
            assert response.headers["content-type"] == canonical.headers["content-type"]
            document = response.json()
            assert document["issuer"] == "http://localhost:8090", path
            assert ("registration_endpoint" in document) is dcr_enabled, path


def test_an_alias_makes_no_core_call_and_writes_no_audit_record(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An alias costs what the canonical location costs: no Core call, no audit record.

    The recorder and the audit capture are proven live by a control request first (a
    refused app resource path writes an audit record), so "none" is a measurement.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(
        apps={APPS_NAME: {}}, dcr_store_path=str(tmp_path / "store.json")
    )

    def audit_count() -> int:
        return sum(1 for r in caplog.records if r.name == "gateway.audit")

    with (
        make_client(settings, private_key_pem) as client,
        respx.mock(assert_all_called=False) as router,
    ):
        client.get(app_protected_resource_path("Skills."))
        assert audit_count() == 1

        for path in [AUTHORIZATION_SERVER_PATH, *alias_paths()]:
            assert client.get(path).status_code == HTTPStatus.OK, path

        assert router.calls.call_count == 0
    assert audit_count() == 1


def test_no_alias_carries_an_openid_provider_member(client: TestClient) -> None:
    """The OpenID Connect location serves the OAuth document as it stands.

    Adding provider members would advertise behavior the gateway does not have: a relying
    party told which ID-token algorithms are supported would request `openid` and wait for
    an ID token that never arrives. The document has no scope list at all, so there is no
    `openid` in one either.
    """
    for path in alias_paths():
        document = client.get(path).json()
        present = [name for name in OPENID_PROVIDER_MEMBERS if name in document]
        assert not present, f"{path} carries {present}"


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "POST"])
def test_aliases_answer_every_method_but_get_with_the_frameworks_405(
    client: TestClient, method: str
) -> None:
    """The aliases behave as the canonical route: `GET` only, the rest `405` with `Allow`.

    No alias serves an `Access-Control-*` header either, which keeps the back-channel
    posture of the discovery documents uniform across the alias set.
    """
    for path in alias_paths():
        response = client.request(method, path)
        assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED, f"{method} {path}"
        assert response.headers["allow"] == "GET", f"{method} {path}"
        assert not [
            name
            for name in response.headers
            if name.lower().startswith("access-control-")
        ]


def test_the_alias_suffix_is_never_reflected_in_the_body(client: TestClient) -> None:
    """A suffix that would break out of markup or a JSON string leaves no trace in the body."""
    for suffix in ("%22", "%3Cscript%3E", "needle-" + "z" * 64):
        response = client.get(f"{AUTHORIZATION_SERVER_PATH}/{suffix}")
        assert response.status_code == HTTPStatus.OK
        assert "needle-" not in response.text
        assert "script" not in response.text
        assert suffix not in response.text


def test_a_path_that_only_resembles_an_alias_is_not_served(client: TestClient) -> None:
    """The aliases end at the segment boundary: a longer final segment is the framework's 404."""
    for path in (
        f"{OPENID_CONFIGURATION_PATH}.json",
        f"{OPENID_CONFIGURATION_PATH}X",
        f"{AUTHORIZATION_SERVER_PATH}X",
    ):
        assert client.get(path).status_code == HTTPStatus.NOT_FOUND, path
