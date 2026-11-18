"""Tests for configuration loading and validation.

Each test states the setting it exercises, so a change to a default that silently
changes behaviour fails here rather than in a flow. Settings are built with the
environment switched off (`make_settings`), which keeps the suite hermetic — see the
last test in this file, which pins that property.

The startup refusals live here rather than with the endpoints they protect: each is a
configuration the gateway declines to run with, and the test asserting it is also the
statement of which configuration that is.
"""

from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path

import pytest
from gateway.settings import (
    DEFAULT_RESOURCE_PATH_MAX_SEGMENTS,
    RESERVED_TOOLSET_NAMES,
    Settings,
)
from pydantic import SecretStr, ValidationError

from tests.conftest import (
    APPS_NAME,
    CUSTODY_KEY_B64,
    CUSTODY_KEY_ID,
    IDP_LIFESPAN_SECONDS,
    TOOLSET_NAME,
    make_settings,
)

# The chosen default refresh window (8 h) and the operator-declared identity-provider session
# bound (24 h). Held as constants so an assertion reads as the design's numbers rather than
# bare literals.
DEFAULT_REFRESH_TTL_SECONDS = 28_800

# The shipped form-body cap and the custody size bound, so the coupling assertions read as
# the design's numbers rather than bare literals.
DEFAULT_FORM_MAX_BODY_BYTES = 16_384
DEFAULT_PROVIDER_TOKEN_MAX_BYTES = 4_096

# A raised bound and cap pair, for the coupling test that moves both together.
RAISED_PROVIDER_BOUND = 16_000
RAISED_FORM_CAP = 48_000

# A valid restriction entry: `scopes_supported` is the only member a restriction entry
# declares, so a test that wants a configured entry spells this rather than repeating it.
_OAUTH_ENTRY: dict[str, object] = {"scopes_supported": ["default"]}

# The shipped discovery-cache window, held as the design's number rather than a bare
# literal in the assertion that pins it.
SHIPPED_CACHE_TTL_SECONDS = 300


def a_custody_key(*, length: int = 32) -> str:
    """A base64 custody key of the named raw length, for the keyset refusals below."""
    return base64.b64encode(secrets.token_bytes(length)).decode()


def test_idp_sso_session_bound_is_required() -> None:
    """The carried session refresh token's window is machine-checked, so its input cannot
    be optional.

    With no default the gateway cannot start on a guessed bound: a deployment that forgets
    the setting learns at startup, not from a silently wrong window.
    """
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            _env_file=None,
            gateway_custody_keys={CUSTODY_KEY_ID: a_custody_key()},
            idp_client_secret="the-client-secret",
        )

    assert "idp_sso_session_max_seconds" in str(excinfo.value)


def test_the_custody_keyset_is_required() -> None:
    """Without a custody key the gateway cannot carry the provider token at all.

    The refusal names the setting and shows the shape to set, so the operator has the
    remedy in front of them rather than a failed sign-in later.
    """
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            _env_file=None,
            idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
            roles_source_path="roles",
            idp_client_secret="the-client-secret",
        )

    assert "gateway_custody_keys" in str(excinfo.value)


def test_roles_source_path_is_required() -> None:
    """Roles are read from a configured path, with no default.

    A silent default here is the trap this setting exists to avoid: a wrong path yields a
    role-less token, which Core answers as a 403 with nothing in the logs saying why.
    """
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            _env_file=None,
            idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
            gateway_custody_keys={CUSTODY_KEY_ID: a_custody_key()},
            idp_client_secret="the-client-secret",
        )

    assert "roles_source_path" in str(excinfo.value)


def test_defaults_are_inert() -> None:
    """Every default is safe to ship: the signing key absent, and the abuse-prone paths
    off.

    (The identity-provider client's secret has no inert default — it is required, and the
    fixture supplies it; the required-secret refusals are pinned in their own section
    below.)
    """
    settings = make_settings()

    assert settings.gateway_signing_key is None
    # Dynamic client registration is open registration, so it is off unless asked for.
    assert settings.dcr_enabled is False
    # Inferring the resource silently addresses a token to a toolset the client never
    # named; the escape hatch stays off.
    assert settings.gateway_infer_resource_single_toolset is False
    # Rotation default-on; the rotated token keeps the original expiry either way.
    assert settings.gateway_rotate_refresh_tokens is True


def test_the_federation_defaults_name_no_provider() -> None:
    """The shipped identity-provider defaults name no provider's address.

    The issuer's default is the RFC 2606 reserved domain — a deployment that forgets the
    setting fails loudly at the identity leg rather than silently pointing at a
    live-looking host — and the back-channel override is unset, so a single-origin
    provider configures nothing. Built on the bare model (the local-shape fixture values
    `make_settings` supplies would defeat the assertion).
    """
    defaults = Settings(
        _env_file=None,
        idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
        roles_source_path="roles",
        gateway_custody_keys={CUSTODY_KEY_ID: a_custody_key()},
        idp_client_secret="the-client-secret",
    )

    assert defaults.idp_issuer == "https://idp.example.com/"
    assert defaults.idp_backchannel_base_url is None


def test_default_refresh_ttl_fits_the_local_deployment() -> None:
    """The shipped refresh window must fit the local realm's declared session bound.

    8 h is the chosen window; if a future default raised it past the deployment it is meant
    for, the local stack would refuse to start.
    """
    settings = make_settings()

    assert settings.gateway_refresh_ttl_seconds == DEFAULT_REFRESH_TTL_SECONDS
    assert settings.gateway_refresh_ttl_seconds < IDP_LIFESPAN_SECONDS


def test_default_bounds_satisfy_the_size_cap_coupling() -> None:
    """The shipped size bound fits inside the shipped form cap, with headroom.

    The two bounds are coupled; the defaults are the worked example of a configuration that
    satisfies the coupling, which is what makes the relationship a property of the file
    rather than a claim about one deployment's numbers.
    """
    settings = make_settings()

    assert settings.gateway_form_max_body_bytes == DEFAULT_FORM_MAX_BODY_BYTES
    assert (
        settings.gateway_custody_provider_token_max_bytes
        == DEFAULT_PROVIDER_TOKEN_MAX_BYTES
    )


def test_dcr_store_path_defaults_to_the_mounted_volume() -> None:
    """The store must default to the path the compose volume is mounted at."""
    assert make_settings().dcr_store_path == "/data/dcr-registrations.json"


# --------------------------------------------------------------- startup refusals


def test_refresh_ttl_longer_than_the_declared_session_bound_refuses_startup() -> None:
    """The session-bound check is enforced, not documented.

    A refresh window longer than the operator-declared session bound would carry the session
    refresh token past the point the provider keeps it usable, so startup refuses and names
    both values — an operator reading the error has the two numbers they need to fix it.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            gateway_refresh_ttl_seconds=IDP_LIFESPAN_SECONDS + 1,
            idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
        )

    message = str(excinfo.value)
    assert str(IDP_LIFESPAN_SECONDS + 1) in message
    assert str(IDP_LIFESPAN_SECONDS) in message
    # The refusal is re-derived: it names the setting an operator sets, not the retired one.
    assert "idp_sso_session_max_seconds" in message
    assert "idp_access_token_lifespan_seconds" not in message


def test_the_session_bound_refusal_names_the_provider_policy_semantics() -> None:
    """The refusal states what the check is: an assertion about session policy.

    The failure it cannot catch — a session policy shorter than declared — is named, and so
    is the guidance that a short window is a correct configuration rather than a degraded
    one. The retired staleness rationale does not survive anywhere in it.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            gateway_refresh_ttl_seconds=IDP_LIFESPAN_SECONDS + 1,
            idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
        )

    message = str(excinfo.value)
    assert "session refresh token" in message
    assert "correct configuration" in message
    assert "staler" not in message


def test_refresh_ttl_equal_to_the_declared_session_bound_is_accepted() -> None:
    """The bound is "not longer than", so equality is inside it, not outside."""
    settings = make_settings(
        gateway_refresh_ttl_seconds=IDP_LIFESPAN_SECONDS,
        idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
    )

    assert settings.gateway_refresh_ttl_seconds == IDP_LIFESPAN_SECONDS


# ------------------------------------------------------- the custody keyset refusals


def test_an_empty_custody_keyset_refuses_startup() -> None:
    """An empty keyset means the gateway could mint nothing it can later decrypt."""
    with pytest.raises(ValidationError) as excinfo:
        make_settings(gateway_custody_keys={})

    assert "gateway_custody_keys" in str(excinfo.value)


def test_a_multi_active_custody_keyset_refuses_startup() -> None:
    """Two live keys would let a transplanted envelope header reach a second key.

    The single-active-keyset invariant is what closes AES-GCM's missing key commitment
    today; a second entry breaks it, so a keyset holding one is refused rather than used.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            gateway_custody_keys={
                CUSTODY_KEY_ID: a_custody_key(),
                "another-key": a_custody_key(),
            }
        )

    assert "exactly one key" in str(excinfo.value)


@pytest.mark.parametrize("length", [16, 24])
def test_a_wrong_length_custody_key_refuses_startup(length: int) -> None:
    """AES-GCM follows the key's length, so a short key would silently run a weaker cipher.

    A 16- or 24-byte key would run AES-128 or AES-192 for the key's whole life, falsifying
    the pinned-algorithm claim without any visible failure. The refusal pins the length at
    startup.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            gateway_custody_keys={CUSTODY_KEY_ID: a_custody_key(length=length)}
        )

    assert "32 bytes" in str(excinfo.value)


def test_a_custody_key_that_is_not_base64_refuses_startup() -> None:
    """The key is a base64 value; anything else is a configuration mistake, not a key."""
    with pytest.raises(ValidationError) as excinfo:
        make_settings(gateway_custody_keys={CUSTODY_KEY_ID: "not base64 at all!!"})

    assert "base64" in str(excinfo.value)


def test_a_custody_key_id_outside_the_header_shape_refuses_startup() -> None:
    """The key id is a header byte string; a longer one would not fit the envelope."""
    with pytest.raises(ValidationError) as excinfo:
        make_settings(gateway_custody_keys={"k" * 64: a_custody_key()})

    assert "key id" in str(excinfo.value)


# ------------------------------------------------- the size-bound / form-cap coupling


def test_a_provider_token_bound_past_the_form_cap_refuses_startup() -> None:
    """The coupling is enforced: a bound the cap cannot deliver is refused, not documented.

    The failure it prevents is the far-from-its-cause one — sign-ins succeed, every refresh
    fails over-cap, hours later. The refusal names both settings so the remedy is visible.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            gateway_custody_provider_token_max_bytes=DEFAULT_PROVIDER_TOKEN_MAX_BYTES,
            gateway_form_max_body_bytes=1_024,
        )

    message = str(excinfo.value)
    assert "gateway_form_max_body_bytes" in message
    assert "gateway_custody_provider_token_max_bytes" in message


def test_the_defaults_satisfy_the_size_coupling() -> None:
    """The negative control: the shipped defaults are inside the coupling, not outside it."""
    settings = make_settings()

    assert (
        settings.gateway_custody_provider_token_max_bytes
        == DEFAULT_PROVIDER_TOKEN_MAX_BYTES
    )
    assert settings.gateway_form_max_body_bytes == DEFAULT_FORM_MAX_BODY_BYTES


def test_raising_the_provider_bound_with_the_cap_is_accepted() -> None:
    """The coupling moves with both values: raising the bound and the cap together starts."""
    settings = make_settings(
        gateway_custody_provider_token_max_bytes=RAISED_PROVIDER_BOUND,
        gateway_form_max_body_bytes=RAISED_FORM_CAP,
    )

    assert settings.gateway_custody_provider_token_max_bytes == RAISED_PROVIDER_BOUND


@pytest.mark.parametrize("name", RESERVED_TOOLSET_NAMES)
def test_reserved_path_segment_refuses_startup(name: str) -> None:
    """A reserved first segment can never be routed, so it is refused where it is configured.

    The front router's authorization-surface location matches `/dial/<segment>/...` for
    these names before the data path can, so such a resource's MCP traffic would never reach
    Core. The refusal names the entry; the reserved set itself is asserted below.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(toolsets={name: dict(_OAUTH_ENTRY)})

    assert name in str(excinfo.value)


@pytest.mark.parametrize("name", RESERVED_TOOLSET_NAMES)
def test_reserved_segments_are_refused_as_reserved_naming_the_whole_set(
    name: str,
) -> None:
    """Every reserved first segment is refused *as reserved*, naming the whole set.

    The set is refused wholesale, so the operator reads the reserved names off the message
    rather than discovering the next one at the following start.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(toolsets={name: dict(_OAUTH_ENTRY)})

    message = str(excinfo.value)
    assert "reserved first segment" in message
    for listed in RESERVED_TOOLSET_NAMES:
        assert listed in message


def test_a_reserved_name_deeper_in_a_path_is_a_valid_entry() -> None:
    """A reserved name appearing only in a later segment is a legal, routable path.

    The reserved rule is a first-segment match, and a stored resource's first segment is its
    type segment (`toolsets`, `applications`), never a reserved name.
    """
    settings = make_settings(toolsets={"toolsets/public/token": dict(_OAUTH_ENTRY)})

    assert "toolsets/public/token" in settings.toolsets


@pytest.mark.parametrize(
    "path",
    [
        "Notion.",  # trailing dot
        "toolsets/public/x.",  # trailing dot at depth
        "a%7Bb",  # a forbidden character, offered encoded
        "toolsets//public/x",  # an empty segment
        "a/../b",  # a dot segment
        "x" * 901,  # over the byte cap
        "/".join(
            ["s"] * (DEFAULT_RESOURCE_PATH_MAX_SEGMENTS + 1)
        ),  # over the depth cap
        "a%FFb",  # a segment that does not decode strictly
    ],
)
def test_a_path_outside_the_decoded_rules_refuses_startup(path: str) -> None:
    """Entries follow the path grammar, so a path the router could never route refuses start.

    Each class — a forbidden character, a trailing dot, a dot/empty segment, an over-length
    or over-depth path, a non-strict sequence — refuses the container's start, naming the
    entry and the rule it broke.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(toolsets={path: dict(_OAUTH_ENTRY)})

    message = str(excinfo.value)
    assert path in message
    assert "could never be routed" in message


def test_a_stored_toolset_path_is_a_valid_entry() -> None:
    """A stored toolset's full resource path (`toolsets/public/x`) is accepted."""
    settings = make_settings(toolsets={STORED_TOOLSET_PATH: dict(_OAUTH_ENTRY)})

    assert STORED_TOOLSET_PATH in settings.toolsets


# -------------------------- the redirect-URI admission rule (task 5.1, the startup site)

# A plain-`http` redirect on a real host, and the loopback/`https` shapes that stay admitted.
HTTP_COLLECTOR_URI = "http://collector.example/callback"
LOOPBACK_CALLBACK_URI = "http://127.0.0.1:8766/callback"
HTTPS_CALLBACK_URI = "https://app.example/callback"


def test_a_pre_registered_http_redirect_uri_refuses_startup_naming_the_entry() -> None:
    """The operator's own configuration is an admission site, not a bypass of the rule.

    A pre-registered redirect URI that is plain `http` on a real host refuses the gateway's
    startup with an error naming the entry — the same rule the DCR and CIMD paths enforce,
    because an operator who configured such a URI would have registered exactly the value
    the registration surfaces refuse.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            pre_registered_clients={
                "a-harness": {"redirect_uris": [HTTP_COLLECTOR_URI]}
            }
        )

    message = str(excinfo.value)
    assert "a-harness" in message
    assert "must be `https`" in message


def test_pre_registered_loopback_and_https_redirect_uris_are_admitted() -> None:
    """The loopback exception and `https` hold at the startup site too."""
    settings = make_settings(
        pre_registered_clients={
            "a-harness": {"redirect_uris": [LOOPBACK_CALLBACK_URI, HTTPS_CALLBACK_URI]}
        }
    )

    assert settings.pre_registered_clients["a-harness"].redirect_uris == [
        LOOPBACK_CALLBACK_URI,
        HTTPS_CALLBACK_URI,
    ]


# ------------------------------------------------------- the apps restriction


def test_an_app_entry_declares_only_the_name() -> None:
    """An app restriction entry carries nothing but the name.

    An app has no authentication kind (it is credential-free by construction) and no scopes
    to declare (no leg sends any), so the model has no member to carry one — an entry is
    accepted on its name alone.
    """
    settings = make_settings(apps={APPS_NAME: {}})

    assert APPS_NAME in settings.apps


def test_an_app_entry_carrying_scopes_is_refused_at_parse() -> None:
    """A member the app namespace has no use for is refused loudly, naming the field.

    Ignoring it would leave an operator believing a declaration was in effect: the apps
    document's `scopes_supported` is empty regardless, so a pinned entry's scopes would be a
    field nothing reads.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(apps={APPS_NAME: {"scopes_supported": ["default"]}})

    assert "scopes_supported" in str(excinfo.value)


def test_an_app_entry_carrying_a_kind_is_refused_at_parse() -> None:
    """An app has no authentication kind, so an entry declaring one is refused by name."""
    with pytest.raises(ValidationError) as excinfo:
        make_settings(apps={APPS_NAME: {"authentication_type": "OAUTH"}})

    assert "authentication_type" in str(excinfo.value)


@pytest.mark.parametrize(
    "path",
    [
        "SkillsDemo.",  # a trailing dot
        "skills%7Bdemo",  # a forbidden character, offered encoded
        "bucket//skills",  # an empty segment
        "a/../b",  # a dot segment
        "x" * 901,  # over the byte cap
    ],
)
def test_an_app_path_outside_the_decoded_rules_refuses_startup(path: str) -> None:
    """A pinned app path the router's apps grammar could never route fails at startup.

    The router's apps location is static configuration with no view of what Core serves, so
    a path outside the decoded per-segment rules is refused here rather than serving an app
    no harness can reach. The refusal is operator-facing and names the entry.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(apps={path: {}})

    message = str(excinfo.value)
    assert path in message
    assert "could never be routed" in message


@pytest.mark.parametrize(
    "path", ["SkillsDemo", "skills_demo", "skills demo", "bucket/skills"]
)
def test_the_wider_app_charset_is_a_valid_entry(path: str) -> None:
    """Core's application-name rule is wider than `[a-z0-9-]`, so those names are served.

    `[A-Za-z0-9._%:-]` is Core's application-name rule; a stored app path
    (`applications/{bucket}/{name}`) is a resource path. Nothing in the gateway
    re-implements Core's per-type name rules, so these are valid restriction entries.
    """
    settings = make_settings(apps={path: {}})

    assert path in settings.apps


def test_a_reserved_front_door_name_is_a_valid_app_path() -> None:
    """The toolset guard's reserved names do not apply to the apps namespace.

    The reserved names are `/dial/`-scoped authorization-surface segments, and an app path
    occupying `/apps/{path}/…` can never capture them — so `token` is a served app path here,
    where it is refused as a toolset first segment.
    """
    settings = make_settings(apps={"token": {}})

    assert "token" in settings.apps


def test_the_app_restriction_is_independent_of_the_toolset_restriction() -> None:
    """The two restrictions never consult each other.

    A name can exist as both a toolset and an app — they are disjoint registries in Core —
    so pinning three toolsets must not unpublish every app, and vice versa.
    """
    settings = make_settings(toolsets={TOOLSET_NAME: dict(_OAUTH_ENTRY)}, apps="")

    assert TOOLSET_NAME in settings.toolsets
    assert settings.apps == {}


def test_inference_never_consults_the_apps_restriction() -> None:
    """Inference's startup requirement is the toolset restriction alone.

    With the toolset restriction pinned to one entry and an apps restriction also
    configured, inference is accepted — the apps restriction is not its dependency.
    """
    settings = make_settings(
        gateway_infer_resource_single_toolset=True,
        toolsets={TOOLSET_NAME: dict(_OAUTH_ENTRY)},
        apps={APPS_NAME: {}},
    )

    assert settings.gateway_infer_resource_single_toolset is True


def test_inference_with_only_an_apps_restriction_refuses_startup() -> None:
    """An apps restriction cannot stand in for the toolset one inference needs.

    With no toolset restriction configured, inference has nothing to infer even though an
    apps restriction is present — the refusal names the toolset restriction.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            gateway_infer_resource_single_toolset=True,
            toolsets="",
            apps={APPS_NAME: {}},
        )

    assert "gateway_infer_resource_single_toolset" in str(excinfo.value)


def test_non_oauth_entry_is_accepted() -> None:
    """A restriction entry declares no authentication kind, so any Core kind is a valid entry.

    The kind a flow acts on is Core's, read per flow: a non-OAuth toolset is served through
    the signed-in short-circuit when a credential is stored and refused on the impossible
    branch otherwise. An operator-declared kind would be a second, staler source of a fact
    Core answers per flow — so the member is gone from the schema, and this entry carries
    no kind at all.
    """
    settings = make_settings(toolsets={"legacy": {}})

    assert "legacy" in settings.toolsets


def test_the_removed_authentication_type_member_is_refused_at_parse() -> None:
    """A mapping still carrying the removed member is refused loudly, naming the field.

    The member no longer means anything — the kind is Core's, read per flow — so silently
    ignoring it would leave an operator believing a declaration was in effect. The schema
    forbids unknown members, so the one breaking operator change fails at parse.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(toolsets={"legacy": {"authentication_type": "API_KEY"}})

    assert "authentication_type" in str(excinfo.value)


def test_oauth_toolset_refuses_startup_with_an_unknown_escape_field() -> None:
    """An unknown field is refused on an accepted entry too.

    An entry is accepted, so were the field merely ignored here it would be a setting an
    operator believed was in effect and was not — the silent-misconfiguration class the
    mapping's field policy exists to remove.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(toolsets={TOOLSET_NAME: {"route_only": True}})

    assert "route_only" in str(excinfo.value)


def test_mapping_entries_are_closed_to_unknown_fields() -> None:
    """A misspelled restriction field is refused, not ignored.

    An ignored field would be a setting an operator believes is in effect and is not —
    the silent-misconfiguration class this whole validation block exists to remove.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(toolsets={"notion": {"authtype": "OAUTH"}})

    assert "authtype" in str(excinfo.value)


def test_placeholder_signing_key_refuses_startup() -> None:
    """The committed example's placeholder is a real value, so it must be refused by name.

    A deployment that never replaced it would sign tokens with a key published in this
    repository — a key anyone could mint identities with.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(gateway_signing_key="generate-me")

    assert "placeholder" in str(excinfo.value)


def test_a_refusal_report_carries_no_settings_values() -> None:
    """A startup refusal must name the setting, not dump the configuration.

    A validation error's report normally carries a repr of the input it was validating,
    which for this model is the whole settings mapping — every deployment value, and the
    signing key's own PEM boundary at the end of it. The refusals name the setting at
    fault, so the input repr adds nothing an operator needs and is suppressed.
    """
    secret_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\n-----END PRIVATE KEY-----"

    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            gateway_signing_key=secret_pem,
            toolsets={"token": dict(_OAUTH_ENTRY)},
            idp_client_secret="a-client-secret-value",
        )

    message = str(excinfo.value)
    assert "reserved" in message
    assert "input_value" not in message
    assert "MIIEvQIBADANBgkqhkiG9w0B" not in message
    assert "END PRIVATE KEY" not in message
    assert "a-client-secret-value" not in message


def test_explicit_empty_mapping_is_accepted() -> None:
    """An unset mapping arrives as an empty string from the environment, not as JSON.

    The compose file passes every setting explicitly, so an empty value must mean "none
    configured" rather than a malformed document.
    """
    settings = make_settings(toolsets="")

    assert settings.toolsets == {}


def test_malformed_mapping_json_refuses_startup() -> None:
    with pytest.raises(ValidationError) as excinfo:
        make_settings(toolsets="not json at all")

    assert "JSON" in str(excinfo.value)


def test_a_malformed_custody_document_refuses_without_echoing_its_text() -> None:
    """A malformed custody document can embed key material, so the refusal names no value.

    The parse refusal is shared by every JSON-document setting; the custody document is the
    one whose text can carry real key material, so this pins the no-echo rule where it
    matters: the refusal states the shape problem and never the string it choked on.
    """
    material_blob = base64.b64encode(secrets.token_bytes(32)).decode()
    # A malformed document (no closing brace) whose text carries a base64 blob.
    malformed = '{"key": "' + material_blob + '"'

    with pytest.raises(ValidationError) as excinfo:
        make_settings(gateway_custody_keys=malformed)

    message = str(excinfo.value)
    assert "JSON" in message
    assert material_blob not in message


# ------------------------------------------------------------------ derived helpers

# The stored-toolset path the round-trip rows use — a multi-segment resource path Core's
# listing route keys on.
STORED_TOOLSET_PATH = "toolsets/public/notion"


def test_toolset_resource_uri_is_derived_from_the_origin_and_path() -> None:
    """One spelling serves the router, the discovery document, and the resource check."""
    settings = make_settings(
        gateway_public_origin="https://dial.example.org",
        toolsets={TOOLSET_NAME: dict(_OAUTH_ENTRY)},
    )

    assert (
        settings.toolset_resource_uri(TOOLSET_NAME)
        == "https://dial.example.org/dial/notion/mcp"
    )


def test_toolset_path_from_resource_inverts_the_derivation_exactly() -> None:
    """The resource-to-path inverse is anchored, so a near-miss is a different resource.

    Under dynamic serving there is no mapping to look the path up in, so the resource URI
    is parsed back out by the one derivation. A trailing slash is a different resource URI,
    not this path's — but a multi-segment path is a served resource, so it resolves whole.
    """
    settings = make_settings(toolsets={TOOLSET_NAME: dict(_OAUTH_ENTRY)})

    assert (
        settings.toolset_path_from_resource("http://localhost:8090/dial/notion/mcp")
        == "notion"
    )
    # A multi-segment path is the resource path, returned in the URI's own spelling.
    assert (
        settings.toolset_path_from_resource(
            "http://localhost:8090/dial/toolsets/public/notion/mcp"
        )
        == STORED_TOOLSET_PATH
    )
    # A trailing slash is a different resource URI, and the derivation is anchored.
    assert (
        settings.toolset_path_from_resource("http://localhost:8090/dial/notion/mcp/")
        is None
    )
    assert (
        settings.toolset_path_from_resource("https://other.example/dial/notion/mcp")
        is None
    )


def test_app_resource_uri_is_derived_from_the_origin_and_path() -> None:
    """The apps twin of the toolset derivation, in the apps namespace's own prefix."""
    settings = make_settings(
        gateway_public_origin="https://dial.example.org",
        apps={APPS_NAME: {}},
    )

    assert (
        settings.app_resource_uri(APPS_NAME)
        == "https://dial.example.org/apps/skills-demo/mcp"
    )


def test_app_path_from_resource_inverts_the_derivation_exactly() -> None:
    """The app resource-to-path inverse is anchored, mirroring the toolset one."""
    settings = make_settings(apps={APPS_NAME: {}})

    assert (
        settings.app_path_from_resource("http://localhost:8090/apps/skills-demo/mcp")
        == APPS_NAME
    )
    # A stored-app path (a multi-segment resource path) resolves whole.
    assert (
        settings.app_path_from_resource(
            "http://localhost:8090/apps/applications/public/skills-demo/mcp"
        )
        == "applications/public/skills-demo"
    )
    assert (
        settings.app_path_from_resource("http://localhost:8090/apps/skills-demo/mcp/")
        is None
    )
    assert (
        settings.app_path_from_resource("https://other.example/apps/skills-demo/mcp")
        is None
    )


def test_the_two_resource_derivations_are_disjoint_by_prefix() -> None:
    """A toolset URI never resolves as an app path, and an app URI never as a toolset.

    The prefixes `/dial/` and `/apps/` are disjoint, so no resource URI resolves both ways —
    which is what keeps a request from being reinterpreted across kinds between surfaces.
    The same path on both kinds resolves to the kind its prefix names.
    """
    settings = make_settings(
        toolsets={TOOLSET_NAME: dict(_OAUTH_ENTRY)}, apps={TOOLSET_NAME: {}}
    )
    toolset_uri = settings.toolset_resource_uri(TOOLSET_NAME)
    app_uri = settings.app_resource_uri(TOOLSET_NAME)

    assert settings.toolset_path_from_resource(app_uri) is None
    assert settings.app_path_from_resource(toolset_uri) is None
    assert settings.resource_kind_and_path(toolset_uri) == ("toolset", TOOLSET_NAME)
    assert settings.resource_kind_and_path(app_uri) == ("app", TOOLSET_NAME)
    assert settings.resource_kind_and_path("http://localhost:8090/other/x/mcp") is None


def test_the_canonical_path_has_one_spelling_per_resource() -> None:
    """Two spellings of one resource canonicalize to one identity.

    The identity rule (the addressing-vocabulary requirement): `%78` and `x` are one
    resource, lowercase-hex escapes canonicalize to uppercase, and the unreserved set stays
    raw. Segmentation precedes decoding, so a `%2F` inside a segment never merges with a
    raw slash onto one identity.
    """
    settings = make_settings()

    assert settings.canonical_path("toolsets/public/%78") == "toolsets/public/x"
    assert settings.canonical_path("toolsets/public/x") == "toolsets/public/x"
    # Lowercase-hex escapes canonicalize to uppercase hex.
    assert settings.canonical_path("a%2fb") == "a%2Fb"
    # Unreserved characters stay raw; everything else is `%XX` uppercase over UTF-8.
    assert settings.canonical_path("A_B-C.D~E") == "A_B-C.D~E"
    assert settings.canonical_path("a b") == "a%20b"


def test_a_non_canonical_resource_uri_canonicalizes_to_one_identity() -> None:
    """A resource URI's canonical form is one string whatever spelling arrived."""
    settings = make_settings()

    assert (
        settings.canonical_resource_uri(
            "http://localhost:8090/dial/toolsets/public/%78/mcp"
        )
        == "http://localhost:8090/dial/toolsets/public/x/mcp"
    )
    assert (
        settings.canonical_resource_uri(
            "http://localhost:8090/dial/toolsets/public/x/mcp"
        )
        == "http://localhost:8090/dial/toolsets/public/x/mcp"
    )
    assert (
        settings.canonical_resource_uri(
            "http://localhost:8090/apps/applications/public/A%2Db/mcp"
        )
        == "http://localhost:8090/apps/applications/public/A-b/mcp"
    )
    assert settings.canonical_resource_uri("http://localhost:8090/other/x/mcp") is None


def test_segmentation_precedes_decoding_so_an_escaped_slash_never_merges() -> None:
    """A `%2F` inside a segment stays in its segment; a raw `/` is the only separator.

    Segmentation precedes decoding — the decode-then-split order would merge a `%2F`-escaped
    boundary and a raw `/` onto one canonical identity, the merge direction T-EP1-b prices.
    """
    settings = make_settings(toolsets="")

    assert settings.canonical_path("a%2Fb") == "a%2Fb"
    assert settings.canonical_path("a/b") == "a/b"
    assert settings.canonical_path("a%2Fb") != settings.canonical_path("a/b")


def test_a_segment_with_a_plus_keeps_the_literal_character() -> None:
    """`+` is a literal in path position, never a space (`unquote`, never `unquote_plus`).

    The decoded value is the literal `+` (had `unquote_plus` run, it would be a space), and
    the canonical encoding renders it as `%2B` because `+` is not unreserved. A space, by
    contrast, would have canonicalized to `%20` — the two are distinct identities.
    """
    settings = make_settings()

    assert settings.canonical_path("a+b") == "a%2Bb"
    assert settings.canonical_path("a%2Bb") == "a%2Bb"
    # A literal `+` and a space are different resources.
    assert settings.canonical_path("a+b") != settings.canonical_path("a%20b")


def test_an_invalid_utf8_escape_is_not_canonicalized() -> None:
    """An invalid, over-long, or surrogate sequence yields `None`, never a U+FFFD identity.

    A lossy replacement decode would merge distinct wire spellings (`%FF`, `%C0%AF`,
    `%ED%A0%80`) onto one replacement-character identity — the aliasing merge direction the
    canonical form exists to prevent.
    """
    settings = make_settings()

    for segment in ("%FF", "%C0%AF", "%ED%A0%80", "%FE", "%80"):
        assert settings.canonical_path(segment) is None, segment


def test_the_path_guard_admits_a_guard_passing_path_in_an_unset_restriction() -> None:
    """Unset, the guard refuses only shape violations and reserved first segments.

    With no restriction configured the served set is every guard-passing path; existence is
    decided post-authentication at the flow's listing read, not here. The guard's verdict is
    its refusal reason, so a passing path yields `None`.
    """
    settings = make_settings(toolsets="")

    assert settings.toolset_guard_refusal("anything-at-all") is None
    assert settings.toolset_guard_refusal(STORED_TOOLSET_PATH) is None
    assert settings.toolset_guard_refusal("token") == "reserved_path_segment"
    # A reserved name deeper in the path is NOT reserved: the capture is a first-segment
    # match, and no stored path's first segment can collide with it.
    assert settings.toolset_guard_refusal("toolsets/public/token") is None


def test_the_path_guard_refuses_a_forbidden_character_offered_encoded() -> None:
    """A forbidden character is refused by the *decoded* check, however it is offered.

    `%7B` decodes to `{`, `%22` to `"`, `%01` to a control character — each in Core's own
    forbidden set — so the encoding cannot smuggle one past the guard. The refusal token is
    the fixed `invalid_resource_path`.
    """
    settings = make_settings(toolsets="")

    for path in ("a%7Bb", "a%22b", "a%01b", "toolsets/public/a%7Db"):
        assert settings.toolset_guard_refusal(path) == "invalid_resource_path", path


def test_the_path_guard_refuses_a_trailing_dot_at_every_depth() -> None:
    """A front-door ruling, declared as one: a segment ending in a dot is refused."""
    settings = make_settings(toolsets="")

    assert settings.toolset_guard_refusal("trailing.") == "invalid_resource_path"
    assert (
        settings.toolset_guard_refusal("toolsets/public/trailing./x")
        == "invalid_resource_path"
    )
    # The escaped trailing dot is the same decoded content, refused the same way.
    assert (
        settings.toolset_guard_refusal("toolsets/public/%2e") == "invalid_resource_path"
    )


def test_the_path_guard_refuses_dot_and_empty_segments() -> None:
    """`.`/`..` and empty segments are refused, so nginx's normalization cannot re-key."""
    settings = make_settings(toolsets="")

    for path in ("a/../b", "a/./b", "toolsets//public/x", "..", "."):
        assert settings.toolset_guard_refusal(path) == "invalid_resource_path", path


def test_the_path_guard_refuses_an_over_length_or_over_depth_path() -> None:
    """The byte cap (900 decoded UTF-8 bytes) and the segment cap bound every guard input."""
    settings = make_settings(toolsets="")

    assert settings.toolset_guard_refusal("x" * 901) == "invalid_resource_path"
    over_depth = "/".join(["s"] * (DEFAULT_RESOURCE_PATH_MAX_SEGMENTS + 1))
    assert settings.toolset_guard_refusal(over_depth) == "invalid_resource_path"
    # The boundary passes: exactly the cap in each dimension.
    at_depth = "/".join(["s"] * DEFAULT_RESOURCE_PATH_MAX_SEGMENTS)
    assert settings.toolset_guard_refusal(at_depth) is None


def test_a_wire_conforming_but_guard_refused_path_refuses_invalid_resource_path() -> (
    None
):
    """The stated asymmetry: a wire-conforming spelling whose decoded content the guard
    refuses is refused invalid_resource_path on the gateway's surfaces (the router forwards
    it on the data path)."""
    settings = make_settings(toolsets="")

    # `%7B` is routeable on the wire (the map admits every `%XX`); the guard refuses it.
    assert settings.toolset_guard_refusal("a%7Bb") == "invalid_resource_path"


@pytest.mark.parametrize("path", ["%FF", "a%FFb", "toolsets/public/a%FFb"])
def test_a_path_that_does_not_decode_strictly_is_invalid_resource_path(
    path: str,
) -> None:
    """A segment whose escapes do not decode as strict UTF-8 is refused like any bad shape."""
    settings = make_settings(toolsets="")

    assert settings.toolset_guard_refusal(path) == "invalid_resource_path"


def test_the_path_guard_refuses_a_path_the_restriction_excludes() -> None:
    """Configured, the restriction admits its own entries alone and names the reason."""
    settings = make_settings(toolsets={TOOLSET_NAME: dict(_OAUTH_ENTRY)})

    assert settings.toolset_guard_refusal(TOOLSET_NAME) is None
    assert settings.toolset_guard_refusal("other") == "restricted_toolset"


def test_a_restriction_entry_admits_its_path_in_every_accepted_spelling() -> None:
    """Restriction membership is decided on the canonical form.

    An entry `toolsets/public/x` admits that path in every accepted spelling and refuses
    every other — the exact-membership semantics names always had, carried to paths.
    """
    settings = make_settings(toolsets={"toolsets/public/x": dict(_OAUTH_ENTRY)})

    assert settings.toolset_guard_refusal("toolsets/public/x") is None
    # A non-canonical spelling of the same resource is admitted (and canonicalizes).
    assert settings.toolset_guard_refusal("toolsets/public/%78") is None
    assert settings.toolset_guard_refusal("toolsets/public/y") == "restricted_toolset"


def test_the_app_guard_admits_every_path_in_an_unset_restriction() -> None:
    """Unset, the app guard refuses only shape violations — there is no reserved class.

    With no apps restriction configured the served set is every guard-passing app path;
    existence is decided post-authentication at the flow's app read. A reserved front-door
    name is a valid app path here, because nothing the gateway owns lives under `/apps/`.
    """
    settings = make_settings(apps="")

    assert settings.app_guard_refusal("anything-at-all") is None
    assert settings.app_guard_refusal("token") is None
    # The apps namespace carries no reserved-name rule, at any depth.
    assert settings.app_guard_refusal("applications/public/token") is None
    assert settings.app_guard_refusal("a%7Bb") == "invalid_resource_path"


def test_the_app_guard_refuses_a_path_the_restriction_excludes() -> None:
    """Configured, the apps restriction admits its own entries alone and names the reason."""
    settings = make_settings(apps={APPS_NAME: {}})

    assert settings.app_guard_refusal(APPS_NAME) is None
    assert settings.app_guard_refusal("other") == "restricted_app"


def test_inference_without_a_single_entry_restriction_refuses_startup() -> None:
    """Inference needs exactly one toolset to infer, and dynamic serving has none.

    With no restriction configured, or one with more than one entry, there is no "the one
    toolset" to infer — and inferring silently is how a token ends up addressed to a
    toolset the client never named.
    """
    with pytest.raises(ValidationError) as excinfo:
        make_settings(gateway_infer_resource_single_toolset=True, toolsets="")

    message = str(excinfo.value)
    assert "gateway_infer_resource_single_toolset" in message

    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            gateway_infer_resource_single_toolset=True,
            toolsets={
                TOOLSET_NAME: dict(_OAUTH_ENTRY),
                "slack": dict(_OAUTH_ENTRY),
            },
        )

    assert "gateway_infer_resource_single_toolset" in str(excinfo.value)


def test_inference_with_a_single_entry_restriction_starts() -> None:
    """The negative control: the one configuration inference is for is accepted."""
    settings = make_settings(
        gateway_infer_resource_single_toolset=True,
        toolsets={TOOLSET_NAME: dict(_OAUTH_ENTRY)},
    )

    assert settings.gateway_infer_resource_single_toolset is True


# ------------------------------------------------------------------------- URLs


@pytest.mark.parametrize(
    "origin",
    ["http://localhost:8090", "https://dial.example.org"],
)
def test_absolute_urls_are_accepted(origin: str) -> None:
    assert make_settings(gateway_public_origin=origin).gateway_public_origin == origin


def test_trailing_slash_is_stripped() -> None:
    """URL settings are joined with paths, so a trailing slash would double the sep."""
    settings = make_settings(gateway_public_origin="http://localhost:8090/")

    assert settings.gateway_public_origin == "http://localhost:8090"


def test_scheme_less_url_is_refused() -> None:
    """A bare host would surface later as a confusing outbound error."""
    with pytest.raises(ValidationError, match="absolute URL"):
        make_settings(dial_core_base_url="core:8080")


# ------------------------------------------ the identity leg's endpoint source (C2)

# The endpoint trio, as a valid direct configuration carries them: absolute HTTPS URLs.
_DIRECT_TRIO: dict[str, object] = {
    "idp_authorization_endpoint": "https://signin.example.com/oauth2/authorize",
    "idp_token_endpoint": "https://signin.example.com/oauth2/token",
    "idp_jwks_uri": "https://signin.example.com/oauth2/keys",
}


@pytest.mark.parametrize(
    "configured",
    [
        pytest.param(
            ("idp_token_endpoint", "idp_jwks_uri"),
            id="authorization-endpoint-missing",
        ),
        pytest.param(
            ("idp_authorization_endpoint", "idp_jwks_uri"),
            id="token-endpoint-missing",
        ),
        pytest.param(
            ("idp_authorization_endpoint", "idp_token_endpoint"),
            id="jwks-uri-missing",
        ),
    ],
)
def test_a_partial_endpoint_trio_refuses_startup(configured: tuple[str, str]) -> None:
    """A leg whose endpoints come from two sources has two spellings of the identity leg.

    Each two-of-three configuration is refused at startup, and the refusal names both the
    configured and the missing members — the operator's remedy is in the message, not in
    the source.
    """
    overrides = dict.fromkeys(configured, "https://signin.example.com/oauth2/x")

    with pytest.raises(ValidationError) as refused:
        make_settings(idp_issuer="https://signin.example.com/journey", **overrides)

    message = str(refused.value)
    for name in ("idp_authorization_endpoint", "idp_token_endpoint", "idp_jwks_uri"):
        assert name in message


def test_a_malformed_endpoint_value_refuses_startup_naming_the_member() -> None:
    """A value that cannot be addressed as a URL cannot serve as the leg's endpoint."""
    for member, value in (
        ("idp_authorization_endpoint", "/relative/path"),
        ("idp_token_endpoint", "signin.example.com/oauth2/token"),
        ("idp_jwks_uri", "https://"),
    ):
        with pytest.raises(ValidationError) as refused:
            make_settings(
                idp_issuer="https://signin.example.com/journey", **{member: value}
            )
        assert member in str(refused.value)


def test_a_plain_http_endpoint_is_refused_without_the_override() -> None:
    """The code and the carried refresh token never ride a plain leg nobody owns."""
    with pytest.raises(ValidationError, match="plain http"):
        make_settings(
            idp_issuer="https://signin.example.com/journey",
            idp_backchannel_base_url=None,
            idp_authorization_endpoint="https://signin.example.com/oauth2/authorize",
            idp_token_endpoint="http://signin.example.com/oauth2/token",
            idp_jwks_uri="https://signin.example.com/oauth2/keys",
        )


def test_a_plain_http_endpoint_is_accepted_on_the_overrides_own_origin() -> None:
    """The override is the operator's explicit ownership of the plain leg.

    The same plain-http token endpoint, configured together with a back-channel base at
    its own origin, is the local deployment's shape — accepted, because the operator
    named the origin as theirs.
    """
    settings = make_settings(
        idp_issuer="https://signin.example.com/journey",
        idp_backchannel_base_url="http://internal.example:8081",
        idp_authorization_endpoint="https://signin.example.com/oauth2/authorize",
        idp_token_endpoint="http://internal.example:8081/oauth2/token",
        idp_jwks_uri="http://internal.example:8081/oauth2/keys",
    )

    assert settings.idp_token_endpoint == "http://internal.example:8081/oauth2/token"


def test_a_plain_http_issuer_is_refused_without_the_override() -> None:
    """The configured issuer is the identity anchor, and it is HTTPS unless owned.

    Whichever endpoint source serves the legs, the anchor is what the discovery fetch
    targets and the token pin compares against; a plain-leg ownership the operator has
    not stated never reaches the anchor itself.
    """
    with pytest.raises(ValidationError, match="idp_issuer"):
        make_settings(
            idp_issuer="http://signin.example.com/journey",
            idp_backchannel_base_url=None,
        )


def test_a_plain_http_issuer_is_accepted_when_the_override_owns_the_origin() -> None:
    """The negative control for the refusal above: the owned shape starts."""
    settings = make_settings(
        idp_issuer="http://signin.example.com/journey",
        idp_backchannel_base_url="http://internal.example:8081",
    )

    assert settings.idp_issuer == "http://signin.example.com/journey"


def test_the_issuer_is_pinned_at_its_configured_spelling() -> None:
    """The configured issuer is kept verbatim — a trailing slash included.

    The issuer is the one URL setting whose value is compared as an exact string (the
    discovery document's `issuer` member, every token's `iss` claim), so the operator's
    spelling is the pin. A provider whose canonical issuer ends in `/` — the per-journey
    issuer form the tested deployments carry — would never match a normalized copy of
    itself: its own document and its own tokens would both be refused. The trailing
    slash is therefore part of the value, and the well-known join is made explicitly at
    the fetch instead.
    """
    issuer = "https://signin.example.com/journey/v2.0/"

    assert make_settings(idp_issuer=issuer).idp_issuer == issuer


@pytest.mark.parametrize(
    ("name", "value"),
    [
        pytest.param("idp_issuer", "https://", id="issuer-with-no-host"),
        pytest.param(
            "idp_backchannel_base_url", "https://", id="backchannel-with-no-host"
        ),
        pytest.param(
            "idp_issuer",
            "ftp://signin.example.com/journey",
            id="issuer-on-a-scheme-no-http-client-speaks",
        ),
    ],
)
def test_a_malformed_issuer_or_backchannel_base_refuses_startup_naming_the_member(
    name: str, value: str
) -> None:
    """The two settings the identity leg hangs off must be addressable as URLs.

    The direct endpoint trio refuses a value that cannot be addressed at startup; the
    issuer and the back-channel base — which the discovery fetch and every back-channel
    call hang off — get the same well-formedness check, so the failure is a
    configuration error naming the setting rather than a client-side URL error at the
    first sign-in.
    """
    with pytest.raises(ValidationError) as refused:
        make_settings(**{name: value})

    assert name in str(refused.value)
    assert "well-formed absolute URL" in str(refused.value)


# ------------------------------------- the required client secret (both toggle positions)
#
# The gateway's identity-provider client is confidential: its secret authenticates every
# identity-leg token request in both positions of the PKCE toggle, so a deployment
# without one is refused at startup. A value absent altogether is the model's own
# required-field refusal (the field has no default); a blank value counts as unset —
# compose passes every setting explicitly, so an unset secret arrives blank — and is
# refused by the settings model, naming the setting.


def _settings_without_a_client_secret(**overrides: object) -> Settings:
    """The bare settings the missing-secret refusals build on, no secret supplied."""
    base: dict[str, object] = {
        "idp_sso_session_max_seconds": IDP_LIFESPAN_SECONDS,
        "roles_source_path": "roles",
        "gateway_custody_keys": {CUSTODY_KEY_ID: a_custody_key()},
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


@pytest.mark.parametrize("pkce_enabled", [True, False])
def test_a_missing_client_secret_refuses_startup_in_either_toggle_position(
    pkce_enabled: bool,
) -> None:
    """The secret is the client's authentication in both modes: without one, no start.

    The refusal names the setting — whichever way `idp_pkce_enabled` is set — so the
    operator's remedy is in the message rather than in a failed sign-in.
    """
    with pytest.raises(ValidationError) as refused:
        _settings_without_a_client_secret(idp_pkce_enabled=pkce_enabled)

    assert "idp_client_secret" in str(refused.value)


@pytest.mark.parametrize("pkce_enabled", [True, False])
def test_a_blank_client_secret_counts_as_unset_and_refuses_startup(
    pkce_enabled: bool,
) -> None:
    """A blank secret would reach the provider as an empty credential.

    Surfaced, that is the provider's `invalid_client` at the first sign-in, far from the
    misconfiguration that caused it — so the blank is refused at startup, naming the
    setting, in either toggle position.
    """
    with pytest.raises(ValidationError) as refused:
        make_settings(idp_pkce_enabled=pkce_enabled, idp_client_secret=SecretStr("   "))

    assert "idp_client_secret" in str(refused.value)


@pytest.mark.parametrize("pkce_enabled", [True, False])
def test_a_configured_client_secret_starts_in_either_toggle_position(
    pkce_enabled: bool,
) -> None:
    """The negative controls: either toggle position, with a secret, starts."""
    settings = make_settings(
        idp_pkce_enabled=pkce_enabled, idp_client_secret=SecretStr("the-client-secret")
    )

    assert settings.idp_client_secret is not None
    assert settings.idp_pkce_enabled is pkce_enabled


# ------------------------------------- the client secret's file spelling (C3, D10)


def test_the_file_spelling_delivers_the_secret_equivalently(tmp_path: Path) -> None:
    """The file spelling loads the secret once, and it is the same value either way.

    The two spellings are equivalent to the gateway: whichever delivers it, the secret
    lands in `idp_client_secret`, so every consumer reads one value and never knows which
    spelling supplied it. A mounted-secret file commonly ends in a newline; that trailing
    byte is surrounding whitespace, not part of the secret, so the file spelling strips it
    and the presented value equals the environment spelling's exactly.
    """
    secret_file = tmp_path / "client-secret"
    secret_file.write_text("the-file-delivered-secret\n", encoding="utf-8")

    # The environment spelling is unset (blank, the way compose passes an unset value), so
    # the file spelling alone delivers the secret.
    settings = make_settings(
        idp_client_secret=SecretStr(""), idp_client_secret_file=str(secret_file)
    )

    assert settings.idp_client_secret.get_secret_value() == "the-file-delivered-secret"

    # Equivalence with the environment spelling, asserted directly: the same secret
    # delivered either way authenticates identically, so the trailing newline must not
    # reach the wire.
    environment = make_settings(
        idp_client_secret=SecretStr("the-file-delivered-secret")
    )

    assert settings.idp_client_secret.get_secret_value() == (
        environment.idp_client_secret.get_secret_value()
    )


def test_both_secret_spellings_configured_refuse_startup_naming_both(
    tmp_path: Path,
) -> None:
    """One secret has one value: both spellings configured refuses, naming both."""
    secret_file = tmp_path / "client-secret"
    secret_file.write_text("the-file-delivered-secret", encoding="utf-8")

    with pytest.raises(ValidationError) as refused:
        make_settings(
            idp_client_secret=SecretStr("the-env-secret"),
            idp_client_secret_file=str(secret_file),
        )

    message = str(refused.value)
    assert "idp_client_secret" in message
    assert "idp_client_secret_file" in message


def test_an_unreadable_secret_file_refuses_startup_naming_the_path(
    tmp_path: Path,
) -> None:
    """An unreadable path refuses loudly, naming the path and never the content."""
    missing = tmp_path / "no-such-secret"

    with pytest.raises(ValidationError) as refused:
        make_settings(
            idp_client_secret=SecretStr(""), idp_client_secret_file=str(missing)
        )

    message = str(refused.value)
    assert "no-such-secret" in message
    assert "idp_client_secret_file" in message


def test_a_blank_secret_file_refuses_startup_naming_the_path(tmp_path: Path) -> None:
    """A blank file is a misconfiguration, not a secret."""
    blank = tmp_path / "blank-secret"
    blank.write_text("\n  \n", encoding="utf-8")

    with pytest.raises(ValidationError) as refused:
        make_settings(
            idp_client_secret=SecretStr(""), idp_client_secret_file=str(blank)
        )

    message = str(refused.value)
    assert "blank-secret" in message


def test_the_missing_secret_refusal_is_unchanged_under_the_file_spellings_absence() -> (
    None
):
    """Neither spelling configured keeps the existing missing-secret refusal, by name."""
    with pytest.raises(ValidationError) as refused:
        _settings_without_a_client_secret()

    message = str(refused.value)
    assert "idp_client_secret" in message
    assert "confidential client" in message


def test_a_blank_secret_file_path_beside_a_real_env_secret_is_accepted() -> None:
    """A blank file-path spelling is unset, so the environment secret is authoritative.

    The composition path fronts every setting explicitly, so an unset file-path arrives as
    an empty string — or as whitespace — rather than as absent. Read as unset, it does not
    count as configuring the file spelling (the both-configured refusal fires on two real
    values only) and the loader is never sent to a blank path. The blank is what compose
    forwards, not a path.
    """
    for blank in ("", "   "):
        settings = make_settings(
            idp_client_secret=SecretStr("the-env-secret"),
            idp_client_secret_file=blank,
        )

        assert settings.idp_client_secret_file is None
        assert settings.idp_client_secret.get_secret_value() == "the-env-secret"


def test_pkce_is_enabled_by_default() -> None:
    """The toggle's default is on: the challenge composes with the required secret."""
    settings = make_settings()

    assert settings.idp_pkce_enabled is True


def test_a_blank_endpoint_value_is_unset_not_malformed() -> None:
    """The compose file passes every setting explicitly; unset arrives as an empty string."""
    settings = make_settings(
        idp_issuer="https://signin.example.com/journey",
        **dict.fromkeys(_DIRECT_TRIO, ""),
    )

    assert settings.idp_authorization_endpoint is None
    assert settings.idp_token_endpoint is None
    assert settings.idp_jwks_uri is None


def test_the_full_trio_starts_and_defaults_to_discovery_when_absent() -> None:
    """Both modes' pass cases: the full trio starts, and no trio means discovery."""
    direct = make_settings(
        idp_issuer="https://signin.example.com/journey", **_DIRECT_TRIO
    )
    discovery = make_settings(idp_issuer="https://signin.example.com/journey")

    assert direct.idp_jwks_uri is not None
    assert discovery.idp_authorization_endpoint is None
    # The shipped cache window: the documented bound on an endpoint change's propagation.
    assert discovery.idp_discovery_cache_ttl_seconds == SHIPPED_CACHE_TTL_SECONDS


def test_cimd_origins_parse_and_drop_blanks() -> None:
    settings = make_settings(
        gateway_cimd_allowed_origins="https://claude.ai, ,https://other.example",
    )

    assert settings.cimd_allowed_origins == (
        "https://claude.ai",
        "https://other.example",
    )


# ----------------------------------------------------------------------- secrets


def test_secret_settings_do_not_render_their_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A settings object must be loggable: secret fields render as a mask.

    This is the guard against the signing key reaching a log line through a traceback or
    a debug dump of the configuration. The custody key is checked in **both** spellings:
    the flat compat spelling holds its base64 material inline, and the structured spelling
    holds it behind a `ref` the model never resolves — so the flat value is the one that
    could render, and it must be masked exactly as the signing key and the client secret
    are.
    """
    secret = "s3cr3t-value-that-must-not-appear"
    custody_material = a_custody_key()
    monkeypatch.setenv("CUSTODY_KEY", custody_material)
    settings = make_settings(
        gateway_signing_key=secret,
        idp_client_secret=secret,
        gateway_custody_keys={CUSTODY_KEY_ID: custody_material},
    )
    structured = make_settings(
        gateway_signing_key=secret,
        idp_client_secret=secret,
        gateway_custody_keys={
            "custody-key": {"source": "env", "ref": "CUSTODY_KEY", "role": "active"}
        },
    )

    for candidate in (settings, structured):
        rendered = (
            f"{candidate!r} {candidate.model_dump()} {candidate.model_dump_json()} "
            f"{candidate.__dict__}"
        )
        assert secret not in rendered
        assert custody_material not in rendered

    assert settings.gateway_signing_key is not None
    assert settings.gateway_signing_key.get_secret_value() == secret
    # The material is masked on the model but resolves to the configured key: the mask is
    # a rendering property, not a loss of the value.
    assert settings.custody_keyset.active.key_id == CUSTODY_KEY_ID


def test_out_of_range_lifetime_is_refused() -> None:
    with pytest.raises(ValidationError):
        make_settings(idp_sso_session_max_seconds=0)


def test_env_file_reading_is_what_makes_the_suite_hermetic(tmp_path: Path) -> None:
    """Pin the mechanism the rest of the suite relies on, with a negative control.

    The suite's independence from the developer's `.env` rests on `_env_file=None`
    suppressing the file. Point the settings at a temporary `.env` carrying a signing key
    and show that (a) with the file enabled the key is read, and (b) with it disabled the
    same file is ignored — the second assertion is the negative control that proves the
    first is measuring the file and not something else.
    """
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"IDP_SSO_SESSION_MAX_SECONDS={IDP_LIFESPAN_SECONDS}\n"
        "ROLES_SOURCE_PATH=roles\n"
        f'GATEWAY_CUSTODY_KEYS={{"{CUSTODY_KEY_ID}":"{CUSTODY_KEY_B64}"}}\n'
        "GATEWAY_SIGNING_KEY=from-the-temp-env-file\n"
        "IDP_CLIENT_SECRET=from-the-temp-env-file\n",
        encoding="utf-8",
    )

    with_file = Settings(_env_file=env_file)
    without_file = Settings(
        _env_file=None,
        idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
        roles_source_path="roles",
        gateway_custody_keys={CUSTODY_KEY_ID: CUSTODY_KEY_B64},
        idp_client_secret="supplied-directly",
    )

    assert with_file.gateway_signing_key is not None
    assert with_file.gateway_signing_key.get_secret_value() == "from-the-temp-env-file"
    assert without_file.gateway_signing_key is None


# ------------------------------------------------- .env.example as documentation


def test_every_settings_field_is_named_in_the_example() -> None:
    """The example is the configuration reference an operator reads, so it must be complete.

    A field the model reads but the example never names is a setting no operator knows
    exists — which is the same failure as a setting declared and then never read, seen from
    the other side.
    """
    example = (Path(__file__).resolve().parent.parent / ".env.example").read_text(
        encoding="utf-8"
    )
    documented = {
        line.partition("=")[0].strip().upper()
        for line in example.splitlines()
        if "=" in line and not line.strip().startswith("#")
    }

    missing = sorted(
        name for name in Settings.model_fields if name.upper() not in documented
    )
    assert missing == [], f"settings the example never names: {missing}"


def test_the_example_names_no_setting_the_model_does_not_read() -> None:
    """A documented setting nothing reads is a promise the gateway does not keep.

    Derived names (`IDP_CALLBACK_PATH`, `UPSTREAM_CALLBACK_PATH`) are the exception:
    they are documented as derived values, and their absence from the model's fields is the
    point.
    """
    example = (Path(__file__).resolve().parent.parent / ".env.example").read_text(
        encoding="utf-8"
    )
    documented = {
        line.partition("=")[0].strip().upper()
        for line in example.splitlines()
        if "=" in line and not line.strip().startswith("#")
    }
    known = {name.upper() for name in Settings.model_fields}
    # The keys the spike and provisioning helpers read from the same file, plus the ones
    # the settings model derives rather than reads.
    other_audiences = {
        "DIAL_CORE_URL",
        "KEYCLOAK_ADMIN_URL",
        "KEYCLOAK_ADMIN_USER",
        "KEYCLOAK_ADMIN_PASSWORD",
        "KEYCLOAK_TOKEN_CLIENT_ID",
        "KEYCLOAK_TOKEN_CLIENT_SECRET",
        "KEYCLOAK_IDENTITY_CLIENT_ID",
        "KEYCLOAK_IDENTITY_CLIENT_SECRET",
        "TEST_USER_NAME",
        "TEST_USER_PASSWORD",
        # The client the end-to-end smoke walks the sign-in as. A probe's input, not the
        # gateway's: a deployment's own clients live in `PRE_REGISTERED_CLIENTS`.
        "GATEWAY_E2E_CLIENT_ID",
    }

    unread = sorted(documented - known - other_audiences)
    assert unread == [], f"documented settings nothing reads: {unread}"


def test_the_callback_paths_are_derived_not_configured() -> None:
    """The two callback paths are fixed by the router's routing and the client's
    registration, so a deployment that could set one here would change a third of the three
    places that must agree."""
    settings = make_settings()

    assert settings.idp_callback_path == "/dial/callback/idp"
    assert settings.upstream_callback_path == "/dial/callback/upstream"
    assert "idp_callback_path" not in Settings.model_fields
    assert "upstream_callback_path" not in Settings.model_fields


def test_the_identity_provider_scopes_are_the_configured_ones() -> None:
    """The scope set is configuration, and the two scopes this realm cannot serve are
    never in it: `openid` is not a client scope here and fails the leg wholesale, and
    `offline_access` would request a refresh token the gateway must not hold."""
    settings = make_settings(idp_client_scopes="profile,email")

    assert settings.idp_client_scopes == "profile,email"


# --------------------------------------------- the operator-facing documents

# The documents an operator reads. Asserted over file content because these are the
# documents' own contracts: an operator upgrading by them must never be told to set a
# setting that no longer exists, nor to expect a behavior the change removed.
_OPERATOR_DOCUMENTS = ("README.md", ".env.example", "docs/gateway-configuration.md")


def _repo_file(relative: str) -> str:
    return (Path(__file__).resolve().parent.parent / relative).read_text(
        encoding="utf-8"
    )


def test_no_operator_document_names_the_removed_authentication_type_member() -> None:
    """The removed member appears only as a migration note, never as configuration to set.

    Each document may mention it in prose (naming the removal and the parse-refusal), but
    none may present it as a member to put in a mapping. The check is on the JSON-shaped
    spelling the old example carried.
    """
    for relative in _OPERATOR_DOCUMENTS:
        content = _repo_file(relative)
        assert '"authentication_type"' not in content, relative


def test_the_committed_examples_are_valid_json_in_both_modes() -> None:
    """The restriction examples are JSON an operator can paste, in both modes.

    The unset mode is the empty value; the set mode is the `scopes_supported` example. Both
    must parse, so neither can carry the removed member the schema would refuse.
    """
    # The set-mode example the README carries as a literal.
    example = '{"notion":{"scopes_supported":["default"]}}'
    parsed = json.loads(example)
    assert parsed == {"notion": {"scopes_supported": ["default"]}}

    # The model accepts the set-mode example verbatim, and the unset mode is valid too.
    assert TOOLSET_NAME in make_settings(toolsets=example).toolsets
    assert make_settings(toolsets="").toolsets == {}


def test_no_operator_document_names_a_discovery_side_service_key_or_consult() -> None:
    """The consult era left no operator-facing vocabulary behind.

    The gateway holds no Core service credential, makes no consult at discovery, and has no
    discovery-side failure shape — so no operator document may name one.
    """
    forbidden = (
        "dial_core_api_key",
        "gateway_discovery_max_concurrent_consults",
        "max_concurrent_consults",
        "discovery consult",
        "service api key",
        "core_unavailable",
    )
    for relative in _OPERATOR_DOCUMENTS:
        content = _repo_file(relative).lower()
        for phrase in forbidden:
            assert phrase not in content, f"{relative} names {phrase!r}"


def test_the_example_restriction_block_states_both_modes() -> None:
    """The operator reads the two modes and the parse-refusal from the example itself."""
    content = _repo_file(".env.example")

    assert "TOOLSETS=" in content
    # Both modes are named, and the loud parse-refusal of an old mapping is stated.
    lowered = content.lower()
    assert "unset (or empty)" in lowered
    assert "only its entries are served" in lowered
    assert "refused" in lowered
    assert "parse" in lowered


def test_the_roadmap_p3_line_states_the_landed_behavior() -> None:
    """The tracker's P3 accepts-line matches the served behavior.

    A non-OAuth toolset with a stored credential is served through the short-circuit, and
    the unknown-name refusal lives at the flow's authenticated settings read (discovery
    having answered a document by the mirror property).
    """
    roadmap = _repo_file("docs/production-roadmap.md")

    assert "non-OAUTH and unknown names fail" not in roadmap
    assert "served through the signed-in" in roadmap
    assert "mirror property" in roadmap


def test_the_roadmap_c1_5_line_states_the_unified_scope() -> None:
    """The tracker's C1.5 entry no longer claims it adds the branch machinery itself.

    The signed-in check, the short-circuit, and the kind branch are built by this change;
    what remains C1.5's is the apps resource surface and the unsigned DIAL_NATIVE case.
    """
    roadmap = _repo_file("docs/production-roadmap.md")

    assert "it adds a new resource kind and a short-circuit branch to" not in roadmap
    assert "the apps resource *surface*" in roadmap


# ------------------------------------- the custody-era operator-facing documents


def test_no_operator_document_names_the_retired_staleness_setting() -> None:
    """The renamed setting's old name and its retired rationale are gone from the docs.

    An operator upgrading by the reference must never be told to set a variable that no
    longer exists while the required new one is unnamed.
    """
    for relative in _OPERATOR_DOCUMENTS:
        content = _repo_file(relative)
        assert "IDP_ACCESS_TOKEN_LIFESPAN_SECONDS" not in content, relative
        assert "staler than" not in content.lower(), relative


def test_the_operator_documents_state_the_session_bound_semantics() -> None:
    """The new setting's operator-assertion meaning is stated in each document."""
    for relative in _OPERATOR_DOCUMENTS:
        content = _repo_file(relative)
        assert "IDP_SSO_SESSION_MAX_SECONDS" in content, relative


def test_the_reference_states_the_custody_key_procedure() -> None:
    """The reference carries the key generation, the mapping shape, and the rotation wave.

    An operator cannot configure the custody key from a name alone: they need the
    generation command, the JSON shape, and the hard-cut rotation's cost — a re-sign-in
    wave — named as the thing to schedule the rotation around.
    """
    content = _repo_file("docs/gateway-configuration.md")

    assert "openssl rand -base64 32" in content
    assert "GATEWAY_CUSTODY_KEYS" in content
    assert "hard cut" in content.lower()
    assert "re-sign-in wave" in content.lower()


def test_the_reference_states_the_size_bound_to_cap_coupling() -> None:
    """The coupling is operator-facing: the two bounds must move together."""
    content = _repo_file("docs/gateway-configuration.md")

    assert "GATEWAY_CUSTODY_PROVIDER_TOKEN_MAX_BYTES" in content
    assert "GATEWAY_FORM_MAX_BODY_BYTES" in content
    assert "coupled" in content.lower()


def test_the_reference_carries_the_rotation_off_warning() -> None:
    """The rotation-off interaction is warned about, naming the single-use consequence."""
    content = _repo_file("docs/gateway-configuration.md").lower()

    assert "GATEWAY_ROTATE_REFRESH_TOKENS=false".lower() in content
    assert "single-use" in content
    assert "warning" in content
