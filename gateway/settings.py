"""Gateway configuration.

Every setting is an environment variable, read from the process environment and from
`.env` (gitignored; committed `.env.example` carries the placeholders). No default here
is a credential: the two settings this repository treats as secret material — the token
signing key and the identity-provider client's own credentials — are typed as
`SecretStr`, so a settings object can never be logged, serialized, or repr'd into a
traceback with the value attached.

Structured configuration — the toolset restriction and the pre-registered client list —
is carried as a JSON document in a single environment variable rather than as a file. The
configuration a deployment edits for this service is the same `.env` it already edits
for every other setting, so there is one place to look and one way to pass a value in
(as a container environment entry); a file would add a mount and an ownership question
for no gain.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, cast
from urllib.parse import quote, unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from gateway.custody import (
    KEY_ID_MAX_BYTES,
    CustodyError,
    CustodyKey,
    CustodyKeyset,
    custody_key_id_is_valid,
    decode_custody_key,
    envelope_bytes_for_token,
)
from gateway.keysets import (
    CUSTODY_KMS_REFUSAL,
    ROLE_ACTIVE,
    SIGNING_KMS_REFUSAL,
    SOURCE_ENV,
    KeysetEntry,
    resolve_material,
    validate_entries,
)
from gateway.redirect_uris import ADMISSION_RULE, scheme_admission_refusal

# The violation a URL-shaped setting reports when it carries no scheme.
_SCHEME_ERROR = "must be an absolute URL including a scheme"


def _origin_of(url: str) -> tuple[str, str]:
    """A URL's origin as its scheme and host, lowercased for the comparison."""
    parts = urlsplit(url)
    return (parts.scheme.lower(), parts.netloc.lower())


def _read_secret_file(path: str) -> str:
    """The content of a secret file, read once, or an `OSError` the caller names the path for.

    Kept as a thin one-line function so a test can steer the read (a file that is readable
    in tests but not in the container is exactly the boundary this refusal exists for) —
    the caller wraps whatever it raises into a refusal naming the path and never the content.
    """
    return Path(path).read_text(encoding="utf-8")


def _flat_custody_material(value: object) -> str:
    """A flat custody entry's key material as the plain string to decode.

    The flat spelling's value is held as a `SecretStr` on the settings model — so the
    material is masked in every repr, dump, and serialization — and resolved to its plain
    value here, at the one seam where the material is turned into bytes. A bare string is
    passed through unchanged: the coercion wraps strings, so this is the fail-open path for
    a value that reached an entry without passing through it, and `resolve_material`'s
    blank check is what refuses a value that is not material at all.
    """
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    return str(value)


# The direct endpoint trio's field names, in the order the all-or-nothing refusal lists
# them. Held as a constant so the refusal that names members and the loop that validates
# them cannot drift apart.
_DIRECT_ENDPOINT_SETTINGS = (
    "idp_authorization_endpoint",
    "idp_token_endpoint",
    "idp_jwks_uri",
)

# The bytes a refresh request spends on everything that is not the custody envelope: the
# gateway refresh token's own signed header and signature, its session-binding claims, and
# the form's other parameters. It exists so the size-bound/cap coupling check below compares
# against a *stated* allowance rather than a bare envelope figure that ignores the token the
# envelope rides inside.
_REFRESH_BODY_OVERHEAD_BYTES = 800

# The front door's resource path is one or more path segments whose decoded form is Core's
# deployment id, so the gateway's guard operates on the **decoded** path, per segment. The
# characters below are Core's own forbidden set for resource names (`{`, `}`, `"`, and any
# control character ≤ U+001F) — and precisely the characters that would break the 401
# challenge header's quoting or the HTML pages' escaping. A decoded `/` is deliberately
# absent: it is reachable inside a segment only as `%2F`, which the router forwards
# byte-faithfully for Core to answer exactly as it answers on its own port (Core's
# resolution refuses a decoded `/` inside a filename — same-answer behavior, not a cut).
_FORBIDDEN_CHARACTERS = frozenset('{}"')
_FORBIDDEN_MAX_CODEPOINT = 0x1F

# The whole decoded resource path MUST NOT exceed this many UTF-8 bytes — the value of
# Core's own path-size bound (`MAX_PATH_SIZE`), adopted deliberately. Core's bound applies
# to the resource's absolute storage path (bucket location plus relative path), not the
# resource URL, so capping the decoded resource path — longer by its type segment — with
# the same number is deliberately stricter at the 890-900-byte edge: an acknowledged edge
# cut, chosen so the front door never advertises a path Core must refuse for length.
RESOURCE_PATH_MAX_BYTES = 900

# The default segment-count cap — the gateway's own stated anti-abuse bound (no Core depth
# limit exists, so the front door states one rather than inheriting none). It joins the
# abuse-bounds family and is a setting (`RESOURCE_PATH_MAX_SEGMENTS`).
DEFAULT_RESOURCE_PATH_MAX_SEGMENTS = 32

# Names whose MCP path the front router's authorization-surface location captures at the
# first segment, before any data-path location can. The reserved-name rule therefore applies
# to the FIRST segment only, and in the `/dial/` namespace only: a stored resource's first
# segment is its type segment (`toolsets`, `applications`), never a reserved name, so a
# reserved name appearing deeper (`toolsets/public/token`) is a legal, routable path. The
# list mirrors the router's alternation verbatim, so the guard and the routing stay in step.
RESERVED_TOOLSET_NAMES: tuple[str, ...] = (
    "authorize",
    "token",
    "register",
    "revoke",
    "callback",
    "consent",
    "jwks.json",
)

# The request-time path guard's refusal reasons, as the audit trail's fixed vocabulary. One
# token per refusal class: every decoded path-shape refusal — a forbidden character, a
# trailing dot, a dot or empty segment, an over-length or over-depth path — lands on
# `invalid_resource_path` (the spec says a trailing dot fails with the same reason class as a
# forbidden character), a reserved first segment on `reserved_path_segment`, and the
# restriction exclusion on the toolset/app tokens the name guard already used, retained so
# the trail still names the namespace a restriction refused in.
INVALID_RESOURCE_PATH = "invalid_resource_path"
RESERVED_PATH_SEGMENT = "reserved_path_segment"
RESTRICTED_TOOLSET = "restricted_toolset"
RESTRICTED_APP = "restricted_app"

# The operator-facing phrasing of each guard refusal class, for the startup refusals that
# name the rule a configured entry broke. Keyed by the fixed-vocabulary token so the two
# cannot drift.
_RULE_PHRASES: dict[str, str] = {
    INVALID_RESOURCE_PATH: (
        'a segment outside the decoded rules (a forbidden character `{`, `}`, `"`, or a '
        "control; a trailing dot; a `.`/`..` or empty segment; or an over-length or "
        "over-depth path)"
    ),
    RESERVED_PATH_SEGMENT: (
        "a reserved first segment (the front router's authorization-surface location "
        "captures /dial/<segment>/... before the data path)"
    ),
}

# The characters a canonical segment leaves raw: the RFC 3986 unreserved set. Everything
# else is `%XX` uppercase hex over UTF-8, so the canonical spelling is one string per
# resource whatever spelling arrived. `%` is deliberately not in the set (it never is in
# unreserved), so no canonical segment carries a bare `%`.
_CANONICAL_SAFE = "-._~"


def _segment_shape_refusal(segment: str) -> str | None:
    """The reason a **decoded** segment fails the per-segment shape rule, or `None` on a pass.

    A segment is admitted when it is non-empty, is not `.` or `..`, carries no forbidden
    character (`{`, `}`, `"`, or any control ≤ U+001F — Core's own resource-name set), and
    does not end in a dot (a front-door ruling mirroring Core's creation-side constraint,
    deliberately stricter than its resolution). The returned token is the fixed-vocabulary
    `invalid_resource_path`; the caller maps it to the path guard's one shape reason.
    """
    if not segment or segment in (".", ".."):
        return INVALID_RESOURCE_PATH
    if segment.endswith("."):
        return INVALID_RESOURCE_PATH
    for character in segment:
        if (
            character in _FORBIDDEN_CHARACTERS
            or ord(character) <= _FORBIDDEN_MAX_CODEPOINT
        ):
            return INVALID_RESOURCE_PATH
    return None


def _strict_unquote(segment: str) -> str | None:
    """A percent-encoded segment decoded as **strict** UTF-8, or `None` when it is not.

    The decode is strict on two axes. Percent-escapes are decoded with `unquote` (never
    `unquote_plus`), so a `+` stays the literal character it is in path position and never
    becomes a space. The decoded bytes are then read as UTF-8 with `errors="strict"`, so an
    invalid, over-long, or CESU-8-style surrogate sequence (e.g. `%FF`, `%C0%AF`, `%ED%A0%80`)
    yields `None` rather than a lossy U+FFFD replacement — a replacement decode would merge
    distinct wire spellings onto one identity, which is exactly the aliasing merge direction
    the canonical form exists to prevent.
    """
    try:
        return unquote(segment, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _decoded_segments(path: str) -> list[str] | None:
    """An offered path's segments, each strictly decoded, or `None` on a strict-decode miss.

    Segmentation precedes decoding: the path is split on raw `/` first, and each segment is
    then decoded independently — so a `%2F` inside a segment decodes to a `/` within that one
    segment and never becomes a separator (the merge direction T-EP1-b prices), and a raw `/`
    is the only thing that separates two identities. A segment whose escapes do not decode
    strictly (an invalid, over-long, or surrogate UTF-8 sequence) makes the whole path
    `None`, the caller's signal to refuse it with the guard's fixed reason.
    """
    segments: list[str] = []
    for segment in path.split("/"):
        decoded = _strict_unquote(segment)
        if decoded is None:
            return None
        segments.append(decoded)
    return segments


# The two callback paths the flow owns, and the reason they are constants rather than
# settings: the front router's authorization-surface location routes them by name, and the
# gateway's identity-provider client is registered against one of them. A deployment that
# could change them here would change only one of those three places, and the failure
# would be a sign-in that never returns.
IDP_CALLBACK_PATH = "/dial/callback/idp"
UPSTREAM_CALLBACK_PATH = "/dial/callback/upstream"

# The value the committed `.env.example` carries for the signing key. It reaches the
# settings model as a real string, so it is refused by name: a deployment that never
# replaced it would otherwise sign tokens with a key published in this repository.
_PLACEHOLDER_SIGNING_KEY = "generate-me"

# The bytes a registration body spends on everything that is not one of the bounded values:
# the JSON scaffolding (braces, the member names RFC 7591 specifies, quotes, commas) and
# the small fields a registration may carry that this gateway does not itself bound. It
# exists so the joint-reachability check below compares against a *stated* allowance rather
# than against a bare sum of the bounded fields, which would be a claim the JSON cannot
# actually satisfy.
_REGISTRATION_SCAFFOLDING_BYTES = 512


class ToolsetMapping(BaseModel):
    """One toolset the gateway serves, as an operator restriction entry.

    The toolset's resource URI is derived from the name and the public origin rather
    than configured, because it is the same string the front router routes and the
    protected-resource document advertises; a second spelling could disagree with both.

    An entry declares no authentication kind. The kind a flow acts on is Core's, read per
    flow from its public settings projection, so an operator-declared kind would be a
    second and staler source of that same fact.
    """

    model_config = ConfigDict(extra="forbid")

    # The upstream authorization server's scopes, as Core publishes them for this
    # toolset. They belong to the upstream leg — the gateway enforces no scopes of its
    # own — and the protected-resource document echoes them verbatim where the toolset is
    # pinned in the restriction.
    scopes_supported: list[str] = Field(default_factory=list)


class AppMapping(BaseModel):
    """One app the gateway serves, as an operator restriction entry.

    The app's resource URI is derived from the name and the public origin rather than
    configured, because it is the same string the front router routes and the
    protected-resource document advertises; a second spelling could disagree with both.

    An entry declares nothing but the name. An app carries no authentication kind — it is
    credential-free by construction, so there is no kind to declare — and no scopes, because
    no leg ever sends scopes for an app resource: the apps protected-resource document's
    `scopes_supported` is empty whether or not the app is pinned here, so an entry-level
    scopes member would be a field nothing reads. The model forbids every other member, so
    an entry carrying one is refused loudly at parse rather than silently ignored.
    """

    model_config = ConfigDict(extra="forbid")


class PreRegisteredClient(BaseModel):
    """A client id an operator has registered out of band.

    Pre-registration is the resolution path with no fetch and no registration call: the
    operator is the source of truth for the redirect URIs, and the client is resolved by
    id lookup alone.
    """

    model_config = ConfigDict(extra="forbid")

    redirect_uris: list[str] = Field(default_factory=list)
    client_name: str | None = None


class KeysetEntryModel(BaseModel):
    """One structured keyset entry: where its material comes from, and its role.

    `ref` names the environment variable (`source: env`) or the file path (`source: file`)
    the entry's material is read from — the keyset document carries structure, never secret
    material. `source` and `role` are validated against the shared vocabulary by the keyset
    validators; an entry carrying the reserved `kms` source refuses startup there, naming
    the gap. The model forbids unknown members, so a misspelled field is refused at parse
    rather than silently ignored.
    """

    model_config = ConfigDict(extra="forbid")

    source: str
    ref: str
    role: str


class Settings(BaseSettings):
    """Resolved gateway configuration.

    Field names map to upper-case environment variables (`gateway_internal_port` ->
    `GATEWAY_INTERNAL_PORT`). Settings that only shape the container layout are read
    here so the same `.env` serves both the app and `docker compose`.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # The same `.env` is read by `docker compose` and by the spike helpers, so it
        # carries keys this model does not consume; an unknown key is not an error.
        extra="ignore",
        case_sensitive=False,
        # A validation error's report carries a repr of the input it was validating. For
        # this model that repr is the whole settings mapping, and it ends with the signing
        # key's own PEM boundary — the value is masked to a short prefix and suffix by
        # `SecretStr`, but the suffix is key material's tail and the surrounding mapping is
        # every deployment value. Refusals below name the setting they refused, so the
        # input repr adds nothing an operator needs.
        hide_input_in_errors=True,
    )

    # -- Topology -------------------------------------------------------------

    # The gateway's public origin: the issuer of every token it mints and the base URL
    # of every discovery document. Fixed by the front router's published port.
    gateway_public_origin: str = "http://localhost:8090"

    # The container-internal port uvicorn binds. Never published to the host — the front
    # router is the gateway's only front door.
    gateway_internal_port: int = Field(default=8091, gt=0, le=65535)

    # The compose network joining the gateway and router to the DIAL instance. Read for
    # the same reason every other container-shaping value is read here.
    dial_compose_network: str = "dial-instance_default"

    # -- DIAL Core ------------------------------------------------------------

    # Core's in-network base URL. Reached by the gateway, never by a harness.
    dial_core_base_url: str = "http://core:8080"

    # The claim path roles are read from in the identity token, and re-emitted from as a
    # plain array under `roles`. Required, with no default: a silent default is exactly
    # the trap — a wrong path yields a role-less token that Core rejects as a 403 with
    # nothing in the logs to say why.
    roles_source_path: str = Field(min_length=1)

    # The claim name the roles array is re-emitted under, and the name Core's gateway
    # provider entry reads it from. Configured rather than fixed because it is the other
    # half of the same deployment fact as the source path: a deployment whose provider
    # entry reads roles elsewhere gets a token whose roles are never matched, silently.
    roles_claim_name: str = Field(default="roles", min_length=1)

    # -- Identity provider ----------------------------------------------------

    # The browser-facing issuer, pinned exactly: a token's `iss` must equal this value
    # whichever port the token endpoint was reached on, so issuer matching is unaffected
    # by the back channel. The placeholder default names the RFC 2606 reserved domain —
    # it is no provider's address, so a deployment that forgets the setting fails loudly
    # at the identity leg rather than silently pointing at a live-looking host.
    idp_issuer: str = Field(default="https://idp.example.com/", validate_default=True)

    # The back channel's base URL: an optional origin override. When set, the gateway's
    # server-to-server calls to the provider are addressed to this base with the
    # provider's own path kept — scheme and host swapped, nothing else — while the
    # browser-facing redirect and issuer matching stay pinned to the configured issuer.
    # It exists for the deployment whose provider's browser-facing origin is impractical
    # for server-to-server traffic (a self-signed certificate, or an internal plain-http
    # port); a single-origin provider leaves it unset, and the calls go to the issuer's
    # own origin.
    idp_backchannel_base_url: str | None = None

    # How long a fetched discovery document is reused before the next identity leg
    # fetches it again, in seconds. The cache is per process, so a cold start or an
    # expired entry costs at most one fetch per window — and this TTL is the documented
    # bound on how long a provider's endpoint change goes unnoticed. There is no fetch at
    # startup: the container's boot must not depend on the provider's availability.
    idp_discovery_cache_ttl_seconds: int = Field(default=300, gt=0)

    # The optional direct endpoint trio — the discovery document's three members,
    # configured by the operator instead of fetched from the provider: the authorization
    # endpoint (browser-facing), the token endpoint, and the key-set URI. ALL THREE or
    # NONE: a partial set gives the identity leg two endpoint sources whose disagreement
    # is undetectable, so it refuses to start naming the configured and the missing
    # members. Where all three are set, no discovery fetch is attempted at all.
    # Each must be a well-formed absolute URL, and HTTPS unless it shares the
    # back-channel base's origin — the override is the operator's explicit ownership of a
    # plain leg, never a default. A configured endpoint is operator input at the issuer
    # setting's own trust level, so it is deliberately NOT origin-bound to the issuer: a
    # provider whose token endpoint lives on a separate host from its issuer is exactly
    # the shape this mode exists to absorb. The mode's trade: a provider's endpoint
    # change propagates within the discovery TTL in discovery mode and not at all here —
    # a moved endpoint fails the leg closed, and keeping the endpoints current is the
    # operator's responsibility.
    idp_authorization_endpoint: str | None = None
    idp_token_endpoint: str | None = None
    idp_jwks_uri: str | None = None

    # Whether the identity leg's authorization redirect carries a PKCE challenge on top
    # of the client's authentication. On by default: the challenge binding is what makes
    # an intercepted identity-leg code unexchangable by an interceptor that reads it off
    # the callback URL, and it composes with the client secret rather than replacing it.
    # Turning it off is the challenge-off mode for a provider that cannot support PKCE:
    # the redirect carries no challenge, and the token requests authenticate with the
    # client secret alone — which every mode requires (`_require_client_secret`). The
    # toggle governs the challenge only: the gateway's own client-facing AS surface keeps
    # requiring PKCE from harness clients whichever way this is set.
    idp_pkce_enabled: bool = True

    # The gateway's own pre-registered identity-provider client — a confidential client
    # whose secret (idp_client_secret) authenticates every identity-leg token request.
    idp_client_id: str = "dial-mcp-proxy"

    # The client's own default scopes, and the only scopes the identity-provider redirect
    # ever requests. They live here rather than in any client-supplied parameter: a scope
    # the gateway's client does not carry — or that is not a client scope at the provider
    # at all — fails the whole authorization leg.
    idp_client_scopes: str = "profile,email"

    # How long an outbound call to Core or to the identity provider may take. Generous
    # because Core's credential call reaches the upstream authorization server before it
    # answers, and a short timeout there would surface as a failed sign-in.
    gateway_outbound_timeout_seconds: float = Field(default=30.0, gt=0)

    # -- Token lifetimes and flow shape --------------------------------------

    gateway_access_token_ttl_seconds: int = Field(default=600, gt=0, le=3600)
    gateway_code_ttl_seconds: int = Field(default=300, gt=0, le=900)
    gateway_flow_ttl_seconds: int = Field(default=600, gt=0, le=3600)

    # The refresh window: the absolute bound on how long a gateway refresh token lives, and
    # therefore on how long any carried custody blob lives. It MUST NOT exceed the
    # operator-declared identity-provider session bound below, because the carried session
    # refresh token has to remain usable at every refresh in the window. Startup refuses to
    # run when it does.
    gateway_refresh_ttl_seconds: int = Field(default=28800, gt=0)

    # The operator's declared bound, in seconds, on how long the identity provider keeps its
    # session-bound refresh token usable. Required, with no default: the gateway cannot
    # learn it, and a guessed bound would make the startup check meaningless. Each provider
    # class publishes the fact under its own name — a sign-in-session lifetime setting, or
    # the refresh-token window the provider gives a client of this registration shape (the
    # confidential client the gateway registers as) — so the operator reads it off
    # the provider's own session policy. The check is an
    # **assertion about provider session policy**, not provider truth: it is arithmetic over
    # two operator settings, and its failure to catch a session policy shorter than declared
    # surfaces at runtime as the `idp_session_ended` refusal burst. Where the provider's
    # policy is short, the short refresh window is the correct configuration, not a degraded
    # one.
    idp_sso_session_max_seconds: int = Field(gt=0)

    # Rotation is on by default. The replacement refresh token keeps the original
    # absolute expiry (non-sliding), so rotation cannot extend the window; the grace
    # window only lets an in-flight request that raced the rotation still use the token it
    # holds. Turning rotation off is valid only on a provider that does not rotate its own
    # refresh token per grant: where it does, the carried credential is effectively
    # single-use — the first refresh consumes the provider's token and every refresh after
    # the first fails at the provider — so the setting is warned about in the operator
    # reference rather than refused here, because the provider's rotation policy is not
    # something this process can know at startup.
    gateway_rotate_refresh_tokens: bool = True
    gateway_rotation_grace_seconds: int = Field(default=60, ge=0, le=600)

    # One flat authorization server serves every toolset, so the RFC 8707 `resource`
    # parameter is required on authorization and token requests — there is no other signal
    # saying which toolset a request is for, and both endpoints reject a missing or
    # mismatched one as `invalid_target`. The escape hatch exists for a deployment that
    # can never serve more than one toolset; it is off by default because inferring the
    # resource silently is how a token ends up addressed to the wrong one.
    gateway_infer_resource_single_toolset: bool = False

    # -- Client registration --------------------------------------------------

    # The audience marker Core's provider entry verifies, so a token minted for another
    # purpose is not valid deployment-wide.
    gateway_audience_marker: str = "dial-mcp-proxy"

    # The toolset restriction: a JSON object keyed by the client-facing toolset name, or
    # empty. Unset, the gateway serves every toolset whose name passes the request-time
    # guard — existence is decided post-authentication, at the flow's listing read, the
    # way Core's own discovery tier decides nothing below authentication. Set, only its
    # entries are served, and each configured entry is validated at startup (see
    # `_validate_mapping`) so one that could never be routed fails the container's start
    # instead of serving a toolset no harness can reach.
    #
    # `NoDecode` keeps pydantic-settings from JSON-decoding these itself: its decoder
    # runs before any validator, and its failure is a raw parse error naming neither the
    # setting nor the document. The parsing happens in `_parse_json_document` instead, so
    # a malformed value is refused with a message that says which setting it was.
    toolsets: Annotated[dict[str, ToolsetMapping], NoDecode] = Field(
        default_factory=dict
    )

    # The apps restriction: the apps namespace's own optional operator restriction, a JSON
    # object keyed by the client-facing app name, or empty. It is a separate setting from
    # the toolset restriction because the two registries are disjoint namespaces in Core —
    # a name can exist as both a toolset and an app, and one shared restriction would admit
    # or deny both together, an operator decision the deployment never asked for.
    #
    # Unset, the gateway serves every app whose name passes the request-time app guard —
    # existence is decided post-authentication, at the flow's app read, the mirror property
    # extended to the second namespace. Set, only its entries are served, and each
    # configured entry is validated at startup (see `_validate_mapping`) for the one routing
    # refusal that applies here — a name outside the routed charset — so a name the router's
    # apps location could never route fails the container's start rather than serving an app
    # no harness can reach. An app name has no reserved-name refusal: nothing the gateway
    # owns is served under the apps namespace's name segment.
    apps: Annotated[dict[str, AppMapping], NoDecode] = Field(default_factory=dict)

    # Clients an operator registered out of band, as a JSON object keyed by client id.
    # The first rung of the resolution order, and the only one whose source of truth is
    # the operator rather than a document the client serves.
    pre_registered_clients: Annotated[dict[str, PreRegisteredClient], NoDecode] = Field(
        default_factory=dict
    )

    # Comma-separated origins allowed to name a client-metadata document. Defaults to
    # the flagship harness's metadata origin.
    gateway_cimd_allowed_origins: str = "https://claude.ai"

    # The `User-Agent` the client-metadata document fetch carries. The origin is
    # fronted by bot protection that rejects library-default agents outright, which
    # would surface as a late, misleading registration failure rather than as a
    # configuration one.
    gateway_cimd_user_agent: str = "dial-mcp-gateway/0.1 (+mcp-signin)"

    # The client-metadata fetch's bounds: connect and total timeouts, the response-size
    # cap, and the cache's TTL and bound. Each is a separate ceiling because they fail
    # in different ways — a slow origin, a huge body, and an unbounded cache are
    # different problems with different remedies.
    gateway_cimd_connect_timeout_seconds: float = Field(default=5.0, gt=0)
    gateway_cimd_total_timeout_seconds: float = Field(default=10.0, gt=0)
    gateway_cimd_max_document_bytes: int = Field(default=65_536, gt=0)
    gateway_cimd_cache_ttl_seconds: int = Field(default=300, gt=0)
    gateway_cimd_cache_max_entries: int = Field(default=256, gt=0)

    # -- Abuse bounds ---------------------------------------------------------

    gateway_flows_max_live: int = Field(default=10_000, gt=0)
    gateway_rate_per_source_per_minute: int = Field(default=30, gt=0)
    gateway_rate_global_per_minute: int = Field(default=600, gt=0)

    # The segment-count cap on a resource path the guard resolves. The front door's
    # addressing vocabulary is the resource path (one or more segments), where the
    # one-segment name vocabulary bounded depth by construction; this restores the bound.
    # No Core depth limit exists, so the front door states one rather than inheriting none.
    # It joins the byte cap (Core's own 900-byte path bound, applied to the decoded path)
    # as the second dimension a caller could otherwise grow without limit.
    resource_path_max_segments: int = Field(
        default=DEFAULT_RESOURCE_PATH_MAX_SEGMENTS, gt=0
    )

    # The hard cap on live approved-client entries, with oldest-first eviction — the flow
    # cap's own discipline applied to the consent/attribution registry. The only write path
    # is a user's approve click on a live, identity-completed flow, so growth is bounded
    # upstream by the rate limits, the flow cap, and the flow TTL; this cap bounds the
    # registry's memory absolutely against the slowest legitimate growth there is (real
    # users approving real clients). Eviction drops the oldest approvals first, and a
    # dropped approval re-prompts the decision page rather than skipping it — the loss
    # direction is fail-safe by construction.
    gateway_approved_clients_max: int = Field(default=10_000, gt=0)

    # The byte cap on a form body at `/dial/token` and `/dial/revoke`, applied while the
    # body is read. The two endpoints are unauthenticated and take a body, so a request
    # that is merely large must cost the gateway a bounded amount of memory rather than
    # however much its sender chose; this is the same discipline `DCR_MAX_BODY_BYTES`
    # applies at `/dial/register`, with one cap for both form endpoints because they take
    # the same shape of request.
    #
    # 16384, not the 8192 that served a snapshot-only refresh token: a refresh request
    # carries the gateway's own refresh token in its form body, and that token now carries
    # the encrypted custody claim. The shared cap means `/dial/revoke`'s read bound rises
    # with it — stated in `.env.example` and in the operator reference, not slipped in. The
    # cap and `gateway_custody_provider_token_max_bytes` are coupled and must move together:
    # a provider-token bound raised past the cap's headroom would make sign-ins succeed while
    # every refresh fails over-cap, hours later and far from its cause. The startup check
    # `_require_custody_bounds_to_fit_the_body_cap` enforces the relationship.
    gateway_form_max_body_bytes: int = Field(default=16384, gt=0)

    # How many CIMD fetches may run on the shared worker pool at once. The fetch's target
    # is caller-chosen, so without this an unauthenticated caller could hold the pool with
    # slow fetches they steer and starve the identity and credential legs; with it, an
    # attacker's share of the pool is bounded and the flow's own legs keep capacity. What
    # remains is queue waiting, which the public-endpoint rate limits bound.
    gateway_cimd_max_concurrent_fetches: int = Field(default=8, gt=0)

    # -- Audit bounds ---------------------------------------------------------

    # The longest a caller-supplied fact may be in an audit record, measured in characters
    # and applied at the point a record is emitted. The facts a refusal records are the
    # request's own values (client id, redirect URI, resource, resource name) and they are
    # recorded so an operator can diagnose a refusal from the log — but a value's length
    # is the caller's choice, and a record whose fields a caller could grow without bound
    # is a log-volume amplification path on an unauthenticated surface. Facts longer than
    # this are truncated, never dropped: the prefix is what identifies which client or
    # which URI a refusal was about, and the record still says the fact was long by being
    # exactly the cap.
    audit_fact_max_length: int = Field(default=256, gt=0)

    # -- Dynamic client registration (config-gated, default off) --------------

    # Off means the registration endpoint answers the documented disabled-error and the
    # authorization-server metadata advertises no registration endpoint; a stored
    # registration stays dormant, not deleted.
    dcr_enabled: bool = False
    dcr_store_path: str = "/data/dcr-registrations.json"
    dcr_max_registrations: int = Field(default=1024, gt=0)

    # The registration body's bounds. The endpoint is unauthenticated and accepts a body,
    # so a request that is merely large is a request that costs memory before any
    # validation runs — the per-record caps below bound what is *stored*, and this bounds
    # what is *read*. A legitimate registration is a few hundred bytes; the per-record
    # limits are generous multiples of anything a real client sends.
    #
    # The two kinds of bound apply to the same request, so they have to agree: this body
    # cap is the **governing** bound, and the per-record maxima are sized to be jointly
    # reachable inside it. A registration listing every redirect URI at the maximum length,
    # with a client name at the maximum length, fits in a default body with room for the
    # JSON around it — so an operator who raises a per-record bound knows that raising this
    # one alongside it is what makes the new bound deliverable. A per-record maximum the
    # body cap could never carry would be a bound that silently never applies: every
    # registration approaching it would be refused as oversized instead.
    dcr_max_body_bytes: int = Field(default=8192, gt=0)
    dcr_max_redirect_uris: int = Field(default=8, gt=0)
    dcr_max_redirect_uri_length: int = Field(default=512, gt=0)
    dcr_max_client_name_length: int = Field(default=256, gt=0)

    # -- Secret material ------------------------------------------------------

    # IdP-grade: whoever holds it can mint any identity Core will trust. Injected, never
    # committed, never logged. This is the **no-rotation** shape: one active `env`-sourced
    # entry and no retained entries, so a deployment that never rotates needs no keyset
    # JSON. The structured `gateway_signing_keys` is the multiply-entry shape; the two
    # configured simultaneously refuses startup naming both. Left unset in the skeleton;
    # the key loader refuses to start without a key in either spelling.
    gateway_signing_key: SecretStr | None = None

    # The structured signing keyset: a JSON object keyed by entry-id, each entry carrying
    # `source` (`env` or `file`; `kms` reserved and refused), `ref` (the environment
    # variable's name or the file's path, a read-only mount), and `role` (`active` or
    # `retained`). Exactly one entry is `active`; retained entries hold private material for
    # the drain window and are published in the JWKS beside the active one. The document is
    # structure, never secret material — each entry's material sits in its own variable or
    # file. Mutually exclusive with the singular `gateway_signing_key`.
    gateway_signing_keys: Annotated[dict[str, KeysetEntryModel], NoDecode] = Field(
        default_factory=dict
    )

    # The confidential client's secret at the identity provider. Required in one of its
    # two spellings: this environment-variable spelling, or the file spelling below. The
    # secret authenticates every identity-leg token request — the code exchange and the
    # refresh grant — in both positions of `idp_pkce_enabled`, so no deployment runs
    # without one. A blank value counts as unset (compose passes every setting explicitly,
    # so an unset value arrives as an empty string); `_resolve_client_secret` refuses a
    # configuration with neither spelling. Injected, never committed, never logged:
    # `SecretStr` keeps the value out of every repr and log line.
    idp_client_secret: SecretStr = SecretStr("")

    # The client secret delivered as a file instead of as an environment variable: the path
    # of a read-only-mounted file (`IDP_CLIENT_SECRET_FILE`, the spelling a mounted Secret
    # file takes). Exactly one of the two spellings is configured; both refuses startup
    # naming both settings. The file is read once at startup, and an unreadable or blank
    # file refuses loudly naming the path and never the content. The two spellings are
    # equivalent to the gateway — the deployment chooses the one its cluster manages.
    idp_client_secret_file: str | None = None

    # The dedicated custody key that seals the identity provider's session refresh token
    # into the gateway's own refresh token, as a JSON object of key-id -> key. Two spellings
    # are accepted, one per document. The **flat** spelling is key-id -> base64 key: exactly
    # one key, active, `env`-sourced, no retention — the pre-keyset shape, so no existing
    # deployment's configuration changes to gain the seam. The **structured** spelling is
    # the keyset entry schema (see `gateway_signing_keys`): one active entry and any number
    # of retained entries, each key-id -> {source, ref, role}. A document mixing the two
    # spellings refuses startup naming the keyset, because the flat shape cannot carry
    # retention and one spelling per document is what keeps the compat shape from silently
    # coexisting with it. Each key is a 32-byte value in base64 (`openssl rand -base64 32`).
    # Kept apart from the signing key: this key decrypts, it never signs.
    #
    # Any key that is not exactly 32 bytes refuses startup, because `AESGCM` follows the
    # key's length and a 16- or 24-byte key would silently run AES-128 or AES-192 for the
    # key's whole life — the pinned-algorithm claim would be false. Required: without it the
    # gateway cannot carry the provider token at all, and a deployment that omitted it would
    # discover that as a failed sign-in rather than at its start.
    gateway_custody_keys: Annotated[dict[str, object], NoDecode] = Field(
        default_factory=dict
    )

    # The largest provider session refresh token the gateway will carry, in bytes. A token
    # over this bound fails the flow **at sign-in**, with an operator-facing error naming the
    # bound: the carrier the token must fit inside is a refresh token handed to a harness
    # token store this gateway does not control, and a store that cannot hold it breaks
    # silently, far from its cause. Failing at sign-in is where the cause is diagnosable;
    # failing hours later at the first refresh would not be.
    gateway_custody_provider_token_max_bytes: int = Field(default=4096, gt=0)

    # -- Derived --------------------------------------------------------------

    @property
    def idp_callback_path(self) -> str:
        """The identity-provider callback path.

        Derived from a module constant rather than configured: the front router routes
        this path by name and the identity-provider client is registered against it, so a
        setting here would let one of the three places that must agree drift.
        """
        return IDP_CALLBACK_PATH

    @property
    def upstream_callback_path(self) -> str:
        """The upstream callback path, fixed for the same reason."""
        return UPSTREAM_CALLBACK_PATH

    @property
    def upstream_callback_uri(self) -> str:
        """The gateway's own upstream callback URI, derived from the public origin.

        The consent branch's upstream authorize URL and the credential call's `redirectUri`
        both carry this value — never the toolset's stored `auth_settings.redirect_uri`,
        which is an artifact of Core's registration that other components overwrite. Derived
        here for the same reason the callback path is a constant rather than a setting: the
        router routes the path by name, the upstream client is registered against the URI,
        and a second spelling of it could disagree with both.
        """
        return f"{self.gateway_public_origin}{UPSTREAM_CALLBACK_PATH}"

    @property
    def cimd_allowed_origins(self) -> tuple[str, ...]:
        """The allowlist as parsed origins, with blank entries dropped."""
        return tuple(
            origin.strip()
            for origin in self.gateway_cimd_allowed_origins.split(",")
            if origin.strip()
        )

    @property
    def custody_keyset(self) -> CustodyKeyset:
        """The custody keyset: the active key that seals, plus any retained keys.

        Built from the validated keyset entries on demand rather than cached: a settings
        object is immutable for the process's life, and the work is a handful of base64
        decodes. The active entry seals; the retained entries open. Exactly one active entry
        is guaranteed by `_validate_custody_keyset`.
        """
        active: CustodyKey | None = None
        retained: list[CustodyKey] = []
        for entry in self._custody_entries():
            key = CustodyKey(entry.id, decode_custody_key(resolve_material(entry)))
            if entry.is_active:
                active = key
            else:
                retained.append(key)
        # Exactly one active entry is guaranteed by `_validate_custody_keyset`; the
        # index below is the partition's read of that guarantee, and an empty list
        # here would mean the validators failed to run.
        return CustodyKeyset(cast(CustodyKey, active), retained)

    @property
    def custody_key(self) -> CustodyKey:
        """The single active custody key, the pre-keyset shape's accessor.

        The keyset is validated to hold exactly one active entry, so this reads that one.
        Retained entries, where configured, are reachable only through `custody_keyset`.
        """
        return self.custody_keyset.active

    def _custody_entries(self) -> list[KeysetEntry]:
        """The custody keyset as normalized entries, folding the flat compat spelling in.

        The flat spelling (key-id -> base64 value) is one active `env`-sourced entry with
        no retention; the structured spelling (key-id -> {source, ref, role}) is the
        multi-entry shape. `_validate_custody_keyset` has already refused a document mixing
        the two, so each entry here is one spelling or the other.
        """
        entries: list[KeysetEntry] = []
        for key_id, value in self.gateway_custody_keys.items():
            if isinstance(value, KeysetEntryModel):
                entries.append(
                    KeysetEntry(
                        id=key_id,
                        source=value.source,
                        role=value.role,
                        ref=value.ref,
                    )
                )
            else:
                entries.append(
                    KeysetEntry(
                        id=key_id,
                        source=SOURCE_ENV,
                        role=ROLE_ACTIVE,
                        material=_flat_custody_material(value),
                    )
                )
        return entries

    def toolset_resource_uri(self, path: str) -> str:
        """The protected resource a toolset's MCP path serves, from its canonical path.

        The path is the resource's canonical encoding (already computed by
        `canonical_path`), and one spelling derived here is what the router routes, what the
        protected-resource document advertises, and what an authorization request's
        `resource` parameter must equal — three places that would otherwise drift.
        """
        return f"{self.gateway_public_origin}/dial/{path}/mcp"

    def app_resource_uri(self, path: str) -> str:
        """The protected resource an app's MCP path serves, from its canonical path.

        The apps twin of `toolset_resource_uri`, derived the same way for the same reason.
        The two derivations are disjoint by prefix (`/dial/` against `/apps/`), so no
        resource URI resolves as both a toolset and an app.
        """
        return f"{self.gateway_public_origin}/apps/{path}/mcp"

    def toolset_path_from_resource(self, resource: str) -> str | None:
        """The toolset resource path a resource URI names, or `None` when it names no toolset.

        The inverse of `toolset_resource_uri` over the shared resolution. The returned path
        is the URI's own spelling as offered (raw percent-escapes, `/` separators); callers
        that need the one canonical identity canonicalize it through `canonical_path`.
        """
        resolved = self.resource_kind_and_path(resource)
        if resolved is None or resolved[0] != "toolset":
            return None
        return resolved[1]

    def app_path_from_resource(self, resource: str) -> str | None:
        """The app resource path a resource URI names, or `None` when it names no app.

        The apps twin of `toolset_path_from_resource`, shared through the same resolution:
        a `/dial/`-prefixed URI never resolves as an app path and vice versa.
        """
        resolved = self.resource_kind_and_path(resource)
        if resolved is None or resolved[0] != "app":
            return None
        return resolved[1]

    def resource_kind_and_path(self, resource: str) -> tuple[str, str] | None:
        """The resource kind and path a resource URI names, or `None` when it names neither.

        The one prefix-anchored resolution both kinds share: a `/dial/`-prefixed URI is a
        toolset, an `/apps/`-prefixed URI an app, and anything else names neither. The
        prefixes are disjoint, so no URI resolves both ways — which is what keeps a request
        from being reinterpreted across kinds between surfaces. Each prefix and the `/mcp`
        suffix are anchored, and the path between them is one or more `/`-separated
        segments — the resource path — so a trailing slash is a different resource, not
        this path's.
        """
        for kind, prefix in (("toolset", "dial"), ("app", "apps")):
            path = self._path_after_prefix(resource, prefix)
            if path is not None:
                return kind, path
        return None

    def _path_after_prefix(self, resource: str, prefix: str) -> str | None:
        """The resource path a URI carries after one kind's prefix, or `None` on a miss.

        The path is one or more `/`-separated segments between the prefix and the anchored
        `/mcp` suffix; it is returned in the URI's own offered spelling (percent-escapes
        intact), and the caller decodes/canonicalizes it. An empty path and any URI whose
        `/mcp` suffix is not terminal (a trailing slash, a post-`/mcp` path tail) are misses.
        """
        head = f"{self.gateway_public_origin}/{prefix}/"
        suffix = "/mcp"
        if not resource.startswith(head) or not resource.endswith(suffix):
            return None
        path = resource[len(head) : -len(suffix)]
        if not path:
            return None
        return path

    def resource_path_from_resource(self, resource: str) -> str | None:
        """The path a resource URI names, whichever kind, or `None` when it names neither.

        The kind-neutral reading of the shared resolution, for a caller that wants the value
        a request offered without asserting which namespace it belongs to. The audit trail's
        pre-allocation refusals use it: the path is recorded under the kind-neutral `name`
        fact, and a namespace-specific field name would misname the other kind's refusal.
        """
        resolved = self.resource_kind_and_path(resource)
        return resolved[1] if resolved is not None else None

    def canonical_resource_uri(self, resource: str) -> str | None:
        """The canonical resource URI a resource URI's path names, or `None` on a miss.

        The offered resource URI resolves to its kind and path, the path is canonicalized,
        and the canonical URI is re-derived from that one spelling — so two spellings of one
        resource (a non-canonical escape, an over-encoded character) yield one identity for
        the flow record, the token audience, and the refresh match. `None` when the URI names
        neither kind, or when a segment does not decode strictly (the caller refuses the
        request with the guard's fixed reason).
        """
        resolved = self.resource_kind_and_path(resource)
        if resolved is None:
            return None
        kind, path = resolved
        canonical = self.canonical_path(path)
        if canonical is None:
            return None
        return (
            self.toolset_resource_uri(canonical)
            if kind == "toolset"
            else self.app_resource_uri(canonical)
        )

    def path_guard_refusal(
        self, path: str, *, first_segment_reserved: bool
    ) -> str | None:
        """The path guard's verdict on an **offered** path: its reason, or `None` on a pass.

        The single predicate every path-resolution site shares. The offered path is split on
        raw `/` into segments first, then each segment is decoded — segmentation precedes
        decoding, so a `%2F` inside a segment decodes to a `/` *within that one segment* and
        never becomes a separator (the merge direction T-EP1-b prices). Per decoded segment:
        non-empty and not `.`/`..`; no forbidden character (`{`, `}`, `"`, or a control
        ≤ U+001F — Core's own set); and no trailing dot (a front-door ruling that mirrors
        Core's creation-side constraint and is deliberately stricter than its resolution).
        The whole path is bounded by the decoded byte cap and the configured segment cap.

        A segment whose escapes do not decode as strict UTF-8 (an invalid, over-long, or
        surrogate sequence) is refused with the same fixed reason, never lossily replaced.

        `first_segment_reserved` says whether the reserved-name rule applies — true for
        `/dial/` (toolset), false for `/apps/` — and when true the FIRST segment MUST NOT be
        a reserved name (`authorize`, `token`, …), because the router's authorization-surface
        location captures `/dial/{segment}/…` at the first segment. The reason is a token
        from this module's vocabulary, never caller-supplied: every decode-shape refusal
        lands on `invalid_resource_path` (the spec makes a trailing dot the
        forbidden-character class), and a reserved first segment on `reserved_path_segment`.
        `None` means the path is admitted by shape alone — an operator restriction, where
        configured, is applied by the kind's guard.
        """
        segments = _decoded_segments(path)
        if segments is None:
            return INVALID_RESOURCE_PATH
        if len(segments) > self.resource_path_max_segments:
            return INVALID_RESOURCE_PATH
        decoded_bytes = (
            sum(len(segment.encode("utf-8")) for segment in segments)
            + len(segments)
            - 1
        )
        if decoded_bytes > RESOURCE_PATH_MAX_BYTES:
            return INVALID_RESOURCE_PATH
        for index, segment in enumerate(segments):
            if _segment_shape_refusal(segment) is not None:
                return INVALID_RESOURCE_PATH
            if (
                first_segment_reserved
                and index == 0
                and segment in RESERVED_TOOLSET_NAMES
            ):
                return RESERVED_PATH_SEGMENT
        return None

    def toolset_guard_refusal(self, path: str) -> str | None:
        """The toolset path guard's verdict on an **offered** path: its reason, or `None`.

        The single predicate every toolset path-resolution site shares: the offered path is
        decoded (strict UTF-8), the decoded form passes the per-segment rules and the
        reserved first segment, and — when an operator restriction is configured — the
        restriction admits the path's canonical identity. A path is served exactly when this
        returns `None`. Unset, the restriction admits every guard-passing path, because
        existence is decided post-authentication at the flow's listing read, not on any
        unauthenticated surface.
        """
        refusal = self.path_guard_refusal(path, first_segment_reserved=True)
        if refusal is not None:
            return refusal
        # The guard has proven the path decodes strictly, so the canonical form exists.
        canonical = self.canonical_path(path)
        if self.toolsets and canonical not in self._canonical_members(self.toolsets):
            return RESTRICTED_TOOLSET
        return None

    def app_guard_refusal(self, path: str) -> str | None:
        """The app path guard's verdict on an **offered** path: its reason, or `None`.

        The apps namespace's twin of `toolset_guard_refusal`, over the same decoded
        per-segment rules and the apps restriction in place of the toolset one. There is
        deliberately no reserved-name check: the toolset guard's reserved names are
        `/dial/`-scoped authorization-surface segments (`/dial/authorize`, `/dial/token`, …),
        and an app path occupying `/apps/{path}/…` can never capture them — nothing the
        gateway owns is served under the apps namespace's first segment. Unset, the app
        restriction admits every guard-passing path, because existence is decided
        post-authentication at the flow's app read, not on any unauthenticated surface.
        """
        refusal = self.path_guard_refusal(path, first_segment_reserved=False)
        if refusal is not None:
            return refusal
        # The guard has proven the path decodes strictly, so the canonical form exists.
        canonical = self.canonical_path(path)
        if self.apps and canonical not in self._canonical_members(self.apps):
            return RESTRICTED_APP
        return None

    def _canonical_members(self, entries: Mapping[str, object]) -> frozenset[str]:
        """A restriction's configured entries as their canonical identities.

        Membership is decided canonical-vs-canonical, so a restricted-out resource cannot
        enter by encoding: an entry spelled with a non-canonical escape admits every
        accepted spelling of the same resource, and a request spelling the entry
        differently canonicalizes to the same string. An entry whose own spelling cannot be
        canonicalized (a stored one the startup validator already refused) is kept verbatim
        so the set never silently widens; startup refuses such entries before serving.
        """
        return frozenset(
            canonical
            if (canonical := self.canonical_path(entry)) is not None
            else entry
            for entry in entries
        )

    def restriction_entry(
        self, entries: Mapping[str, object], path: str
    ) -> object | None:
        """A restriction's entry for a path, matched on the canonical identity.

        The path offered is canonicalized and compared against each configured entry's
        canonical form, so an entry the operator spelled non-canonically is still found. The
        first match wins; a restriction's keys are unique canonical identities after the
        startup validator has run.
        """
        canonical = self.canonical_path(path)
        for entry, value in entries.items():
            if self.canonical_path(entry) == canonical:
                return value
        return None

    def canonical_path(self, path: str) -> str | None:
        """The one canonical encoding of an offered resource path, or `None`.

        The canonical form is the resource's **identity**: the flow record, the token
        audience, the refresh match, and the restriction's membership check all use it, so
        two spellings of one resource are one resource and never two. It is computed by
        splitting the offered path on raw `/` into segments (segmentation precedes decoding)
        and re-encoding each segment: unreserved characters raw, everything else `%XX`
        uppercase hex over UTF-8. A decoded `/` within one segment (reachable only as `%2F`)
        is re-encoded to `%2F`, so it can never merge with a segment separator.

        A segment's percent-escapes decode as **strict UTF-8**: an invalid, over-long, or
        CESU-8-style surrogate sequence yields `None` (the caller refuses the path with the
        guard's fixed reason), never a lossy replacement that would merge distinct wire
        spellings onto one U+FFFD identity. `+` is a literal character in path position,
        never a space (the escape set is `unquote`, never `unquote_plus`). The caller
        validates the decoded path through the guard; canonicalization itself is shape-neutral.
        """
        segments = _decoded_segments(path)
        if segments is None:
            return None
        return "/".join(quote(segment, safe=_CANONICAL_SAFE) for segment in segments)

    @staticmethod
    def decoded_path(canonical_path: str) -> str:
        """The decoded form of a canonical resource path.

        The credential call's `url` member carries the **decoded** path — the form Core's own
        `id` fields carry and its credential store keys on — while the flow record's resource
        field carries the canonical path. Both come from one resolution; this is the decode
        step from the canonical form. Segments are decoded with `unquote` (never
        `unquote_plus`), matching the canonical encoder's pinned discipline.
        """
        return "/".join(unquote(segment) for segment in canonical_path.split("/"))

    # -- Validation -----------------------------------------------------------

    @model_validator(mode="after")
    def _validate_mapping(self) -> Settings:
        """Refuse a configured restriction entry that could never be routed.

        The path guard's classes are all caught here rather than at request time, and only
        for *configured* entries: a reserved first segment has its MCP path captured by the
        router's authorization surface, so its traffic never reaches Core, and a segment
        outside the decoded rules — a forbidden character, a trailing dot, a dot or empty
        segment, an over-length or over-depth path — has no location the router's grammar can
        route. The router is static configuration with no view of what Core serves, so none
        of these can be repaired at request time for a path the operator pinned — only here,
        before the container serves anything. A dynamic path is guarded by the request-time
        path guard instead, which reuses the same rules, so the two cannot disagree.

        The apps restriction carries the same decoded-rule refusals, for the same
        static-routing reason, and only those: an app path has no reserved-name class,
        because nothing the gateway owns is served under the apps namespace's first segment.
        """
        for path in self.toolsets:
            self._refuse_unroutable_entry(path, kind="toolset", reserved=True)
        for path in self.apps:
            self._refuse_unroutable_entry(path, kind="app", reserved=False)
        return self

    def _refuse_unroutable_entry(self, path: str, *, kind: str, reserved: bool) -> None:
        """Refuse one configured restriction entry the path grammar could never route.

        The entry is offered the same way a request is: split on raw `/`, each segment
        strictly decoded, and the decoded path passed through the path guard. The refusal
        names the entry and the rule it broke, so an operator reads the remedy off the
        message. A segment that does not decode strictly (an invalid, over-long, or surrogate
        sequence) is the same class as a segment outside the decoded rules.
        """
        refusal = self.path_guard_refusal(path, first_segment_reserved=reserved)
        if refusal is None:
            return
        rule = _RULE_PHRASES.get(refusal, "the path rules")
        if refusal == RESERVED_PATH_SEGMENT:
            rule = f"{rule}. Reserved names: {', '.join(RESERVED_TOOLSET_NAMES)}"
        message = (
            f"{kind} restriction entry {path!r} could never be routed: {rule}. A "
            f"configured entry must be a resource path the front router's grammar can "
            f"route, so it is refused here rather than serving a resource no harness can "
            f"reach"
        )
        raise ValueError(message)

    @model_validator(mode="after")
    def _require_admissible_redirect_uris(self) -> Settings:
        """Refuse a pre-registered client whose redirect URIs carry a non-loopback http URI.

        The operator's own configuration is an admission site like the registration
        surfaces: a plain-`http` redirect on a real host is the collector the authorization
        response would cross in cleartext, and an operator who configured one would
        otherwise have registered exactly the value the DCR and CIMD paths refuse. The
        refusal names the entry, so the operator can find it in the JSON document without
        guessing which client it belongs to.
        """
        for client_id, client in self.pre_registered_clients.items():
            for uri in client.redirect_uris:
                refusal = scheme_admission_refusal(uri)
                if refusal is not None:
                    message = (
                        f"pre-registered client {client_id!r} carries a redirect URI this "
                        f"gateway cannot admit ({uri!r}): {ADMISSION_RULE}. Pre-registration "
                        f"is an admission site like the registration surfaces, so the "
                        f"container refuses to start rather than serve the URI"
                    )
                    raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _require_a_single_toolset_to_infer(self) -> Settings:
        """Refuse resource inference with no single-entry toolset restriction to infer from.

        Inference picks "the one toolset" when a request names no resource. Under dynamic
        serving there is no single toolset unless the operator's *toolset* restriction pins
        exactly one, so enabling inference without that restriction would have nothing to
        infer and could only guess — which is how a token ends up addressed to a toolset
        the client never named. The check names the toolset restriction explicitly, and
        inference never consults the apps restriction: with a second namespace served by the
        same authorization server there is even less "the one resource" an unnamed request
        could honestly be resolved to.
        """
        if self.gateway_infer_resource_single_toolset and len(self.toolsets) != 1:
            message = (
                "gateway_infer_resource_single_toolset is enabled but the toolset "
                "restriction is not configured with exactly one entry; resource inference "
                "needs a single-entry toolset restriction to name the toolset a request "
                "without a resource should be served, or disable inference and have clients "
                "send the `resource` parameter. Inference never consults the apps "
                "restriction and never resolves a request to an app"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _validate_direct_endpoint_set(self) -> Settings:
        """Refuse a direct endpoint set that cannot serve the identity leg whole.

        The trio is all-or-nothing, and each member is checked before the container
        serves anything, because a leg whose endpoints come from two sources has two
        spellings of the identity leg and a member that cannot be addressed as a URL
        fails at first use — far from the misconfiguration that caused it.

        Three refusals, each naming the settings it is about:

        * **partial set** — some members configured and others missing, so the leg would
          mix its sources;
        * **not a well-formed absolute URL** — a value with no scheme or no host cannot
          be addressed as an endpoint at all;
        * **plain http without the override** — the code, the carried refresh token, and
          the client secret never ride a plain leg the operator has not explicitly owned
          by configuring the back-channel base to that origin.

        Deliberately absent: an origin binding to the issuer. The trio is operator input
        at the issuer setting's own trust level — there is no provider-asserted document
        to constrain — and a split-origin provider (a token endpoint on a separate host
        from its issuer) is a legitimate shape this mode exists to serve.
        """
        configured = {
            name: getattr(self, name)
            for name in _DIRECT_ENDPOINT_SETTINGS
            if getattr(self, name) is not None
        }
        if not configured:
            return self
        if len(configured) < len(_DIRECT_ENDPOINT_SETTINGS):
            missing = [
                name for name in _DIRECT_ENDPOINT_SETTINGS if name not in configured
            ]
            message = (
                f"the direct identity-provider endpoint set is partial: "
                f"{', '.join(sorted(configured))} configured, "
                f"{', '.join(missing)} missing. The set is all-or-nothing, because a "
                f"leg whose endpoints come from two sources has two spellings of the "
                f"identity leg: set all three of "
                f"idp_authorization_endpoint, idp_token_endpoint, and idp_jwks_uri, "
                f"or none of them"
            )
            raise ValueError(message)

        override = self.idp_backchannel_base_url
        override_origin = _origin_of(override) if override else None
        # `configured` holds only the members that are set, so every value here is a
        # string; the names are sorted so the checks, like the partial-set refusal, run
        # in one deterministic order.
        for name, value in sorted(configured.items()):
            parts = urlsplit(value)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                message = (
                    f"{name} ({value!r}) is not a well-formed absolute URL: an "
                    f"endpoint must carry a scheme and a host to be addressed at all"
                )
                raise ValueError(message)
            if parts.scheme != "https" and _origin_of(value) != override_origin:
                message = (
                    f"{name} is plain http and shares no configured back-channel "
                    f"base's origin: the code, the carried refresh token, and the "
                    f"client secret never ride a plain leg the operator has not "
                    f"explicitly owned. Set the endpoint to HTTPS, or configure "
                    f"idp_backchannel_base_url to own this origin"
                )
                raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _require_wellformed_issuer_and_backchannel_base(self) -> Settings:
        """Refuse an issuer or back-channel base no HTTP client could address.

        The two settings the whole identity leg hangs off get the same well-formedness
        check the direct endpoint trio carries: a value that is not an absolute http(s)
        URL — an empty host, a scheme no HTTP client speaks — is a configuration error,
        refused at startup naming the setting, rather than surfacing as a client-side
        URL error at the first sign-in, far from the misconfiguration that caused it.
        The check is deliberately the trio's shape (parse, scheme, host): it refuses
        what cannot be addressed at all, and a value that passes it and that the HTTP
        client itself still refuses fails the leg at the fetch, translated into the
        leg's fixed-vocabulary operator-facing error like any other unreachable
        provider.
        """
        for name in ("idp_issuer", "idp_backchannel_base_url"):
            value = getattr(self, name)
            if value is None:
                continue
            try:
                parts = urlsplit(value)
                addressable = parts.scheme in ("http", "https") and bool(parts.netloc)
            except ValueError:
                addressable = False
            if not addressable:
                message = (
                    f"{name} ({value!r}) is not a well-formed absolute URL: the "
                    f"identity leg hangs off it, and a value that cannot be addressed "
                    f"as a URL fails at the first sign-in, far from the configuration "
                    f"that caused it"
                )
                raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _require_https_issuer_without_the_override(self) -> Settings:
        """Refuse a plain-http configured issuer with no back-channel base to own it.

        The configured issuer is the identity anchor in either endpoint mode — the
        discovery fetch's target and the document's validation target in discovery mode,
        the exact pin's comparison value in both — and the plain-leg ownership the
        back-channel override grants reaches the endpoints the leg calls, never the
        anchor itself. So the anchor is HTTPS unless the operator has explicitly owned a
        plain origin by configuring the override, whichever endpoint source serves the
        legs.
        """
        if (
            urlsplit(self.idp_issuer).scheme == "http"
            and not self.idp_backchannel_base_url
        ):
            message = (
                "idp_issuer is plain http and no back-channel base is configured: the "
                "configured issuer is the identity anchor, and the back-channel "
                "override's plain-leg ownership reaches the endpoints the leg calls, "
                "never the anchor itself. Set the issuer to HTTPS, or configure "
                "idp_backchannel_base_url to own this plain origin"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _resolve_client_secret(self) -> Settings:
        """Resolve the client secret from its one configured spelling, or refuse.

        The secret is the confidential client's authentication: every identity-leg token
        request — the code exchange and the refresh grant — presents it, in both positions
        of the PKCE toggle. Exactly one of its two spellings may be configured:

        * **both** — a secret with two possible values has no single value, so startup
          refuses naming both settings (the same mixing refusal the keyset seam carries);
        * **the file spelling alone** — the file is read once, here at startup, and its
          content becomes the secret. An unreadable or blank file refuses loudly naming the
          path and never the content: a read error can echo what it choked on, and a
          material-shaped value in an error is a credential in a log line;
        * **the environment variable alone** — a value absent or blank is refused by name,
          because compose passes every setting explicitly and an unset value arrives as an
          empty string, so a blank that passed would surface as the provider's
          `invalid_client` at the first sign-in, far from the misconfiguration that caused
          it;
        * **neither** — the missing-secret refusal, naming the setting.

        The two spellings are equivalent to the gateway: whichever delivers it, the secret
        lives in the same `idp_client_secret` field afterwards, so every consumer reads one
        value and the delivery choice never reaches them.
        """
        environment_spelling = bool(self.idp_client_secret.get_secret_value().strip())
        file_spelling = bool(self.idp_client_secret_file)
        if environment_spelling and file_spelling:
            message = (
                "idp_client_secret and idp_client_secret_file are both configured: the "
                "identity-provider client's secret has exactly one value, so it is "
                "delivered by exactly one spelling. Set the environment variable, or the "
                "file path, but not both"
            )
            raise ValueError(message)

        if file_spelling:
            path = self.idp_client_secret_file or ""
            try:
                content = _read_secret_file(path)
            except OSError as exc:
                message = (
                    f"idp_client_secret_file names {path!r}, which cannot be read: the "
                    f"client secret must be a readable file on a read-only mount at that "
                    f"path"
                )
                raise ValueError(message) from exc
            if not content.strip():
                message = (
                    f"idp_client_secret_file names {path!r}, which is blank: a blank "
                    f"source is a misconfiguration, not a secret"
                )
                raise ValueError(message)
            # Strip at read, the same discipline `decode_custody_key` applies to the keyset
            # sources: a mounted-secret file commonly ends in a newline, and an unstripped
            # trailing byte would silently change the presented secret and surface as the
            # provider's `invalid_client` at the first sign-in — far from the file that
            # caused it. The blank check above is `strip()`-based, so a whitespace-only file
            # still refuses as blank; the strip here only removes surrounding whitespace
            # from a real value.
            self.idp_client_secret = SecretStr(content.strip())
            return self

        if not environment_spelling:
            message = (
                "idp_client_secret is missing or blank: the identity-provider client "
                "is a confidential client, and its secret authenticates every "
                "identity-leg token request (the code exchange and the refresh grant) "
                "in both positions of idp_pkce_enabled — client secret plus PKCE, or "
                "client secret alone, never PKCE alone. Configure idp_client_secret "
                "(the client must be registered confidential at the provider), or "
                "idp_client_secret_file naming a read-only mounted file that carries it"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _require_refresh_window_within_provider_session_bound(self) -> Settings:
        """Refuse a refresh window longer than the declared identity-provider session bound.

        The carried session refresh token has to remain usable at every refresh in the
        window, so the window must fit inside the operator's declared bound on how long the
        provider keeps that token usable. The declared value is an **assertion about
        provider session policy**, not a fact this process can learn: an operator states the
        bound from the provider's own session policy, and the check is arithmetic over two
        operator settings. What
        it cannot catch — a session policy shorter than declared — fails loudly at runtime
        instead, as the `idp_session_ended` refusal on the audit trail. Both values are
        named in the refusal, because the remedy is one of the two rather than anything the
        gateway could do.
        """
        if self.gateway_refresh_ttl_seconds > self.idp_sso_session_max_seconds:
            message = (
                f"gateway_refresh_ttl_seconds ({self.gateway_refresh_ttl_seconds}) "
                f"exceeds idp_sso_session_max_seconds "
                f"({self.idp_sso_session_max_seconds}): the carried session refresh "
                f"token must remain usable at every refresh in the window, and the "
                f"declared session bound is how long the identity provider keeps it. "
                f"Where the provider's session policy is shorter, the shorter refresh "
                f"window is the correct configuration"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _validate_custody_keyset(self) -> Settings:
        """Refuse a custody keyset that cannot seal exactly one key.

        The keyset holds the key that seals — and only the active one can seal — the
        identity provider's session refresh token inside every issued gateway refresh token.
        Both spellings are checked here, and the failures each can produce are caught rather
        than trusted because each fails silently in operation:

        * **empty** — the gateway could mint nothing it can later decrypt;
        * **mixed spellings** — a document whose entries are some flat and some structured
          has no single reading: the flat shape means "one active env key, no retention," so
          mixing it with structured entries would let a compat shape carry retention by
          accident. One spelling per document, refused by name otherwise;
        * **zero or multiple active** — a structured keyset must hold exactly one `active`
          entry (no key seals with none; two sealing keys break the single-active invariant);
        * **reserved `kms`** — an entry naming the unimplemented source refuses, naming the
          gap, never silently falling back;
        * **wrong length** — `AESGCM` constructs for a 16-, 24-, or 32-byte key and follows
          the key's length, so a shorter key would silently run AES-128 or AES-192 for the
          key's whole life and make the pinned-algorithm claim false.
        """
        if not self.gateway_custody_keys:
            message = (
                "gateway_custody_keys is not set: the gateway has no custody key to seal "
                "the identity provider's session refresh token with. Generate one with "
                "`openssl rand -base64 32` and set it in GATEWAY_CUSTODY_KEYS as "
                '{"<key-id>": "<base64 key>"}'
            )
            raise ValueError(message)

        structured = [
            value
            for value in self.gateway_custody_keys.values()
            if isinstance(value, KeysetEntryModel)
        ]
        if structured and len(structured) != len(self.gateway_custody_keys):
            message = (
                "gateway_custody_keys mixes the flat and the structured spelling in one "
                "document: the flat shape (key-id -> base64 key) means one active "
                "env-sourced key with no retention, and the structured shape (key-id -> "
                "{source, ref, role}) carries the roles. One spelling per document — a "
                "mixed document has no single reading"
            )
            raise ValueError(message)

        entries = self._custody_entries()
        validate_entries(
            entries,
            "gateway_custody_keys",
            kms_refusal=CUSTODY_KMS_REFUSAL,
            one_active_phrase="exactly one key must be active",
        )

        for entry in entries:
            if not custody_key_id_is_valid(entry.id):
                message = (
                    f"custody key id {entry.id!r} must be 1 to {KEY_ID_MAX_BYTES} ASCII "
                    f"characters"
                )
                raise ValueError(message)
            try:
                decode_custody_key(resolve_material(entry))
            except CustodyError as exc:
                message = f"custody key {entry.id!r}: {exc}"
                raise ValueError(message) from exc
        return self

    @model_validator(mode="after")
    def _validate_signing_keyset(self) -> Settings:
        """Refuse a signing keyset that cannot sign, or a doubly-configured spelling.

        The two signing spellings are mutually exclusive: the singular `gateway_signing_key`
        is the no-rotation compat shape, and the structured `gateway_signing_keys` is the
        multiply-entry shape. Both configured refuses by name, because the gateway would
        otherwise have two candidate active keys and no honest way to choose between them.

        The structured keyset's entries are validated here (one active, the reserved `kms`
        value refused by name, every source known, every entry naming its material). The
        material itself is parsed and the derived-`kid` duplicate check runs in the loader
        (`gateway/keys.py`), which reads the files and variables once at startup — this
        model holds no secret material and reads no file for the signing key.
        """
        if self.gateway_signing_key is not None and self.gateway_signing_keys:
            message = (
                "gateway_signing_key and gateway_signing_keys are both configured: the "
                "singular setting is the no-rotation shape (one active key, no retained "
                "entries) and the structured setting is the keyset shape. Configure "
                "exactly one — a deployment that never rotates needs no keyset JSON"
            )
            raise ValueError(message)

        if self.gateway_signing_keys:
            entries = [
                KeysetEntry(
                    id=entry_id,
                    source=entry.source,
                    role=entry.role,
                    ref=entry.ref,
                )
                for entry_id, entry in self.gateway_signing_keys.items()
            ]
            validate_entries(
                entries,
                "gateway_signing_keys",
                kms_refusal=SIGNING_KMS_REFUSAL,
                one_active_phrase="exactly one entry must be active",
            )
        return self

    @model_validator(mode="after")
    def _require_custody_bounds_to_fit_the_body_cap(self) -> Settings:
        """Refuse a provider-token size bound the form-body cap could never deliver.

        The two settings bound the same request from two directions: the size bound says how
        large a provider refresh token a sign-in may carry, and the body cap says how large a
        refresh request the token endpoint will read. A refresh request carries the gateway's
        own refresh token — which carries the custody envelope — in its form body, so a
        provider-token bound raised past the cap's headroom would let sign-ins succeed and
        make every refresh fail over-cap, hours later and far from its cause. That is exactly
        the far-from-its-cause failure the loud sign-in refusal exists to prevent, recreated
        by configuration; so it is refused at startup, naming both settings.
        """
        envelope_bytes = envelope_bytes_for_token(
            self.gateway_custody_provider_token_max_bytes
        )
        # The envelope rides inside the gateway's signed refresh token, whose own claims,
        # signature, and the form's other parameters add a bounded overhead.
        needed = envelope_bytes + _REFRESH_BODY_OVERHEAD_BYTES
        if needed > self.gateway_form_max_body_bytes:
            message = (
                f"gateway_custody_provider_token_max_bytes "
                f"({self.gateway_custody_provider_token_max_bytes}) does not fit inside "
                f"gateway_form_max_body_bytes ({self.gateway_form_max_body_bytes}): a "
                f"provider token at the bound seals into an envelope of about "
                f"{envelope_bytes} bytes, and the refresh request carrying it needs about "
                f"{needed} bytes with the token's own claims and the form's other "
                f"parameters. Raise gateway_form_max_body_bytes, or lower the provider-token "
                f"bound, so every refresh body the bound lets a sign-in issue passes the cap"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _require_registration_bounds_to_fit_the_body_cap(self) -> Settings:
        """Refuse registration bounds the body cap could never deliver.

        The per-record maxima and the body cap bound the same request from two directions:
        the cap bounds what is *read*, the maxima bound what one registration may
        *contain*. Stated alone each looks reasonable, and together they can contradict —
        silently, because the symptom is that the registration endpoint refuses as
        oversized exactly the registrations its own configuration advertises as allowed.
        An operator who raised a per-record maximum expecting larger clients would see no
        error and no effect.

        So the largest registration the maxima permit, plus the JSON scaffolding around it,
        must fit inside the cap. A configuration that fails this is refused at startup
        naming both settings, because the remedy is one of the two values rather than
        anything the gateway could do with a request. The defaults satisfy it comfortably,
        which is what makes the stated relationship a property of this file rather than a
        claim about one deployment's numbers.
        """
        largest_permitted = (
            self.dcr_max_redirect_uris * self.dcr_max_redirect_uri_length
            + self.dcr_max_client_name_length
            + _REGISTRATION_SCAFFOLDING_BYTES
        )
        if largest_permitted > self.dcr_max_body_bytes:
            message = (
                f"the registration bounds are jointly unreachable within "
                f"dcr_max_body_bytes ({self.dcr_max_body_bytes}): "
                f"dcr_max_redirect_uris ({self.dcr_max_redirect_uris}) redirect URIs of up "
                f"to dcr_max_redirect_uri_length ({self.dcr_max_redirect_uri_length}) "
                f"characters, a client name of up to dcr_max_client_name_length "
                f"({self.dcr_max_client_name_length}), and the JSON around them need about "
                f"{largest_permitted} bytes. A registration at the advertised maxima would "
                f"be refused as oversized, so one of the two bounds has to move: raise "
                f"dcr_max_body_bytes, or lower the per-record bounds until they fit"
            )
            raise ValueError(message)
        return self

    @field_validator("gateway_signing_key")
    @classmethod
    def _reject_placeholder_key(cls, value: SecretStr | None) -> SecretStr | None:
        """Refuse the committed example's placeholder for the signing key.

        The placeholder is a real, if unusable, value: a deployment that never replaced
        it would sign tokens with a key that is published in this repository. Refusing it
        at startup turns that into a configuration error.
        """
        if value is not None and value.get_secret_value() == _PLACEHOLDER_SIGNING_KEY:
            message = (
                "gateway_signing_key is still the placeholder from `.env.example`; "
                "generate a key and set the real value in `.env`"
            )
            raise ValueError(message)
        return value

    @field_validator(
        "gateway_public_origin",
        "dial_core_base_url",
        "idp_backchannel_base_url",
        "idp_authorization_endpoint",
        "idp_token_endpoint",
        "idp_jwks_uri",
    )
    @classmethod
    def _require_scheme(cls, value: str | None) -> str | None:
        """Reject a URL-shaped setting that carries no scheme.

        A bare host reaches the URL builders as a relative path, where the failure is a
        confusing outbound error rather than a configuration error. Trailing slashes are
        stripped so joining a path is unambiguous. The back-channel override and the
        direct endpoint trio are optional, so their absence (or a blank environment
        value, which `compose` interpolation produces for an unset variable) means unset
        rather than malformed. The configured issuer is deliberately absent from this
        validator: its value is a pin before it is an address, and its spelling is
        preserved verbatim (`_require_scheme_on_the_issuer`).
        """
        if value is None:
            return None
        if "://" not in value:
            message = f"{_SCHEME_ERROR}, got {value!r}"
            raise ValueError(message)
        return value.rstrip("/")

    @field_validator("idp_issuer")
    @classmethod
    def _require_scheme_on_the_issuer(cls, value: str | None) -> str | None:
        """Reject a scheme-less issuer, and otherwise keep the configured spelling verbatim.

        The issuer is the one URL setting whose value is a pin before it is an address:
        the discovery document's `issuer` member and every identity token's `iss` claim
        are compared against it as exact strings, so the operator's spelling is the
        trust anchor's spelling. A trailing slash is part of the pin — a provider whose
        canonical issuer ends in `/` (the per-journey issuer form some providers carry)
        would never match a normalized copy of itself, and neither its document nor its
        tokens could ever be accepted. Normalization is therefore not applied here; the
        one place the issuer is used as an address — the well-known join, at the fetch —
        adds the separator explicitly instead.
        """
        if value is None:
            return None
        if "://" not in value:
            message = f"{_SCHEME_ERROR}, got {value!r}"
            raise ValueError(message)
        return value

    @field_validator(
        "idp_backchannel_base_url",
        "idp_authorization_endpoint",
        "idp_token_endpoint",
        "idp_jwks_uri",
        mode="before",
    )
    @classmethod
    def _blank_optional_url_is_unset(cls, value: object) -> object:
        """Read a blank optional URL setting as unset.

        The compose file passes every setting explicitly, so an unset deployment value
        arrives here as an empty string rather than as absent; "unset by default" is that
        empty string, not a malformed URL.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("idp_client_secret_file", mode="before")
    @classmethod
    def _blank_secret_file_path_is_unset(cls, value: object) -> object:
        """Read a blank secret-file path as unset.

        The compose file passes every setting explicitly, so an unset deployment value
        arrives here as an empty string; "unset" is that empty string, not a path. The
        resolved-secret check (`_resolve_client_secret`) then sees the file spelling as
        absent and reads the environment spelling instead.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("gateway_signing_key", mode="before")
    @classmethod
    def _blank_signing_key_is_unset(cls, value: object) -> object:
        """Read a blank singular signing key as unset.

        The compose file passes every setting explicitly, so an unset deployment value
        arrives here as an empty string (or as whitespace) rather than as absent; "unset"
        is that blank, not a key. Normalizing at the field is what lets every reader see
        the same fact: the exclusivity check (`_validate_signing_keyset`) reads a blank
        singular as unconfigured beside a structured keyset, and the loader's fold
        (`gateway/keys.py` `_entries_from_settings`) reads it as no singular entry, so a
        blank singular alone surfaces as the neither-configured refusal rather than as a
        parse refusal over empty material. A spelling is configured only by a real value.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("gateway_custody_keys", mode="after")
    @classmethod
    def _coerce_custody_entries(cls, value: dict[str, object]) -> dict[str, object]:
        """Turn each structured custody value into its entry model, masking each flat value.

        The field is typed loosely (`object`) because a document may carry either spelling:
        a flat value is a base64 string, a structured value is the `{source, ref, role}`
        mapping. A mapping is validated into `KeysetEntryModel` here so a misspelled member
        is refused at parse naming the field; a flat string is wrapped in `SecretStr` here
        so the key material is masked in every repr, dump, and serialization of a settings
        object — the flat spelling is what existing deployments configure, so it must be as
        loggable as the structured spelling, whose material lives behind a `ref` indirection
        the model never holds. `_custody_entries` unwraps the `SecretStr` at the one place
        the material is resolved. `_validate_custody_keyset` then refuses a document mixing
        the two kinds.
        """
        coerced: dict[str, object] = {}
        for key_id, entry in value.items():
            if isinstance(entry, KeysetEntryModel):
                coerced[key_id] = entry
            elif isinstance(entry, dict):
                coerced[key_id] = KeysetEntryModel.model_validate(entry)
            elif isinstance(entry, str):
                coerced[key_id] = SecretStr(entry)
            else:
                coerced[key_id] = entry
        return coerced

    @field_validator(
        "toolsets",
        "apps",
        "pre_registered_clients",
        "gateway_signing_keys",
        "gateway_custody_keys",
        mode="before",
    )
    @classmethod
    def _parse_json_document(cls, value: object) -> object:
        """Accept the structured settings as a JSON document in an environment variable.

        An empty value means "none configured" rather than a malformed document — the
        compose file passes every setting explicitly, and an unset list arrives as an
        empty string. The custody keyset is required, so an empty value surfaces as that
        requirement's own refusal rather than as a malformed document.

        The refusal names the problem and never the raw value: a malformed custody document
        can carry real key material inside its text, so echoing what the parser choked on
        would put a credential in an error message — the class `hide_input_in_errors` does
        not reach, since it redacts only the model's own field values.
        """
        if isinstance(value, str):
            if not value.strip():
                return {}
            try:
                return json.loads(value)
            except ValueError as exc:
                message = f"must be a JSON object: {exc}"
                raise ValueError(message) from exc
        return value
