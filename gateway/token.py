"""The `/dial/token` grants, and `/dial/revoke`.

**The code grant's job is validation**, and the validation is the whole security story of
the endpoint. A code is a signed token, so its bindings can be checked without server
state — but only if every one of them is checked: the code must have been issued to this
client, for this redirect URI, and for the resource being redeemed, and the presented
verifier must be the one the challenge was derived from. A code redeemed twice must fail,
and that is the one check that does need state: the replay cache, keyed by the code's own
identifier and claimed at the same moment the code is accepted, so there is no window
between "verified" and "used" that a second request could slip through. The code's claim
snapshot is the access token's claim source here — the code's own short TTL is its freshness
bound — and the code grant seals the provider's session refresh token (held by `_finish` in
the pending hand-off entry keyed by the code's id) into the issued refresh token's custody
claim. An entry that is absent refuses the grant fail closed: a code whose entry was lost
with the process, or one already consumed, names no provider credential, and a session minted
without custody could never be refreshed — so the refusal lands here rather than at that
token's next refresh.

**The refresh grant re-reads the claims.** It decrypts the custody claim, presents the
recovered provider refresh token to the identity provider's token endpoint (RFC 6749 §6),
verifies the fresh token the grant returns through the same path issuance uses, copies and
overlays its claims onto the minted access token, and rotates — re-encrypting the provider's
latest refresh token into the replacement under the current custody key. Every failure
refuses with `invalid_grant` and no fallback: the gateway's refresh token carries no claim
snapshot at all, so a stale-snapshot mint has no data to serve and cannot be taken under an
availability squeeze. Three failure classes audit apart through the closed reason table —
`custody_decrypt_failed` (the gateway's own custody fault), `claims_read_failed` (an outage,
an unusable answer, a subject mismatch, a missing roles path, or any provider 4xx other than
`invalid_grant`), and `idp_session_ended` (the provider's `invalid_grant` — the session is
gone) — so a custody mistake, a provider outage, a session-policy break, and mass revocation
are four distinguishable bursts on the trail.

**Revocation is local**: a refresh token's id is denylisted until the token's own expiry,
so the entry is bounded by the token it names. Nothing is introspected, because there is
nothing to introspect — the tokens are the gateway's own.

Each check refuses by raising, and one handler turns every refusal into the error document
a client's OAuth library expects. The sequence of checks is then readable as an ordered
list rather than as a ladder of nested early returns.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qsl

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from gateway import errors
from gateway.codes import CodeError, decode_code, verify_pkce
from gateway.custody import CustodyError
from gateway.idp import IdentityProviderError, RefreshGrantError
from gateway.requests import capped_body
from gateway.runtime import Runtime
from gateway.settings import (
    INVALID_RESOURCE_PATH,
    RESERVED_PATH_SEGMENT,
    RESTRICTED_APP,
    RESTRICTED_TOOLSET,
    Settings,
)
from gateway.state import new_token_id
from gateway.tokens import (
    CUSTODY_CLAIM_MEMBER,
    REFRESH_TOKEN_TYPE,
    IssuanceError,
    TokenError,
    claims_for_tokens,
    copied_claims,
    decode_own_token,
    initial_refresh_expiry,
    mint_access_token,
    mint_refresh_token,
    rotated_expiry,
)

router = APIRouter()

# The token type every issued access token is presented as.
_BEARER = "Bearer"

# The grants this endpoint performs.
_AUTHORIZATION_CODE_GRANT = "authorization_code"
# Triaged, not silenced: the RFC 6749 grant type name, which is the value a client sends
# in its request, not a credential (bandit B105 triaged in place).
_REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105  # nosec B105

# The refusal for a resource that is missing or is not the one a code was issued for. One
# description covers both because they are one problem: the request does not identify the
# resource the token is for.
_INVALID_TARGET_DESCRIPTION = (
    "the `resource` parameter must be present and must match the one the authorization "
    "request named"
)

# The refusal for a refresh token that cannot be used: unknown, expired, revoked, or bound
# to something else. RFC 6749 gives one code for all of them, and separating them would
# report which of the four a caller hit to someone who may hold none of them legitimately.
_INVALID_GRANT_DESCRIPTION = (
    "the refresh token is not valid; it may have expired, been revoked, or been replaced "
    "by a rotation. Start the sign-in again from your tool."
)

# The refusal the refresh grant gives when the claims re-read could not complete: the
# provider was unreachable, answered unusably, or refused the grant for a reason other than
# `invalid_grant`. The client's action is the same as any other invalid_grant refusal — start
# the sign-in again — so the description is the same one; only the audit token differs.
_CLAIMS_READ_FAILED_DESCRIPTION = (
    "the gateway could not read your current access rights, so it refused to issue a token "
    "from stale ones. Start the sign-in again from your tool."
)

# The refusal the refresh grant gives when the identity provider has ended the session.
_GRANT_SESSION_ENDED_DESCRIPTION = (
    "your sign-in session at the identity provider has ended; start the sign-in again from "
    "your tool."
)

# The refusal the refresh grant gives when the carried custody claim cannot be used — absent
# (a token minted before this gateway carried one), tampered, under an unknown key or
# version, expired, or bound to another subject.
_CUSTODY_FAILED_DESCRIPTION = (
    "this refresh token's carried credentials cannot be read; it was issued before the "
    "gateway's current custody key, or it has been altered. Start the sign-in again from "
    "your tool."
)

# The refusal the code grant gives when the pending hand-off entry it must seal is gone:
# absent (a code issued before a restart dropped the entry, or one whose entry has expired),
# or already consumed. The gateway's own custody fault, like the refresh grant's — it names
# no provider state and no client mistake — so it audits under the same class.
_CODE_CUSTODY_FAILED_DESCRIPTION = (
    "the gateway could not recover this sign-in's credentials, so it refused to issue a "
    "token that could not be refreshed. Start the sign-in again from your tool."
)

# The three named refusal classes the refresh grant's `invalid_grant` refusals audit under,
# so the closed reason table can tell a custody fault from a provider outage from a session
# end. Committed in `_REFUSAL_REASONS` below with the guard classes.
CUSTODY_DECRYPT_FAILED = "custody_decrypt_failed"
CLAIMS_READ_FAILED = "claims_read_failed"
IDP_SESSION_ENDED = "idp_session_ended"

# The content type every OAuth client posts a token request as. A request in any other
# form is refused rather than guessed at: the parameters of a token request include values
# that must not be taken from a shape the client did not intend.
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

# The refusal both endpoints answer when the caller is over the limit. One sentence,
# because the two endpoints' readers are the same OAuth client library and the available
# action is the same either way.
_TOO_MANY_REQUESTS = "too many token requests from this source; try again in a minute"


# The audit trail's fixed token for each refusal this endpoint can answer with. The
# mapping is closed and one-directional: a refusal's error code — together with its named
# refusal class where a class must be distinguishable — always lands on one of these
# tokens, so the log's vocabulary is a property of this table rather than of any message a
# refusal happened to carry. The key is the OAuth error code plus the optional named class,
# because the code alone cannot separate the several distinct refusals that share
# `invalid_target` (the request-time name guard's classes) or `invalid_grant` (the refresh
# grant's three failure classes). Every token a refusal can take is committed here; an
# unmapped key raises at the first such refusal, in a test, rather than logging an
# unrecognized token.
_REFUSAL_REASONS: dict[tuple[str, str | None], str] = {
    (errors.INVALID_REQUEST, None): "invalid_token_request",
    (errors.INVALID_GRANT, None): "invalid_grant",
    (errors.INVALID_TARGET, None): "invalid_target",
    (errors.UNSUPPORTED_GRANT_TYPE, None): "unsupported_grant_type",
    # The request-time path guard's refusal classes, all answered as `invalid_target`,
    # each landing on its own committed token. The toolset classes and the app classes
    # share this table because the authorization and refresh grants resolve both shapes.
    (errors.INVALID_TARGET, INVALID_RESOURCE_PATH): INVALID_RESOURCE_PATH,
    (errors.INVALID_TARGET, RESERVED_PATH_SEGMENT): RESERVED_PATH_SEGMENT,
    (errors.INVALID_TARGET, RESTRICTED_TOOLSET): RESTRICTED_TOOLSET,
    (errors.INVALID_TARGET, RESTRICTED_APP): RESTRICTED_APP,
    # The `invalid_grant` refusal classes, each its own token so a custody fault, a provider
    # outage or misconfiguration, and a session end are distinguishable on the trail — none
    # of them reads as mass token revocation. `custody_decrypt_failed` is the gateway's own
    # custody fault on both grants: the refresh grant's unusable carried claim and the code
    # grant's missing pending entry are the same class because they are the same fault.
    (errors.INVALID_GRANT, CUSTODY_DECRYPT_FAILED): CUSTODY_DECRYPT_FAILED,
    (errors.INVALID_GRANT, CLAIMS_READ_FAILED): CLAIMS_READ_FAILED,
    (errors.INVALID_GRANT, IDP_SESSION_ENDED): IDP_SESSION_ENDED,
}


class TokenRequestError(Exception):
    """A request refused before any token was minted.

    Carries the RFC 6749 error code, the description to hand the client, and the status to
    answer with. The description is always fixed text chosen here, so a refusal cannot
    reflect a caller-supplied string back out.

    `refusal_class` names the refusal subclass where several share one error code and the
    operator's trail must tell them apart — the name guard's three classes, for instance.
    It selects the audit token from the closed table and is never rendered to the client.
    """

    def __init__(
        self,
        error: str,
        description: str,
        status_code: int = 400,
        *,
        refusal_class: str | None = None,
    ) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code
        self.refusal_class = refusal_class

    @property
    def reason(self) -> str:
        """The audit trail's token for this refusal, from the closed table above.

        A key outside the table is a programming mistake rather than a value to log
        silently, so the lookup is allowed to raise: it would surface at the first refusal
        of that class, in a test, rather than as an unrecognized token in the operator's log.
        """
        return _REFUSAL_REASONS[(self.error, self.refusal_class)]


@router.post("/dial/token")
async def token(request: Request) -> Response:
    """Redeem an authorization code or a refresh token for tokens.

    The form body is parsed here rather than declared as typed parameters, so that a
    missing or malformed parameter is answered as the RFC 6749 error a client's OAuth
    library understands, rather than as a framework's own validation response — a
    distinction a client's error handling actually depends on.
    """
    runtime: Runtime = request.app.state.runtime
    if not runtime.limiter.allow(errors.client_source(request)):
        # Bounded before any work: this endpoint is unauthenticated and every request that
        # reaches validation costs at least one RSA verification, so the count is the thing
        # that keeps a flood from becoming a CPU-exhaustion path.
        runtime.audit.flow_refused("rate_limited")
        return errors.oauth_error(
            errors.TEMPORARILY_UNAVAILABLE, _TOO_MANY_REQUESTS, status_code=429
        )

    parameters: dict[str, str] = {}
    try:
        parameters = await _form_parameters(request, runtime.settings)
        return await _grant(runtime, parameters)
    except TokenRequestError as refusal:
        runtime.audit.flow_refused(
            refusal.reason,
            client_id=parameters.get("client_id"),
            redirect_uri=parameters.get("redirect_uri"),
            resource=parameters.get("resource"),
        )
        return errors.oauth_error(
            refusal.error, refusal.description, status_code=refusal.status_code
        )


async def _grant(runtime: Runtime, parameters: dict[str, str]) -> Response:
    """Dispatch a token request to the grant it names, or refuse the name.

    Unknown grants are `unsupported_grant_type` rather than `invalid_request`, because the
    request is well formed and the client's library is reporting a flow this server does
    not implement — a distinction a client's error handling acts on.
    """
    grant_type = parameters.get("grant_type")
    if not grant_type:
        raise TokenRequestError(errors.INVALID_REQUEST, "grant_type is required")
    if grant_type == _AUTHORIZATION_CODE_GRANT:
        return _code_grant(runtime, parameters)
    if grant_type == _REFRESH_TOKEN_GRANT:
        return await _refresh_grant(runtime, parameters)
    raise TokenRequestError(
        errors.UNSUPPORTED_GRANT_TYPE,
        f"grant_type must be {_AUTHORIZATION_CODE_GRANT} or {_REFRESH_TOKEN_GRANT}",
    )


# --------------------------------------------------------------- the code grant


def _code_grant(runtime: Runtime, parameters: dict[str, str]) -> Response:
    """Redeem an authorization code for an access token and a refresh token."""
    claim = _validated_claim(runtime, parameters)
    settings = runtime.settings

    # The claim snapshot the code carries is the access token's claim source here: the code's
    # own short TTL is its freshness bound, as before. The refresh token, by contrast, gets
    # no snapshot — its one non-binding member is the custody claim below.
    snapshot = claims_for_tokens(claim.payload)
    access_token = mint_access_token(
        runtime.signing_key,
        settings,
        claims=snapshot,
        resource=claim.resource,
        ttl_seconds=settings.gateway_access_token_ttl_seconds,
    )
    # The provider's session refresh token was held in the pending entry keyed by this code's
    # id, because the code cannot carry it — a code is a signed-but-unencrypted JWT whose
    # payload anyone holding the string can read. It is consumed here and sealed into the
    # issued refresh token, so it exists only in the process and, encrypted, in the token the
    # client receives. An entry that is absent refuses the whole grant: see
    # `_sealed_custody_claim`.
    expires_at = initial_refresh_expiry(settings)
    custody_claim = _sealed_custody_claim(runtime, claim, expires_at=expires_at)
    # The refresh token's id is named here rather than left to the mint, so it can be
    # recorded against the code that bought it: a later replay of this code (the memo's
    # claim fails) denylists exactly this token, which is the revoke-on-double-redemption
    # rule. The record is bounded by the replay memo's own TTL — the code's life, past
    # which no replay is detectable — while the denylist entry it produces lives to the
    # token's expiry, the retention that matters.
    refresh_jti = new_token_id()
    refresh_token = mint_refresh_token(
        runtime.signing_key,
        settings,
        subject=claim.subject,
        resource=claim.resource,
        client_id=claim.client_id,
        expires_at=expires_at,
        custody_claim=custody_claim,
        token_id=refresh_jti,
    )
    runtime.replay.record_token_id(
        claim.code_id, refresh_jti, expires_at=float(expires_at)
    )
    runtime.audit.token_issued(
        subject=claim.subject, client_id=claim.client_id, resource=claim.resource
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": _BEARER,
            "expires_in": settings.gateway_access_token_ttl_seconds,
            "refresh_token": refresh_token,
            # The gateway enforces no scopes of its own, so the granted set is empty
            # rather than a set it would then have to justify.
            "scope": "",
        },
        headers=_NO_STORE,
    )


def _sealed_custody_claim(
    runtime: Runtime, claim: _ValidatedClaim, *, expires_at: int
) -> str:
    """The provider token sealed into a custody claim, or a custody refusal.

    The provider refresh token is read from the pending entry the flow left under this code's
    id and consumed here — a code is redeemed once, so its carried provider token is sealed
    into exactly one refresh token.

    A pending entry that is absent refuses the grant: no pending entry means no mint. The two
    ways to find none are the restart (the memory-only entry went with the process) and the
    already-consumed or expired entry (a stale or replayed code), and both leave this grant
    holding no provider credential. A refresh token minted without custody could never be
    refreshed, so it is a session born dead — issuing it would defer the fail-closed refusal
    to its first refresh, and the fail-closed rule pins the refusal here, at the grant, where
    the client is still in a sign-in it can restart. The fault is the gateway's own — never a
    provider event and never the client's — so it audits under the custody refusal class.

    The envelope binds the provider token to the refresh token's signed subject and to the
    same absolute expiry, so a blob moved to another user's token or kept past the window
    refuses at the custody seam.
    """
    provider_refresh_token = runtime.pending_custody.take(claim.code_id)
    if provider_refresh_token is None:
        raise TokenRequestError(
            errors.INVALID_GRANT,
            _CODE_CUSTODY_FAILED_DESCRIPTION,
            refusal_class=CUSTODY_DECRYPT_FAILED,
        )
    return runtime.custody_keyset.encrypt(
        subject=claim.subject,
        expires_at=expires_at,
        token=provider_refresh_token,
    )


class _ValidatedClaim:
    """What a redeemed code establishes: who the token is for, and for what resource."""

    __slots__ = ("client_id", "code_id", "payload", "resource", "subject")

    def __init__(
        self,
        *,
        client_id: str,
        code_id: str,
        subject: str,
        resource: str,
        payload: dict[str, object],
    ) -> None:
        self.client_id = client_id
        self.code_id = code_id
        self.subject = subject
        self.resource = resource
        self.payload = payload


def _validated_claim(runtime: Runtime, parameters: dict[str, str]) -> _ValidatedClaim:
    """Validate a code redemption's every binding, or refuse it.

    The order of the checks is deliberate: the cheapest and the most general first, then
    the code's own signature and lifetime, then each binding the code carries, and the
    single-use claim last — so a code is never marked used on a request that was going to
    fail anyway.
    """
    code_value = _present(parameters, "code")
    redirect_uri_value = _present(parameters, "redirect_uri")
    client_id_value = _present(parameters, "client_id")
    verifier = _present(
        parameters,
        "code_verifier",
        "every client here is a public PKCE client, so the verifier is always required",
    )
    # Checked before the code is decoded, so a request that names no resource is answered
    # the same way whatever code it carries. Absent and mismatched are the same refusal
    # because they are the same problem: the request does not say which resource it is for,
    # so a token issued for it would be addressed to one the client never named.
    resource_value = parameters.get("resource")
    if not resource_value:
        raise TokenRequestError(errors.INVALID_TARGET, _INVALID_TARGET_DESCRIPTION)

    try:
        payload = decode_code(
            runtime.signing_keyset,
            code_value,
            runtime.settings.gateway_public_origin,
        )
    except CodeError as exc:
        raise TokenRequestError(errors.INVALID_GRANT, str(exc)) from exc

    if payload.get("client_id") != client_id_value:
        raise TokenRequestError(
            errors.INVALID_GRANT, "this authorization code was issued to another client"
        )
    if payload.get("redirect_uri") != redirect_uri_value:
        raise TokenRequestError(
            errors.INVALID_GRANT,
            "this authorization code was issued for another redirect_uri",
        )

    code_resource = str(payload.get("resource", ""))
    # Canonical-vs-canonical: the offered spelling is canonicalized before the match, so a
    # client that redeems its code with a non-canonical spelling of the same resource is
    # accepted — the code's own `resource` is the canonical identity the flow recorded.
    canonical_offered = runtime.settings.canonical_resource_uri(resource_value)
    if canonical_offered is None or canonical_offered != code_resource:
        raise TokenRequestError(errors.INVALID_TARGET, _INVALID_TARGET_DESCRIPTION)

    challenge = str(payload.get("code_challenge", ""))
    method = str(payload.get("code_challenge_method", ""))
    if not verify_pkce(verifier, challenge, method):
        raise TokenRequestError(
            errors.INVALID_GRANT,
            "the code_verifier does not match the code_challenge the authorization "
            "request presented",
        )

    code_identifier = str(payload.get("jti", ""))
    subject = str(payload.get("sub", ""))
    if not code_identifier or not subject:
        raise TokenRequestError(
            errors.INVALID_GRANT, "the authorization code is not valid"
        )
    if not runtime.replay.claim(code_identifier):
        # Single use is what makes an intercepted code worthless to a second redeemer, and
        # the PKCE binding already makes it worthless to anyone without the verifier — but
        # only one of the two is observable here, so both are enforced. The detection is
        # also where revoke-on-double-redemption lands: the memo recorded the refresh token
        # the first redemption minted against this code's id, so the replay denylists that
        # token — the replayed flow's token family dies at the token's next presentation,
        # rather than surviving to its own expiry.
        _revoke_the_tokens_this_code_bought(runtime, code_identifier)
        raise TokenRequestError(
            errors.INVALID_GRANT, "this authorization code has already been used"
        )

    return _ValidatedClaim(
        client_id=client_id_value,
        code_id=code_identifier,
        subject=subject,
        resource=code_resource,
        payload=payload,
    )


def _revoke_the_tokens_this_code_bought(runtime: Runtime, code_id: str) -> None:
    """Denylist the refresh token a replayed code's first redemption minted.

    RFC 9700 §4.2.4 asks the AS to revoke the tokens a doubly-redeemed code bought. As
    built the replay was already refused, but the first redemption's tokens stayed live —
    nothing connected the code's id to what it bought. The replay memo carries that
    connection now (the code grant records the minted refresh token's id against the code),
    so the detected replay makes one `TokenDenylist.revoke` call: the same call `/dial/revoke`
    makes, on the existing store, with no new surface. The next presentation of that token
    refuses `invalid_grant` through the denylist consult every refresh grant already runs.

    Two bounds are the clause's own and are not closed here, deliberately: the access token
    the first redemption minted is a bearer token with a short TTL and stays unrevocable by
    design (RFC 9700's SHOULD tolerates exactly this); and a refresh token that already
    rotated before the replay was detected survives, because rotation mints a fresh id and
    no code-to-successor mapping exists — closing that half would make the memo track the
    rotation chain, which is the known extension the rule records and does not build.
    """
    token_id = runtime.replay.claimed_token_id(code_id)
    if token_id is None:
        # A code whose redemption recorded no token bought none (it failed at the custody
        # seam, or predates this rule): there is nothing to revoke, and the replay refusal
        # stands on its own.
        return
    expiry = runtime.replay.claimed_token_expiry(code_id)
    runtime.denylist.revoke(
        token_id, expires_at=expiry if expiry is not None else time.time()
    )


# ------------------------------------------------------------ the refresh grant


async def _refresh_grant(runtime: Runtime, parameters: dict[str, str]) -> Response:
    """Exchange a refresh token for a fresh access token, re-reading the claims.

    The validation ladder runs first and unchanged: signature and type, denylist, resource,
    the name guard on the token's own resource, the subject, and the client. Only then does
    the grant touch the custody claim and reach the identity provider — a request failing
    validation spends no outbound call.

    The claims the minted access token carries come from the fresh verified token the
    provider's refresh grant returns, never from a snapshot: the gateway's refresh token
    carries none, so a stale-snapshot mint is structurally impossible. Every failure of the
    read refuses `invalid_grant` with no fallback, and the three failure classes audit apart.
    """
    settings = runtime.settings
    validated = _validated_refresh_claim(runtime, parameters)
    subject = validated.subject

    # The custody claim is decrypted behind the validation ladder, at the one seam that
    # reads it, and every way the seam can fail is the gateway's own fault class: a
    # token minted before this change carries no claim, and a tampered, expired, unknown-key,
    # or subject-mismatched one is the same refusal to the client and the same distinct
    # audit token to the operator.
    provider_refresh_token = _decrypt_custody_claim(
        runtime, validated.payload, subject=subject
    )

    # The provider's refresh grant: the claims re-read.
    fresh_claims, new_provider_token = await _fresh_claims(
        runtime, provider_refresh_token, subject=subject
    )

    # The copy and the roles overlay run on the fresh claims, through the same functions
    # issuance uses; an absent roles path refuses here exactly as it does at issuance.
    try:
        fresh_snapshot = copied_claims(fresh_claims, settings)
    except IssuanceError as exc:
        raise _claims_read_refusal() from exc

    access_token = mint_access_token(
        runtime.signing_key,
        settings,
        claims=fresh_snapshot,
        resource=validated.resource,
        ttl_seconds=settings.gateway_access_token_ttl_seconds,
    )
    body: dict[str, object] = {
        "access_token": access_token,
        "token_type": _BEARER,
        "expires_in": settings.gateway_access_token_ttl_seconds,
        "scope": "",
    }
    _apply_rotation(
        runtime,
        validated,
        body,
        presented=parameters["refresh_token"],
        provider_refresh_token=new_provider_token or provider_refresh_token,
    )
    runtime.audit.token_refreshed(
        subject=subject, client_id=validated.client_id, resource=validated.resource
    )
    return JSONResponse(body, headers=_NO_STORE)


class _ValidatedRefresh:
    """What a validated refresh request establishes."""

    __slots__ = ("client_id", "payload", "resource", "subject", "token_id")

    def __init__(
        self,
        *,
        client_id: str,
        payload: dict[str, object],
        resource: str,
        subject: str,
        token_id: str,
    ) -> None:
        self.client_id = client_id
        self.payload = payload
        self.resource = resource
        self.subject = subject
        self.token_id = token_id


def _validated_refresh_claim(
    runtime: Runtime, parameters: dict[str, str]
) -> _ValidatedRefresh:
    """Run the refresh grant's validation ladder, or refuse.

    The order is the code grant's: the signature and type, then the denylist, the resource
    and its name guard, the subject, and the client. Emptying this into one function keeps
    the grant's own body readable as the sequence of the read, the mint, and the rotation.
    """
    settings = runtime.settings
    refresh_token = _present(parameters, "refresh_token")
    try:
        payload = decode_own_token(
            runtime.signing_keyset,
            refresh_token,
            issuer=settings.gateway_public_origin,
            expected_type=REFRESH_TOKEN_TYPE,
        )
    except TokenError as exc:
        raise TokenRequestError(
            errors.INVALID_GRANT, _INVALID_GRANT_DESCRIPTION
        ) from exc

    token_id = str(payload.get("jti", ""))
    if not token_id or runtime.denylist.is_revoked(token_id):
        raise TokenRequestError(errors.INVALID_GRANT, _INVALID_GRANT_DESCRIPTION)

    # The resource must match the one the refresh token was minted for, and the match is
    # canonical-vs-canonical: the presented spelling is canonicalized so two spellings of
    # one resource cannot re-key the match, and the token's own `resource` is the canonical
    # identity the flow recorded. One flat authorization server serves both resource kinds,
    # so a refresh that named a different resource would be asking for a token addressed
    # somewhere the original flow never approved — the same check the code grant makes.
    resource = str(payload.get("resource", ""))
    presented = parameters.get("resource")
    if not presented:
        raise TokenRequestError(errors.INVALID_TARGET, _INVALID_TARGET_DESCRIPTION)
    canonical_presented = settings.canonical_resource_uri(presented)
    if canonical_presented is None or canonical_presented != resource:
        raise TokenRequestError(errors.INVALID_TARGET, _INVALID_TARGET_DESCRIPTION)

    # The refresh grant's resource-to-path resolution, guarded exactly as every other
    # path-resolution site is. The resource's shape names its kind, and the guard of that
    # kind applies: a toolset-shaped resource passes the toolset guard, an app-shaped one
    # the app guard. A path the guard refuses here is one no flow could ever have issued a
    # token for; guard failures answer `invalid_target` like the mismatch above, with their
    # own committed reason token.
    resolved = settings.resource_kind_and_path(resource)
    if resolved is not None:
        kind, refresh_path = resolved
        refusal = (
            settings.toolset_guard_refusal(refresh_path)
            if kind == "toolset"
            else settings.app_guard_refusal(refresh_path)
        )
        if refusal is not None:
            raise TokenRequestError(
                errors.INVALID_TARGET,
                _INVALID_TARGET_DESCRIPTION,
                refusal_class=refusal,
            )

    subject = str(payload.get("sub", ""))
    client_id = str(payload.get("client_id", ""))
    if not subject:
        raise TokenRequestError(errors.INVALID_GRANT, _INVALID_GRANT_DESCRIPTION)

    # RFC 6749 §6: a client that presents `client_id` must present its own. Nothing else
    # at this endpoint binds the request to the client the refresh token was minted for —
    # the token itself is the only credential here — so a request naming another client is
    # refused rather than served. A client that names none is not refused: the parameter is
    # optional in the grant, and the token's own `client_id` is what the fresh tokens carry.
    presented_client_id = parameters.get("client_id")
    if presented_client_id and presented_client_id != client_id:
        raise TokenRequestError(
            errors.INVALID_GRANT, "this refresh token was issued to another client"
        )

    return _ValidatedRefresh(
        client_id=client_id,
        payload=payload,
        resource=resource,
        subject=subject,
        token_id=token_id,
    )


async def _fresh_claims(
    runtime: Runtime, provider_refresh_token: str, *, subject: str
) -> tuple[dict[str, object], str | None]:
    """Run the provider's refresh grant and verify its fresh token, or refuse.

    Two failure classes are separated here, both answered to the client as
    `invalid_grant`: the provider's `invalid_grant` (the session is gone —
    `idp_session_ended`) and everything else (unreachable, unusable, unverifiable, or a
    subject the provider did not re-assert — `claims_read_failed`). The subject cross-check
    keeps no provider answer alone from moving the mint to another principal.
    """
    try:
        fresh_token, new_provider_token = await runtime.idp.refresh_identity(
            provider_refresh_token
        )
        fresh_claims = await runtime.idp.verified_claims(fresh_token)
    except RefreshGrantError as exc:
        if exc.session_ended:
            raise TokenRequestError(
                errors.INVALID_GRANT,
                _GRANT_SESSION_ENDED_DESCRIPTION,
                refusal_class=IDP_SESSION_ENDED,
            ) from exc
        raise _claims_read_refusal() from exc
    except IdentityProviderError as exc:
        raise _claims_read_refusal() from exc

    if str(fresh_claims.get("sub", "")) != subject:
        raise _claims_read_refusal()
    return fresh_claims, new_provider_token


def _claims_read_refusal() -> TokenRequestError:
    """The `invalid_grant` refusal every non-session-ended failure of the read lands on."""
    return TokenRequestError(
        errors.INVALID_GRANT,
        _CLAIMS_READ_FAILED_DESCRIPTION,
        refusal_class=CLAIMS_READ_FAILED,
    )


def _apply_rotation(
    runtime: Runtime,
    validated: _ValidatedRefresh,
    body: dict[str, object],
    *,
    presented: str,
    provider_refresh_token: str,
) -> None:
    """Rotate the gateway refresh token, re-encrypting the provider's latest token.

    Where the provider rotated its own refresh token, the replacement carries the newest one
    (latest-wins); where it did not, the one just used is re-sealed. The blob's embedded
    expiry is the token's own non-sliding absolute expiry, so a grace-window presentation of
    a pre-rotation token carries its own stale blob and fails at the provider where the
    provider rotates per grant. With rotation off, the presented token is returned unchanged
    — valid only on a provider that does not rotate per grant.
    """
    settings = runtime.settings
    if not settings.gateway_rotate_refresh_tokens:
        body["refresh_token"] = presented
        return

    original_expiry = _int_claim(validated.payload.get("exp"))
    body["refresh_token"] = mint_refresh_token(
        runtime.signing_key,
        settings,
        subject=validated.subject,
        resource=validated.resource,
        client_id=validated.client_id,
        # The original absolute expiry, frozen at the first issuance: rotation must never
        # extend the window, so a rotated token inherits the end of the window.
        expires_at=rotated_expiry(original_expiry),
        custody_claim=runtime.custody_keyset.encrypt(
            subject=validated.subject,
            expires_at=rotated_expiry(original_expiry),
            token=provider_refresh_token,
        ),
    )
    if not runtime.denylist.in_rotation_grace(validated.token_id):
        # Recorded only on the first rotation. A second request that raced this one and lost
        # gets the same treatment but does not restart the grace window, so a client cannot
        # hold one token's window open by replaying it.
        runtime.denylist.rotate(
            validated.token_id,
            expires_at=float(original_expiry),
            grace_seconds=settings.gateway_rotation_grace_seconds,
        )
    body["rotation_expires_in"] = max(0, original_expiry - int(time.time()))


def _decrypt_custody_claim(
    runtime: Runtime, payload: dict[str, object], *, subject: str
) -> str:
    """The provider refresh token sealed in a presented refresh token, or a custody refusal.

    Every way the seam can fail lands on the one custody refusal class, distinct from both
    provider failure classes: a claim that is absent (a token minted before this change),
    not a string, malformed, tampered, under an unknown key id or version, expired, or bound
    to another subject. A custody-key mistake or a botched rotation is therefore never
    readable on the trail as a provider event.
    """
    custody_claim = payload.get(CUSTODY_CLAIM_MEMBER)
    if not isinstance(custody_claim, str) or not custody_claim:
        raise TokenRequestError(
            errors.INVALID_GRANT,
            _CUSTODY_FAILED_DESCRIPTION,
            refusal_class=CUSTODY_DECRYPT_FAILED,
        )
    try:
        return runtime.custody_keyset.decrypt(custody_claim, subject=subject)
    except CustodyError as exc:
        raise TokenRequestError(
            errors.INVALID_GRANT,
            _CUSTODY_FAILED_DESCRIPTION,
            refusal_class=CUSTODY_DECRYPT_FAILED,
        ) from exc


# ----------------------------------------------------------------- revocation


@router.post("/dial/revoke")
async def revoke(request: Request) -> Response:
    """Revoke a refresh token, by denylisting its id until the token would expire.

    RFC 7009 semantics, in both directions. A request naming no `token` parameter is
    `invalid_request` (§2.1 makes the parameter required), while a request that names one
    — whether or not this gateway issued it, whether or not it is live, and whether it is
    an access token rather than a refresh token — is answered with the same **empty 200**.
    The uniformity is the point: a response that reported whether anything was actually
    revoked would make this endpoint an oracle for whether a token a caller holds is real,
    which is the question an attacker holding a stolen token is asking.

    Only refresh tokens are revocable — an access token is a bearer string this service
    does not track, and it dies within its own short lifetime, which is the bound the
    access TTL exists to provide.
    """
    runtime: Runtime = request.app.state.runtime
    if not runtime.limiter.allow(errors.client_source(request)):
        runtime.audit.flow_refused("rate_limited")
        return errors.oauth_error(
            errors.TEMPORARILY_UNAVAILABLE, _TOO_MANY_REQUESTS, status_code=429
        )

    try:
        parameters = await _form_parameters(request, runtime.settings)
    except TokenRequestError as refusal:
        # The form itself is what failed, so there are no request facts to record: the
        # refusal's own token is the whole report, and no parameter was parsed to carry.
        runtime.audit.flow_refused("invalid_revocation_request")
        return errors.oauth_error(
            refusal.error, refusal.description, status_code=refusal.status_code
        )

    token_value = parameters.get("token")
    if not token_value:
        # RFC 7009 §2.1 requires the parameter, and a request that names no token is not
        # probing one — so it earns the malformed-request refusal rather than the uniform
        # 200. Saying so is not an oracle: it reports the shape of the request, not the
        # state of any token. The route taken before this point (a missing parameter
        # answered as an empty 200) told a client its revocation had succeeded when
        # nothing had been revoked and nothing could have been.
        runtime.audit.flow_refused("missing_revocation_token")
        return errors.oauth_error(
            errors.INVALID_REQUEST,
            "the `token` parameter is required: it names the refresh token to revoke",
        )

    try:
        payload = decode_own_token(
            runtime.signing_keyset,
            token_value,
            issuer=runtime.settings.gateway_public_origin,
            expected_type=REFRESH_TOKEN_TYPE,
        )
    except TokenError:
        payload = None
    if payload is not None:
        token_id = str(payload.get("jti", ""))
        expires_at = payload.get("exp")
        if token_id and isinstance(expires_at, (int, float)):
            runtime.denylist.revoke(token_id, expires_at=float(expires_at))
            runtime.audit.token_revoked(token_id=token_id)

    # An empty 200, per RFC 7009 §2.2: no body, because a body could only say whether a
    # token existed, and that is the oracle the uniform answer exists to close.
    return Response(status_code=200, headers=_NO_STORE)


# ------------------------------------------------------------------- plumbing


async def _form_parameters(request: Request, settings: Settings) -> dict[str, str]:
    """Parse a token or revocation request's form body into its parameters.

    The body is read under a byte cap *while it is read*, not after: this endpoint is
    unauthenticated and takes a body, so a request that is merely large must cost the
    gateway a bounded amount of memory rather than however much its sender chose. A token
    request is a handful of short parameters, so the cap is a generous multiple of real
    traffic; a body past it is refused whole rather than parsed in part, since a form
    whose meaning depends on which parameters survived truncation has no meaning to
    validate.

    A parameter that appears more than once is refused rather than resolved by picking one:
    two different parsers can read two different values from a repeated parameter, and a
    request whose meaning depends on the parser has no single meaning to validate.
    """
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != _FORM_CONTENT_TYPE:
        raise TokenRequestError(
            errors.INVALID_REQUEST,
            f"the request body must be sent as {_FORM_CONTENT_TYPE}",
        )

    raw = await capped_body(request, settings.gateway_form_max_body_bytes)
    if raw is None:
        raise TokenRequestError(
            errors.INVALID_REQUEST,
            f"the request body is larger than the "
            f"{settings.gateway_form_max_body_bytes} bytes this gateway accepts",
        )
    body = raw.decode("utf-8", errors="replace")
    parameters: dict[str, str] = {}
    for name, value in parse_qsl(body, keep_blank_values=True):
        if name in parameters:
            raise TokenRequestError(
                errors.INVALID_REQUEST, f"the parameter {name} appears more than once"
            )
        parameters[name] = value
    return parameters


def _int_claim(value: object) -> int:
    """An integer claim, read defensively.

    The payload is this gateway's own signed output, so the value is one of ours — but a
    claim read into an arithmetic expression is exactly where a wrong shape would surface
    as a crash on a live request, so the shape is stated rather than assumed.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TokenRequestError(errors.INVALID_GRANT, _INVALID_GRANT_DESCRIPTION)
    return int(value)


def _present(parameters: dict[str, str], name: str, because: str = "") -> str:
    """A required request parameter, present and non-empty, or a refusal naming it."""
    value = parameters.get(name)
    if not value:
        detail = f"{name} is required"
        if because:
            detail = f"{detail}: {because}"
        raise TokenRequestError(errors.INVALID_REQUEST, detail)
    return value


_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
