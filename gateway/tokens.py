"""Minting and verifying the gateway's own access and refresh tokens.

Two decisions shape everything here.

**The claim copy is verbatim, minus the claims the gateway owns.** Every claim a
deployment consumes varies by deployment, and Core matches authorization rules on arbitrary
claim paths and writes analytics rows keyed on one configured claim (its value hashed by
default — `loggingKey`/`loggingSalt` with obfuscation on; unhashed claim values reach a log
only through the operator's opt-in `analytics.claimsAllowlist`, or the small fixed claim set
emitted at DEBUG level) — so an allowlist copy would be authorization policy expressed as
configuration, whose failure mode is silent: a role-less token, an unresolvable identity, or
a rule that never matches, with nothing in any log to say why. Copying the whole payload
minus a fixed registry blocklist keeps every deployment claim path working with no per-claim
configuration at all. The minted token is larger, which is the accepted price. It is not a
new exposure either: a vanilla harness holds the identity provider's own token, which
carries the same payload.

**Roles are overlaid, not copied.** After the copy, roles are re-emitted as a plain array
under the claim name Core's gateway provider entry reads, taken from a required
operator-configured path in the identity token. The overlay is `copy first, overlay
second`, so an unrelated claim that happens to be named `roles` is harmless. The two
failure modes are deliberately different: a path that is *absent* is a misconfigured
deployment and refuses issuance loudly, because a silent role-less token produces
undiagnosable 403s; a path that resolves to an *empty* value is legitimate user state and
is copied as it is.

The access token carries the copied claims; the refresh token does not carry a claim
snapshot at all. The refresh grant re-reads the claims from the identity provider's own
refresh grant and mints the access token from that verified fresh read — the refresh token's
one non-binding member is the encrypted custody claim (the provider's session refresh token,
`gateway/custody.py`), which is ciphertext and never a mint input. The frozen-snapshot
fallback therefore has no data to serve, and the rotated token keeps the *original* absolute
expiry, so rotation can never extend the window.
"""

from __future__ import annotations

import time

import jwt
from jwt import exceptions as jwt_exceptions

from gateway.keys import SigningKey, SigningKeyset
from gateway.settings import Settings
from gateway.state import new_token_id

# The token's own type claim. All three token kinds are signed by one key, so the type is
# what keeps one from being presented where another belongs.
# Triaged, not silenced: these are token type names from the RFC 6749 vocabulary, not
# credentials.
ACCESS_TOKEN_TYPE = "access"  # noqa: S105  # nosec B105
REFRESH_TOKEN_TYPE = "refresh"  # noqa: S105  # nosec B105

# The refresh token's one non-binding payload member: the encrypted custody claim (the
# provider's session refresh token). It is ciphertext, never a mint input, and its presence
# on exactly one token kind is the carrier discipline.
CUSTODY_CLAIM_MEMBER = "custody"  # nosec B105 - a claim name, not a credential

# The claims the gateway owns and therefore never copies from the identity token. Each one
# describes a property of *the token the identity provider issued* — its issuer, its
# audience, its lifetime, its key id, its nonce, its session — and carrying any of them
# into a token this gateway signs would state something false about the new token, or
# collide with a field the new token must set itself.
#
# `acr` and `auth_time` are the authentication-context pair, stripped for the same reason:
# they describe *the provider's* authentication event — its assurance level and when it
# happened — and the gateway is an OAuth 2.x server, not an OIDC provider, so it holds no
# authentication-time or assurance fact of its own to state. A provider that minted either
# into its access token would otherwise have it copied verbatim into a gateway token, where
# it would assert the provider's authentication event as a fact of this token. The mint's
# own recency facts are its `iat` and `exp`, which the mint sets itself and which are the
# honest limit of what it knows.
REGISTRY_CLAIMS: frozenset[str] = frozenset(
    {
        "iss",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "typ",
        "azp",
        "nonce",
        "at_hash",
        "c_hash",
        "acr",
        "auth_time",
        "cnf",
        "scope",
        "session_state",
        "sid",
    }
)

# The bindings a redeemed authorization code carries that must not travel into the tokens
# it is exchanged for: they describe the code, not the session it opened.
_CODE_BINDINGS: frozenset[str] = frozenset(
    {
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
        "resource",
        "toolset",
    }
)


class IssuanceError(Exception):
    """A token that must not be minted, with a message safe to show and to log.

    Raised for the deployment error the copy can surface: the configured roles path is not
    present in the identity token, which means the operator's configuration names a claim
    this identity provider does not mint.
    """

    def __init__(self, message: str, *, operator_facing: bool = False) -> None:
        super().__init__(message)
        self.operator_facing = operator_facing


class TokenError(Exception):
    """A presented token that is not a valid one of its kind."""


def resolve_claim_path(claims: dict[str, object], path: str) -> tuple[bool, object]:
    """Resolve a dotted claim path, reporting whether it was present at all.

    The two-part answer is the point: `None` alone cannot distinguish "the path is not in
    this token" (a deployment misconfiguration) from "the path resolved to an empty value"
    (a user with no roles). Traversal through a non-mapping ends as absent rather than as
    an error, because a path the token does not have is exactly what absent means.
    """
    current: object = claims
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return False, None
        current = current[segment]
    return True, current


def copied_claims(
    identity_claims: dict[str, object], settings: Settings
) -> dict[str, object]:
    """The claim set a minted token carries: the identity payload minus registry claims.

    The roles overlay is applied here rather than at each token, so the authorization
    decision the tokens carry is made once, in one place, and a refusal happens before any
    credential is handed out.

    The custody member is stripped here as it is in `claims_for_tokens`: it belongs on the
    refresh token alone, and the write side already refuses to mint it anywhere else — but a
    provider answer is an untrusted input, and one carrying a member of this name would
    otherwise be copied verbatim into the access token. Stripping it makes the carrier
    discipline structural on both the write and the copy path, not a convention of the mint
    functions.
    """
    copied = {
        name: value
        for name, value in identity_claims.items()
        if name not in REGISTRY_CLAIMS and name != CUSTODY_CLAIM_MEMBER
    }
    copied[settings.roles_claim_name] = _roles_from(identity_claims, settings)
    return copied


def _roles_from(identity_claims: dict[str, object], settings: Settings) -> list[str]:
    """The roles array, read at the configured path in the identity token.

    Absent refuses loudly. A wrong path yields a token whose roles Core cannot match, and
    the symptom is a 403 the user cannot act on and the operator cannot diagnose — the
    exact silent failure the required setting exists to prevent.
    """
    path = settings.roles_source_path
    present, resolved = resolve_claim_path(identity_claims, path)
    if not present:
        message = (
            f"roles_source_path ({path!r}) is not present in the identity token this "
            f"deployment issued, so no token can be minted with the roles Core "
            f"authorizes on. Set ROLES_SOURCE_PATH to the path this identity provider "
            f"actually mints roles at."
        )
        raise IssuanceError(message, operator_facing=True)

    if isinstance(resolved, str):
        # A single-valued claim is one role, and an empty string is no roles: the
        # provider's own representation of the same fact, not a second kind of absence.
        return [resolved] if resolved else []
    if isinstance(resolved, list):
        roles = []
        for entry in resolved:
            if not isinstance(entry, str):
                message = (
                    f"roles_source_path ({path!r}) resolves to a list holding a "
                    f"{type(entry).__name__}; every role must be a string"
                )
                raise IssuanceError(message, operator_facing=True)
            roles.append(entry)
        return roles
    if resolved is None:
        # Explicitly null is an empty value the provider chose to mint, not a missing
        # path: the user legitimately has no roles.
        return []

    message = (
        f"roles_source_path ({path!r}) resolves to a {type(resolved).__name__}; roles "
        f"must be a string or a list of strings"
    )
    raise IssuanceError(message, operator_facing=True)


def mint_access_token(
    signing_key: SigningKey,
    settings: Settings,
    *,
    claims: dict[str, object],
    resource: str,
    ttl_seconds: int,
) -> str:
    """Mint an access token carrying the copied claims, addressed to one resource.

    The audience is the resource *plus* the configured marker. The resource is what the
    token is for; the marker is what makes Core's provider entry accept a gateway-issued
    token and reject anything else that presents this issuer.
    """
    now = int(time.time())
    payload: dict[str, object] = {
        **claims,
        "iss": settings.gateway_public_origin,
        "aud": [resource, settings.gateway_audience_marker],
        "typ": ACCESS_TOKEN_TYPE,
        "jti": new_token_id(),
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return signing_key.sign(payload)


def mint_refresh_token(  # noqa: PLR0913 - signing material, config, and the bindings it carries
    signing_key: SigningKey,
    settings: Settings,
    *,
    subject: str,
    resource: str,
    client_id: str,
    expires_at: int,
    custody_claim: str | None = None,
    token_id: str | None = None,
) -> str:
    """Mint a refresh token: session bindings only, plus an absolute expiry.

    The payload carries **no claim snapshot**. Its members are the session bindings (`sub`,
    `aud`, `typ`, `jti`, `iat`, `exp`, `client_id`, `resource`) plus one non-binding member,
    the encrypted custody claim: ciphertext, never a mint input. The refresh grant's only
    claim input is the verified fresh read, so the frozen-snapshot fallback has no data to
    serve and cannot be reintroduced.

    The `aud` is the resource **alone** — the audience marker the access mint carries is
    never included. That is the token-type separation: the marker is what makes a
    gateway-issued token a Core-acceptable access token, so its absence keeps this token
    from ever being one, and with no copied claims aboard it authorizes nothing at Core's
    role-path matching even absent the marker check.

    `expires_at` is passed in rather than derived from a TTL because a rotated token must
    keep the *original* expiry — see `rotated_expiry`. A rotation that granted a fresh
    window would extend the whole carried window, and the bound would stop being a bound.

    `token_id` lets a caller name the token's `jti` in advance instead of letting the mint
    generate one. The code grant uses it to record the token id against the code that bought
    it, so a detected replay of that code can denylist the token (the revoke-on-double-
    redemption rule); every other caller leaves it `None` and the mint generates one.
    """
    now = int(time.time())
    payload: dict[str, object] = {
        "iss": settings.gateway_public_origin,
        "sub": subject,
        "aud": [resource],
        "typ": REFRESH_TOKEN_TYPE,
        "jti": token_id or new_token_id(),
        "iat": now,
        "exp": expires_at,
        "client_id": client_id,
        "resource": resource,
    }
    if custody_claim is not None:
        payload[CUSTODY_CLAIM_MEMBER] = custody_claim
    return signing_key.sign(payload)


def rotated_expiry(original_expires_at: int) -> int:
    """The expiry a rotated refresh token carries: the original one, unchanged.

    Named as a function because it is the whole non-sliding property, and a future change
    that "refreshes" the window should have to delete a function whose docstring says why
    it must not.
    """
    return original_expires_at


def initial_refresh_expiry(settings: Settings) -> int:
    """The absolute expiry a newly issued refresh token gets, frozen at issuance."""
    return int(time.time()) + settings.gateway_refresh_ttl_seconds


def claims_for_tokens(code_payload: dict[str, object]) -> dict[str, object]:
    """The claim snapshot a redeemed code carries, minus the code's own bindings.

    The code is the flow's carrier: it holds the copied claim set so the token endpoint
    needs neither the identity provider nor the flow record, and the bindings are stripped
    here rather than at issuance because they are what the redemption validates against.

    The custody member is stripped alongside the bindings and the registry claims: it rides
    the refresh token only, and a code whose payload carried one — a provider answer that
    planted it, copied into the code at issuance — must not hand it back to the access token
    the code is exchanged for.
    """
    return {
        name: value
        for name, value in code_payload.items()
        if name not in _CODE_BINDINGS
        and name not in REGISTRY_CLAIMS
        and name != CUSTODY_CLAIM_MEMBER
    }


def decode_own_token(
    keyset: SigningKeyset,
    token: str,
    *,
    issuer: str,
    expected_type: str,
) -> dict[str, object]:
    """Verify a token this gateway signed and read its claims.

    The token's `kid` selects the entry within the startup-fixed keyset — the active key or
    a retained one — and the algorithm is the selected entry's pinned one, so a token's
    header can select neither the algorithm nor any key material: an unknown `kid` (a
    removed retained entry's included) is refused as not issued by this gateway. The type is
    checked after the signature because the type claim is inside the signed payload: a token
    that verifies but is the wrong kind is a token presented where another belongs, and one
    key signs all three kinds.
    """
    key = keyset.key_for_token(token)
    if key is None:
        message = "the token was not issued by this gateway"
        raise TokenError(message)
    try:
        payload: dict[str, object] = jwt.decode(
            token,
            key.public_key(),
            algorithms=[key.algorithm],
            issuer=issuer,
            # The audience varies by token kind and is enforced against the request's
            # resource by the caller, which is where the request states what it is for.
            options={"verify_aud": False},
        )
    except jwt_exceptions.ExpiredSignatureError as exc:
        message = "the token has expired"
        raise TokenError(message) from exc
    except jwt_exceptions.InvalidTokenError as exc:
        message = "the token is not valid"
        raise TokenError(message) from exc

    if payload.get("typ") != expected_type:
        message = "the token is not one this endpoint can use"
        raise TokenError(message)
    return payload
