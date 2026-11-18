"""Authorization codes and PKCE verification.

The authorization code carries its whole binding inside itself: it names the client, the
redirect URI, the PKCE challenge, the addressed resource (a toolset or an app), and the
subject. Nothing about it is looked
up in server state, so the token endpoint's validation is a signature check plus the
bindings the code itself states — which is also why a code is useless to anyone but the
client it was issued to, even inside its short life.

The verifier never leaves the client. The gateway stores only the challenge, computes the
transformation from the presented verifier, and compares — the same shape Core uses for
the upstream leg, and the reason a code intercepted in transit establishes nothing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

import jwt
from jwt import exceptions as jwt_exceptions

from gateway.keys import SigningKey, SigningKeyset
from gateway.state import new_token_id

# The claim that marks this token as an authorization code rather than an access or
# refresh token. All three are signed by the same key, so the type is what stops one from
# being presented where another belongs.
# The `# nosec B105` is a triage, not a silence: the value is a token type name that
# appears in RFC 6749 and in the tokens themselves, and no credential is involved.
CODE_TOKEN_TYPE = "code"  # noqa: S105  # nosec B105

# PKCE S256 is the only method the gateway advertises, so it is the only one accepted.
S256 = "S256"


class CodeError(Exception):
    """A code that cannot be issued or redeemed, with a client-safe message."""


class CodeBindings:
    """Everything an authorization code binds, as one object.

    Passed as a single argument rather than as eleven parameters: the bindings belong
    together — they are exactly what a redemption has to match — and a signature that
    takes them one by one makes it easy to pass the right values in the wrong order.

    `toolset` carries the addressed resource's name, of either kind: it keeps the
    kind-specific spelling but not that meaning — an app-kind flow binds the app's name here.
    """

    __slots__ = (
        "claims",
        "client_id",
        "code_challenge",
        "code_challenge_method",
        "redirect_uri",
        "resource",
        "subject",
        "toolset",
    )

    def __init__(  # noqa: PLR0913 - one parameter per binding the code must carry
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        resource: str,
        toolset: str,
        subject: str,
        claims: dict[str, object],
    ) -> None:
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.resource = resource
        self.toolset = toolset
        self.subject = subject
        self.claims = claims


def code_challenge_for(verifier: str) -> str:
    """The S256 challenge for a verifier: base64url of its SHA-256, unpadded."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    """Whether a presented verifier satisfies the challenge a code carries.

    Only S256 is accepted. `plain` is refused rather than implemented: it would put the
    verifier itself on the wire, which is the property PKCE exists to avoid.
    """
    if method != S256:
        return False
    if not verifier or not challenge:
        return False
    return hmac.compare_digest(code_challenge_for(verifier), challenge)


def issue_code(
    signing_key: SigningKey,
    bindings: CodeBindings,
    *,
    issuer: str,
    ttl_seconds: int,
    code_id: str | None = None,
) -> str:
    """Mint the authorization code a callback redirects the harness with.

    The bindings' `claims` are the identity snapshot the code carries forward — the whole
    payload the identity token held, minus the claims the gateway owns. Carrying it here
    rather than re-fetching at the token endpoint is what keeps a flow from needing the
    identity provider a second time, and what keeps the minted token independent of any
    later change at the provider.

    `code_id` is the code's `jti`, generated here when the caller does not supply one. The
    flow's caller supplies it so the same value can key the pending hand-off entry the code
    grant consumes: the code's id is the one handle both sides already agree on, and it is
    what makes the provider token's transit resolvable at redemption without the flow record
    — which by then has been destroyed.
    """
    now = int(time.time())
    payload: dict[str, object] = {
        **bindings.claims,
        "iss": issuer,
        "sub": bindings.subject,
        "typ": CODE_TOKEN_TYPE,
        "jti": code_id or new_token_id(),
        "iat": now,
        "exp": now + ttl_seconds,
        "client_id": bindings.client_id,
        "redirect_uri": bindings.redirect_uri,
        "code_challenge": bindings.code_challenge,
        "code_challenge_method": bindings.code_challenge_method,
        "resource": bindings.resource,
        # The addressed resource's name, of either kind — the field keeps the
        # kind-specific `toolset` spelling but not that meaning (an app-kind flow
        # carries the app's name).
        "toolset": bindings.toolset,
    }
    return signing_key.sign(payload)


def decode_code(keyset: SigningKeyset, code: str, issuer: str) -> dict[str, object]:
    """Verify and decode an authorization code, refusing anything not one.

    Verification selects the keyset entry the code's `kid` names — the active key or a
    retained one — under that entry's pinned algorithm, so a code minted before a rotation
    still redeems through its retained entry while the entry is published, and a code whose
    `kid` names no entry refuses as not issued by this gateway.
    """
    key = keyset.key_for_token(code)
    if key is None:
        message = "the authorization code was not issued by this gateway"
        raise CodeError(message)
    try:
        payload: dict[str, object] = jwt.decode(
            code,
            key.public_key(),
            algorithms=[key.algorithm],
            issuer=issuer,
            # The audience is the addressed resource (a toolset or an app), which is not
            # known until after decoding; `aud` is checked against the request's resource
            # by the caller.
            options={"verify_aud": False},
        )
    except jwt_exceptions.ExpiredSignatureError as exc:
        message = "the authorization code has expired; start the sign-in again"
        raise CodeError(message) from exc
    except jwt_exceptions.InvalidTokenError as exc:
        message = "the authorization code is not valid"
        raise CodeError(message) from exc

    if payload.get("typ") != CODE_TOKEN_TYPE:
        message = "the presented token is not an authorization code"
        raise CodeError(message)
    return payload
