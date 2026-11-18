"""Server-side state: flow records, the approval registry, the replay cache, the pending
custody entries, and the rate limits.

All of it lives in memory, and that is a decision rather than an omission. A flow record's
whole life is minutes — it holds a browser's mid-flight state — so durability would buy
nothing while costing a store, and its loss is already answered plainly: the browser lands
on a page saying the sign-in session expired and to start again. A code's replay cache is
bounded by the code's own short life and by the PKCE binding that makes a replayed code
useless to anyone but its holder. The pending custody entries hold a provider refresh token
for the minutes between a flow's end and the code grant that consumes it, and their loss —
a restart — costs exactly one re-run sign-in for a code that was never redeemed. The
approval registry is the one store whose loss a user notices as a click: a restart forgets
which clients they have approved, so each re-approves once — the fail-safe direction, since
a forgotten approval re-prompts rather than skips. None of it is state whose loss needs to
be survived.

The flow identifier is a 128-bit random value, and the entropy is load-bearing: an
attacker who could guess an in-flight flow id would present their own upstream
authorization code alongside it, and whatever pairs the two would store the attacker's
credential against the victim's identity — every later call in that victim's session would
then run in the attacker's upstream workspace. Unguessable ids, the state round-trip, and
destroy-on-first-use are what make that chain impossible.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field


def new_flow_id() -> str:
    """A fresh 128-bit flow identifier, in URL-safe base64 (22 characters)."""
    return secrets.token_urlsafe(16)


def new_client_id() -> str:
    """A client id for a dynamically registered client.

    The same entropy class as a flow id: a client id is public, but it must not be
    guessable into another registrant's record.
    """
    return secrets.token_urlsafe(16)


def new_code_verifier() -> str:
    """A fresh PKCE verifier for the gateway's own identity-provider leg.

    The same entropy class as a flow id and the same reasoning: the pair is what binds the
    code the provider returns to this flow, and a verifier an attacker could guess would
    make the binding worthless.
    """
    return secrets.token_urlsafe(32)


def new_token_id() -> str:
    """A fresh token identifier, for the `jti` claim.

    A token id must not repeat across tokens: it is what makes one token addressable in
    the audit trail and distinguishable from another when a claim about it (used once, or
    revoked) is made.
    """
    return secrets.token_urlsafe(16)


@dataclass
class FlowRecord:
    """One in-flight authorization request, held server-side.

    The browser carries only the flow id; everything a later leg needs — the client, its
    redirect URI, the PKCE challenge, the toolset the resource named — lives here, so
    nothing on the client side can be edited between the legs.

    The fields past `expires_at` are filled in as the legs run and are the flow's
    credential-bearing state, which is why the record is destroyed on first use at the
    upstream callback and why nothing here is ever logged:

    * `idp_code_verifier` is the gateway's own PKCE verifier for the identity-provider leg.
      It stays server-side for the whole leg — the browser carries the challenge, never
      the verifier — and is used once, at the code exchange.
    * `identity_access_token` and `identity_claims` are what that exchange established.
      The token serves the flow's one decision step — "may this user sign in to this
      toolset, and are they already signed in?" — and its one action, the credential call,
      and is discarded when the flow ends; the claims are the snapshot every minted
      token is copied from, which is why the record exists at all.
    * `identity_refresh_token` is the provider's session-bound refresh token, captured at
      the same exchange. It is the flow's most powerful credential and never reaches the
      client: at flow end it moves into the pending hand-off entry, the record drops it, and
      the code grant seals it, encrypted, into the issued refresh token.
    """

    flow_id: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    resource: str
    # The addressed resource's name, of either kind (its kind is `resource_kind` beside it).
    # The field keeps the kind-specific `toolset` spelling, but not that meaning: an
    # app-kind flow stores the app's name here.
    toolset: str
    resource_kind: str
    client_name: str | None
    client_source: str
    state: str | None
    created_at: float
    expires_at: float

    # The gateway's own PKCE pair for the identity-provider leg. The verifier never leaves
    # the process; `idp_state` is the flow id, round-tripped by the provider. Both credential
    # fields below are `repr=False`: a flow record reaching a debug dump or a traceback must
    # not print a provider credential.
    idp_code_verifier: str | None = field(default=None, repr=False)
    idp_state: str | None = None

    # What the identity-provider leg established, and when the flow's use of it ends.
    identity_access_token: str | None = field(default=None, repr=False)
    identity_claims: dict[str, object] | None = None

    # The provider's session-bound refresh token, captured at the exchange. It is mintable
    # credential material and never travels to the client: at flow end it moves into the
    # pending hand-off entry keyed by the issued code's id, the code grant consumes it from
    # there, and `_finish` clears this field on both flow paths. On the consented path the
    # record is destroyed at the upstream callback before the flow records the clear; on the
    # short-circuit the clear is what keeps the field from outliving the flow's use of it.
    identity_refresh_token: str | None = field(default=None, repr=False)

    # The callback URI Core registered for this toolset, carried from the interstitial leg
    # to the credential call. It is a value of the toolset's own registration — read once,
    # from Core's public projection, never from the callback a request supplies.
    upstream_redirect_uri: str | None = None

    # The upstream authorization URL the consent branch built, kept on the record for the
    # same reason the redirect URI above is: it is a fact of the toolset's own
    # registration, read once, and the approve action continues the flow from the record
    # alone — the built URL must survive the decision page's one presentation so that the
    # continuation is not rebuilt (or lost) between the page and the action. Its presence
    # is also the record's own marker of which stage the checkpoint deferred: the consent
    # branch built it, the two short-circuits never do.
    upstream_authorization_url: str | None = None

    # Whether the checkpoint's decision page is up and waiting for the user's act. Set
    # when the page renders, cleared when the action processes it — so the approve and deny
    # actions are single-use-per-flow: a re-presented POST, or one against a flow that has
    # already advanced, finds this clear and lands on the expired-flow page rather than
    # minting or advancing a second time. It is also the marker that separates a flow
    # parked at the decision point from one still mid-identity-leg: only the checkpoint
    # sets it, and only after the identity leg has completed.
    awaiting_attribution: bool = False

    # When the flow's hold on the identity token ends, on the same monotonic clock
    # `expires_at` uses — min(flow TTL, the identity token's own expiry, measured as a
    # duration). The flow TTL bounds *retention*, not the token's life, so the shorter of
    # the two is what actually bounds it.
    identity_expires_at: float | None = None

    def identity_expired(self) -> bool:
        """Whether the flow's hold on the identity token has reached its end.

        The bound is the *shorter* of the flow's own TTL and the identity token's `exp` in
        the provider's answer: a flow still holding a credential the provider has already
        expired is useless anyway — the second of the token's uses would fail — so the
        record is released at the sooner of the two rather than at the flow's own, later
        one.
        """
        if self.identity_access_token is None or self.identity_expires_at is None:
            return False
        return self.identity_expires_at <= time.monotonic()

    def discard_identity_token(self) -> None:
        """Drop the identity token, keeping the claims the token-minting step still needs.

        Called as soon as both of the token's uses are spent. The claim snapshot is not a
        credential — it is the same payload a vanilla harness's own token carries — while
        the access token is one, so the record keeps the first and drops the second.
        """
        self.identity_access_token = None


class FlowStore:
    """Live flow records with a TTL and a hard cap that evicts oldest-first.

    The cap is what bounds memory on an endpoint anyone can call: without it, an
    unauthenticated caller allocates records until the process dies. Eviction takes the
    oldest records, whose browsers then receive the ordinary expired-session page — an
    outcome a user can act on, rather than the opaque failure the fallback would
    otherwise be.
    """

    def __init__(self, max_live: int, ttl_seconds: int) -> None:
        self._max_live = max_live
        self._ttl_seconds = ttl_seconds

        # Insertion order is age order, which is exactly the eviction order.
        self._flows: dict[str, FlowRecord] = {}

    def create(  # noqa: PLR0913 - one parameter per field the flow must carry between legs
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        resource: str,
        toolset: str,
        resource_kind: str,
        client_name: str | None,
        client_source: str,
        state: str | None,
    ) -> FlowRecord:
        """Allocate a flow record, evicting the oldest when the cap is reached."""
        self._prune()
        if len(self._flows) >= self._max_live:
            oldest_key = next(iter(self._flows))
            del self._flows[oldest_key]

        now = time.monotonic()
        record = FlowRecord(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            resource=resource,
            toolset=toolset,
            resource_kind=resource_kind,
            client_name=client_name,
            client_source=client_source,
            state=state,
            flow_id=new_flow_id(),
            created_at=now,
            expires_at=now + self._ttl_seconds,
        )
        self._flows[record.flow_id] = record
        return record

    def get(self, flow_id: str) -> FlowRecord | None:
        """The live flow for an id, or `None` when it is unknown, expired, or evicted."""
        record = self._flows.get(flow_id)
        if record is None:
            return None
        if record.expires_at <= time.monotonic() or record.identity_expired():
            del self._flows[flow_id]
            return None
        return record

    def destroy(self, flow_id: str) -> None:
        """Remove a record — the first-use consumption a callback performs."""
        self._flows.pop(flow_id, None)

    def live_count(self) -> int:
        """How many records are live, used by tests to observe the cap."""
        self._prune()
        return len(self._flows)

    def live_ids(self) -> tuple[str, ...]:
        """The live flow ids, in age order.

        Exposed because a flow id is the one thing a later leg resolves, so a test that
        wants to observe which ids exist — their number, their distinctness, their shape —
        should not have to reach into the store's internals to do it.
        """
        self._prune()
        return tuple(self._flows)

    def _prune(self) -> None:
        expired = [
            key
            for key, record in self._flows.items()
            if record.expires_at <= time.monotonic()
        ]
        for key in expired:
            del self._flows[key]


class ApprovedClientRegistry:
    """The per-user approvals the consent/attribution checkpoint consults.

    One entry means "this user has approved this client to act for them": keyed
    `(subject, client_id)`, the pair being the two facts the approval is about — the
    provider-verified `sub` and the resolved client id. The key carries no resource
    dimension, because the decision the page asks for is the *client's* ("may this client
    act for me"), named on a resource; the resource a flow addresses is still gated
    separately by the flow's own DIAL authorization read, so a client approved for one
    resource does not thereby reach another.

    The only writer is the approve action on a live, identity-completed flow. That is a
    structural property rather than a convention: the registry exposes `approve` and
    nothing that creates an entry without it, so an entry is always downstream of every
    bound the flow store already enforces (rate limits, flow cap, the flow's own TTL), and
    is always keyed to the subject the flow's identity leg verified — an attacker can only
    write entries against their own subject.

    Custody is process memory, single instance, and this direction is the design's:

    * **No TTL.** An approval is durable for the process's life; the decision is a
      standing user preference, not a per-flow one.
    * **Loss fails safe.** A restart empties the registry and eviction under cap pressure
      drops the oldest entries — either way the affected users re-approve once, because a
      missing entry re-prompts the decision page. Nothing here can make a lost approval
      read as a granted one.
    * **No persistence and no cookie.** The store touches no host volume and the decision
      rides no client-visible artifact: the flow id is the binding, and the flow id is
      server-side.
    """

    def __init__(self, max_entries: int) -> None:
        self._max_entries = max_entries
        # Insertion order is age order, which is exactly the eviction order — the same
        # oldest-first discipline the flow store uses.
        self._approved: dict[tuple[str, str], None] = {}

    def approve(self, subject: str, client_id: str) -> None:
        """Record that `subject` approved `client_id`, evicting the oldest at the cap.

        The one write path. Re-approving an already-approved pair is idempotent and does
        not move its age: an approval that has already been given keeps its place, so a
        burst of repeat sign-ins cannot push an older approval out of the cap ahead of
        newer ones.
        """
        key = (subject, client_id)
        if key in self._approved or not subject:
            return
        if len(self._approved) >= self._max_entries:
            oldest = next(iter(self._approved))
            del self._approved[oldest]
        self._approved[key] = None

    def is_approved(self, subject: str, client_id: str) -> bool:
        """Whether this (subject, client) pair has been approved."""
        return (subject, client_id) in self._approved

    def entry_count(self) -> int:
        """How many approvals are live, so the cap can be observed rather than assumed."""
        return len(self._approved)


class ReplayCache:
    """A single-use claim set with a TTL, for authorization codes.

    Claiming a value marks it used for as long as it could still be presented; the entry
    then ages out on its own, since nothing presents an expired code.

    The entry also carries the id of the refresh token the value's single successful
    redemption minted, recorded once by the grant that redeemed it. That is what makes
    revoke-on-double-redemption possible without a new store: on a detected replay the
    refusal reads the id back and denylists the token the first redemption bought, so the
    replayed code's token family dies at that token's next presentation. The id is bounded
    by the same TTL as the claim — no replay can be detected after the code expires, and
    the denylist entry it produces lives to the token's own expiry, which is the retention
    that matters.
    """

    def __init__(self, ttl_seconds: int, max_entries: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._claimed: dict[str, float] = {}
        # The refresh-token id and expiry a claimed code bought, keyed by the same value.
        # Kept apart from `_claimed` so a claim's liveness and the token it bought age
        # independently on the same TTL — a value with no recorded token simply has none.
        self._bought: dict[str, tuple[str, float]] = {}

    def claim(self, value: str) -> bool:
        """Claim a value once; `False` means it was already claimed and is still live."""
        self._prune()
        if value in self._claimed:
            return False
        if len(self._claimed) >= self._max_entries:
            oldest = min(self._claimed, key=lambda key: self._claimed[key])
            del self._claimed[oldest]
            self._bought.pop(oldest, None)
        self._claimed[value] = time.monotonic() + self._ttl_seconds
        return True

    def record_token_id(self, value: str, token_id: str, *, expires_at: float) -> None:
        """Record the refresh-token id a claimed value's redemption minted.

        Called by the code grant after it claims the code and mints the token the claim
        bought, so a later detected replay of the same code can denylist exactly that
        token. A no-op for a value that is not live: only a claim that succeeded should
        leave a token id behind.
        """
        self._prune()
        if value in self._claimed:
            self._bought[value] = (token_id, expires_at)

    def claimed_token_id(self, value: str) -> str | None:
        """The refresh-token id a claimed value bought, or `None` when none is recorded."""
        self._prune()
        entry = self._bought.get(value)
        return entry[0] if entry is not None else None

    def claimed_token_expiry(self, value: str) -> float | None:
        """The expiry of the refresh token a claimed value bought, or `None`."""
        self._prune()
        entry = self._bought.get(value)
        return entry[1] if entry is not None else None

    def is_claimed(self, value: str) -> bool:
        self._prune()
        return value in self._claimed

    def entry_count(self) -> int:
        """How many claims are live, so a bound can be observed rather than assumed."""
        self._prune()
        return len(self._claimed)

    def _prune(self) -> None:
        now = time.monotonic()
        for key in [k for k, expiry in self._claimed.items() if expiry <= now]:
            del self._claimed[key]
            self._bought.pop(key, None)


class PendingCustodyStore:
    """The provider refresh token's short transit between the flow and the code grant.

    The carrier for the custody claim — the gateway's own refresh token — does not exist
    until the code grant at `/dial/token`, minutes after the flow ends, and the flow record
    never reaches the code grant (it is destroyed on first use at the upstream callback, or
    TTL-bounded and credential-free on the already-signed-in short-circuit, whose `_finish`
    clears both of its credentials and leaves only the claim snapshot). So the provider's
    session refresh token transits this store instead: an entry keyed by the authorization
    code's `jti`, created when the code is minted, bounded by the code's own short TTL, and
    consumed when the code grant issues the refresh token that seals it.

    Three properties are decisions rather than omissions:

    * **Memory-only.** A restart drops every entry, so a code issued before the restart and
      never redeemed fails its grant fail closed. The custody itself survives the restart,
      because the ciphertext returns with the presented refresh token.
    * **The code's own TTL is the bound.** An entry lives no longer than the code that names
      it could be redeemed; past that the code is refused anyway and the entry is dropped.
    * **Nothing here is logged.** The value is a mintable provider credential; it exists in
      the process only as the transient entry and, at the grant, the ciphertext it becomes.
    """

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._entries: dict[str, tuple[str, float]] = {}

    def put(self, code_id: str, provider_refresh_token: str) -> None:
        """Hold a provider refresh token until the code named by `code_id` is redeemed."""
        self._prune()
        self._entries[code_id] = (
            provider_refresh_token,
            time.monotonic() + self._ttl_seconds,
        )

    def take(self, code_id: str) -> str | None:
        """Consume the entry for a code, or `None` when there is none.

        Consuming rather than reading is what makes the transit single-use: a code is
        redeemed once, so its carried provider token is sealed into exactly one refresh
        token and is not left behind for a second grant to pick up.
        """
        self._prune()
        entry = self._entries.pop(code_id, None)
        return entry[0] if entry is not None else None

    def entry_count(self) -> int:
        """How many entries are live, so the bound can be observed rather than assumed."""
        self._prune()
        return len(self._entries)

    def _prune(self) -> None:
        now = time.monotonic()
        for key in [k for k, (_, expiry) in self._entries.items() if expiry <= now]:
            del self._entries[key]


@dataclass
class _Revocation:
    """One denylisted refresh-token id, and whether it is still inside its grace window."""

    expires_at: float
    # Set only for a rotation, and only for its grace window: a rotation is not a
    # revocation — the token was valid when it arrived and lost a race — so a request that
    # raced it is served rather than refused.
    grace_until: float | None = None


class TokenDenylist:
    """Refresh-token ids that must not be redeemed, held until the token's own expiry.

    An entry is kept only as long as the token it names could still be presented — past
    its `exp` the signature check refuses it anyway, so holding the id longer would be
    unbounded memory for no property. The list is therefore self-bounding: it can hold at
    most one entry per refresh token that is still alive, and refresh tokens are minted
    only by a completed sign-in or a rotation.

    Two ways in, and the difference matters:

    * `revoke` is a revocation — immediate, permanent for the token's life, and the only
      way a caller can end a session.
    * `rotate` is bookkeeping: the token was successfully redeemed and replaced, and this
      id is dead from here. Its *grace window* exists so that a client which sent two
      requests and lost the race on the first rotation is not logged out, and it is
      deliberately one-way — replaying the token inside its grace gets the same treatment
      but does not restart the window, and the replacement it receives keeps the original
      non-sliding expiry, so neither the replay nor the replacement can extend the session.
    """

    def __init__(self) -> None:
        self._revoked: dict[str, _Revocation] = {}

    def revoke(self, token_id: str, *, expires_at: float) -> None:
        """Denylist a token id, immediately, to the moment the token expires."""
        self._prune()
        self._revoked[token_id] = _Revocation(expires_at=expires_at)

    def rotate(self, token_id: str, *, expires_at: float, grace_seconds: float) -> None:
        """Denylist a redeemed token id, with a grace window for a request racing it."""
        self._prune()
        now = time.time()
        self._revoked[token_id] = _Revocation(
            expires_at=expires_at,
            grace_until=now + grace_seconds if grace_seconds > 0 else now,
        )

    def is_revoked(self, token_id: str) -> bool:
        """Whether a token id must be refused outright."""
        return self._entry(token_id) is not None

    def in_rotation_grace(self, token_id: str) -> bool:
        """Whether a token id was rotated and is still inside its grace window.

        A token in this state is served exactly as a live one: the caller mints an access
        token and a replacement refresh token for it, because it was redeemed successfully
        and only lost a race with another request. Its grace window exists so that a client
        that sent two requests is not logged out for losing — and it is deliberately
        one-way, so replaying the token inside the window neither restarts the window nor
        forks the rotation chain.
        """
        entry = self._entry(token_id)
        if entry is None or entry.grace_until is None:
            return False
        return time.time() < entry.grace_until

    def entry_count(self) -> int:
        """How many ids are denylisted, so the bound can be observed."""
        self._prune()
        return len(self._revoked)

    def _entry(self, token_id: str) -> _Revocation | None:
        self._prune()
        entry = self._revoked.get(token_id)
        if entry is None:
            return None
        if entry.grace_until is not None and time.time() < entry.grace_until:
            # Inside the grace window this is not a revocation at all.
            return None
        return entry

    def _prune(self) -> None:
        now = time.time()
        for key in [k for k, entry in self._revoked.items() if entry.expires_at <= now]:
            del self._revoked[key]


@dataclass
class _Window:
    started_at: float
    count: int = 0
    touched_at: float = field(default=0.0)


class RateLimiter:
    """Per-source and global request limits over a fixed window.

    Both limits exist because they bound different things: the per-source limit bounds
    what one caller can do, and the global limit bounds what the endpoint as a whole
    accepts — a caller with many addresses would otherwise be bounded by neither. The
    per-source map is itself bounded, since an unbounded map keyed by a caller-supplied
    value is the same exhaustion problem in a different place.
    """

    def __init__(
        self,
        per_source_limit: int,
        global_limit: int,
        window_seconds: int = 60,
        max_sources: int = 4096,
    ) -> None:
        self._per_source_limit = per_source_limit
        self._global_limit = global_limit
        self._window_seconds = window_seconds
        self._max_sources = max_sources
        self._sources: dict[str, _Window] = {}
        self._global = _Window(started_at=time.monotonic())

    def allow(self, source: str) -> bool:
        """Whether a request from this source may proceed, counting it if so."""
        now = time.monotonic()
        self._roll(self._global, now)
        if self._global.count >= self._global_limit:
            return False

        window = self._sources.get(source)
        if window is None:
            if len(self._sources) >= self._max_sources:
                self._evict_oldest_source()
            window = _Window(started_at=now)
            self._sources[source] = window
        self._roll(window, now)
        if window.count >= self._per_source_limit:
            return False

        window.count += 1
        window.touched_at = now
        self._global.count += 1
        return True

    def _roll(self, window: _Window, now: float) -> None:
        if now - window.started_at >= self._window_seconds:
            window.started_at = now
            window.count = 0

    def source_count(self) -> int:
        """How many sources are tracked, so the map's bound can be observed."""
        return len(self._sources)

    def _evict_oldest_source(self) -> None:
        oldest = min(self._sources, key=lambda key: self._sources[key].touched_at)
        del self._sources[oldest]
