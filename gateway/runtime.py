"""The gateway's runtime state, assembled once and hung off the app.

Every route reads one `Runtime` from the application state rather than re-reading the
environment or rebuilding a store per request: the settings, the signing key, the
registration store, the in-memory maps, and the audit trail are all things whose identity
must be stable for the process's whole life. The registration store in particular must be
loaded exactly once, or a restart's load would race a request's write.
"""

from __future__ import annotations

from dataclasses import dataclass

from gateway.audit import AuditTrail
from gateway.cimd import ClientMetadataCache
from gateway.core import CoreClient
from gateway.custody import CustodyKey, CustodyKeyset
from gateway.idp import IdentityProviderClient
from gateway.keys import SigningKey, SigningKeyset, load_signing_keyset
from gateway.settings import Settings
from gateway.state import (
    ApprovedClientRegistry,
    FlowStore,
    PendingCustodyStore,
    RateLimiter,
    ReplayCache,
    TokenDenylist,
)
from gateway.store import RegistrationStore

# How many claimed authorization-code ids are remembered. A code is single-use within its
# own short life, so the cache only needs to span that life; the bound keeps a flood of
# codes from growing it without limit.
_REPLAY_CACHE_MAX_ENTRIES = 100_000


@dataclass
class Runtime:
    """Everything the routes share, built once at startup."""

    settings: Settings
    signing_keyset: SigningKeyset
    custody_keyset: CustodyKeyset
    registrations: RegistrationStore
    flows: FlowStore
    replay: ReplayCache
    pending_custody: PendingCustodyStore
    denylist: TokenDenylist
    limiter: RateLimiter
    approved_clients: ApprovedClientRegistry
    client_cache: ClientMetadataCache
    audit: AuditTrail
    idp: IdentityProviderClient
    core: CoreClient

    @property
    def signing_key(self) -> SigningKey:
        """The active signing entry: the one key every token is minted with.

        A convenience for callers that mint or publish the one active key; verification
        and the JWKS go through `signing_keyset`, which holds the retained entries too.
        """
        return self.signing_keyset.active

    @property
    def custody_key(self) -> CustodyKey:
        """The active custody key: the one every sealed envelope carries the id of."""
        return self.custody_keyset.active

    @classmethod
    def build(cls, settings: Settings) -> Runtime:
        """Assemble the runtime, failing loudly on anything unusable.

        Each one of these constructors refuses rather than degrades: a missing or
        unreadable signing key, a missing or malformed custody key, a corrupt registration
        store, and a store that cannot be created all stop the process's start, with a
        message naming the setting or the path. A gateway that starts without them would
        fail at a harness instead.
        """
        return cls(
            settings=settings,
            signing_keyset=load_signing_keyset(settings),
            custody_keyset=settings.custody_keyset,
            registrations=RegistrationStore(settings),
            flows=FlowStore(
                max_live=settings.gateway_flows_max_live,
                ttl_seconds=settings.gateway_flow_ttl_seconds,
            ),
            replay=ReplayCache(
                ttl_seconds=settings.gateway_code_ttl_seconds,
                max_entries=_REPLAY_CACHE_MAX_ENTRIES,
            ),
            # The pending hand-off entries live no longer than the codes that key them.
            pending_custody=PendingCustodyStore(
                ttl_seconds=settings.gateway_code_ttl_seconds
            ),
            denylist=TokenDenylist(),
            limiter=RateLimiter(
                per_source_limit=settings.gateway_rate_per_source_per_minute,
                global_limit=settings.gateway_rate_global_per_minute,
            ),
            # The consent/attribution checkpoint's approvals: the flow store's own class,
            # no TTL, a hard cap with oldest-first eviction, and loss re-prompting.
            approved_clients=ApprovedClientRegistry(
                max_entries=settings.gateway_approved_clients_max
            ),
            client_cache=ClientMetadataCache(settings),
            audit=AuditTrail(settings.audit_fact_max_length),
            idp=IdentityProviderClient(settings),
            core=CoreClient(settings),
        )
