"""The per-flow audit trail.

One line per flow event, carrying identifiers and outcomes only: the flow id, the subject,
the client id, the resource, timestamps, and results. It never carries a token, a code, a
key, or a secret — the audit trail exists to answer *who did what*, and every value that
would answer *with what* is exactly the material this gateway must not retain.

Every one of a record's fields is also either **length-bounded** or **fixed** at the point
the record is emitted. The facts a refusal records are the request's own values (client id,
redirect URI, resource, resource name), and a value's length is the caller's choice: an
unauthenticated request carrying a megabyte-long client id would otherwise land in the log
in full, so the trail bounds what it writes rather than trusting each call site to. A fact
past the bound is truncated to it — the prefix is what identifies the client or the URI the
refusal was about, so the diagnosis survives, and the record still shows the request was
oversized by sitting exactly at the bound. The remaining fields are this gateway's own
fixed vocabulary and are bounded by their vocabulary already, which is why the bound names
the fact fields rather than every string: a record whose reason had been truncated would no
longer carry the vocabulary the whole surface is read by.

The sink is the process's standard output, which is where a container's log collector
already reads; the destination is a deployment concern, not a decision this module makes.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

# The default bound on how long any string in a record may be, and the value the settings
# model carries as its own default (`AUDIT_FACT_MAX_LENGTH`, whose docstring is the
# operator-facing statement of what it is for). Defined here rather than there so a trail
# built without a configuration — a test's, or a helper's — is bounded by the same value
# as one built from settings, instead of by no bound at all.
DEFAULT_FACT_MAX_LENGTH = 256

# A dedicated logger so an operator can route audit records apart from operational
# messages, and so a log-level change on the package does not silence them.
_LOGGER = logging.getLogger("gateway.audit")

# The record fields whose values come from a request rather than from this gateway: the
# client id, the redirect URI, the resource URI, and the resource name a refusal names.
# `client_name` joins them: it is registrant-supplied through CIMD or DCR, so the
# attribution events carry a value whose length a registrant chooses. These are the fields
# whose length a caller chooses, so these are the fields the bound applies to. Everything
# else in a record is the gateway's own — a fixed-vocabulary reason, an event name, a leg
# name, a subject read from a token this gateway minted — and is already bounded by the
# vocabulary it comes from. `resource_kind` is deliberately absent: it is this gateway's
# own fixed token (`toolset`/`app`), never a caller-supplied value.
_CALLER_FACT_FIELDS = frozenset(
    {"client_id", "client_name", "redirect_uri", "resource", "name"}
)


def _bounded(field: str, value: object, limit: int) -> object:
    """A record field with its length bounded, when the field is one a caller supplies.

    Only the **caller-supplied facts** are bounded, and only when they are strings. The
    other fields are this gateway's own — the event name, the refusal reason, a leg name, a
    flow id, a token id — and they are already as short as the vocabulary makes them;
    truncating one would corrupt the record's meaning rather than bound it, and a record
    whose `reason` had been cut to fit a cap would no longer carry the fixed vocabulary
    that the whole refusal-audit surface is read by. The bound's purpose is narrower than
    "every string": it exists for the values whose length the request chooses.

    Truncation rather than refusal because the field's purpose is diagnosis, and the prefix
    of an over-long value is the part that says which client, URI, or resource name the
    refusal was about.
    """
    if field in _CALLER_FACT_FIELDS and isinstance(value, str) and len(value) > limit:
        return value[:limit]
    return value


class AuditTrail:
    """Records flow events, redacted and bounded by construction.

    Both properties are enforced at the one point every record passes through, `_emit`,
    rather than at each call site: a call site that had to remember to bound its own
    values eventually would not, and the surfaces that feed this trail are
    unauthenticated, so the length bound is a property of the trail rather than of its
    callers.
    """

    def __init__(self, fact_max_length: int = DEFAULT_FACT_MAX_LENGTH) -> None:
        self._fact_max_length = fact_max_length

    def _emit(self, event: str, **fields: Any) -> None:
        record = {"event": event, "at": time.time(), **fields}
        # `json.dumps` of an explicitly constructed mapping: every value here is a
        # string, a number, or None, and each has already been chosen by the caller to
        # be safe to record. The caller-supplied facts pass through `_bounded` first, so a
        # value that is merely long cannot grow the record without limit.
        _LOGGER.info(
            json.dumps(
                {
                    key: _bounded(key, value, self._fact_max_length)
                    for key, value in record.items()
                },
                sort_keys=True,
                default=str,
            )
        )

    def flow_allocated(self, flow: object) -> None:
        """A flow record was created for a validated authorization request.

        Carries the resource the flow serves and the resource *kind* it serves (a toolset
        or an app): a flat authorization server now serves two kinds, so the kind is the
        fact that tells an operator reading the trail which namespace's read the flow's
        later stages will make.
        """
        self._emit(
            "flow_allocated",
            flow_id=getattr(flow, "flow_id", None),
            client_id=getattr(flow, "client_id", None),
            resource=getattr(flow, "resource", None),
            resource_kind=getattr(flow, "resource_kind", None),
        )

    def flow_refused(  # noqa: PLR0913 - one parameter per non-credential fact a refusal may carry
        self,
        reason: str,
        *,
        client_id: str | None = None,
        redirect_uri: str | None = None,
        resource: str | None = None,
        name: str | None = None,
        resource_kind: str | None = None,
    ) -> None:
        """A request was refused before a flow record was allocated.

        Two disciplines meet here, and the split is the point:

        * The **reason** is one of this gateway's own fixed descriptions, never a value
          supplied by the caller. It is what tells the operator which refusal class this
          was, and a caller cannot write content into the log through it.
        * The **facts** are the request's own values — the client id it presented, the
          redirect URI, the resource, the resource *name* — and they are recorded so the
          operator can diagnose the refusal from the log instead of reproducing it with
          external probes. They are not interpolated into any text: each is a discrete
          field of the JSON record, and `json.dumps` encodes it, so a value carrying a
          newline or a brace cannot become a second line or a second record. A caller can
          therefore write its own value into its own field and nothing else.

        The name fact is deliberately kind-neutral rather than `toolset`: a refusal under
        either the toolset or the apps namespace carries the name the request offered, and
        a namespace-specific field name would read the same value as one kind's fact when
        the refusal was the other kind's. Where the site knows the namespace — the
        discovery guards, each of which serves one kind — it also passes `resource_kind`,
        whose value is this gateway's own fixed token, so the trail names the namespace
        explicitly. Where the site does not know it (the authorization endpoint resolves
        the kind only after validation), the name stands alone.

        None of these values is a credential, which is what makes them safe here: a client
        id, a redirect URI, a resource URI, and a resource name are all as public as the
        request that carried them. A refused request that presented a token or a code does
        not put one here — no call site passes one, and this signature has no parameter for
        one. There is no flow id: this is the refusal class for requests that never
        allocated one.

        Each caller-supplied fact is bounded at the `_emit` boundary: the facts are the
        caller's own values and their length is the caller's choice, so a refusal that
        carried an over-long one lands truncated rather than in full. The reason and the
        resource kind need no such treatment — they are tokens from this gateway's own
        fixed vocabulary — but every field passes through the same bound, which is why the
        bound lives at the emit rather than at the arguments.

        A refusal that recorded no facts passes none, and the fields are then present and
        null rather than absent: the record's shape stays one shape, so a collector reading
        these lines does not have to distinguish "this class carries no client id" from "the
        client id was lost". The limiter's 429 branch records the reason only, deliberately
        — the limiter bounds work, not log volume, and a volume-refused request is one whose
        facts would be written at the rate an attacker chooses.
        """
        self._emit(
            "flow_refused",
            reason=reason,
            client_id=client_id,
            redirect_uri=redirect_uri,
            resource=resource,
            name=name,
            resource_kind=resource_kind,
        )

    def client_registered(self, client_id: str, source: str) -> None:
        """A client registration was persisted."""
        self._emit("client_registered", client_id=client_id, source=source)

    def token_issued(self, *, subject: str, client_id: str, resource: str) -> None:
        """Tokens were minted for a redeemed authorization code.

        The subject and the client are recorded; the tokens themselves, the code, and the
        verifier are not — an audit record that carried them would be a credential store.
        The resource is the URI the tokens address, which for a flow of either kind names
        the resource the sign-in was for.
        """
        self._emit(
            "token_issued",
            subject=subject,
            client_id=client_id,
            resource=resource,
        )

    def token_refreshed(self, *, subject: str, client_id: str, resource: str) -> None:
        """A refresh token was exchanged for a fresh access token.

        Recorded for the same reason a first issuance is: the trail should answer who kept
        a session alive and for how long, which is a question the tokens cannot answer
        after the fact because they are the only record of themselves.
        """
        self._emit(
            "token_refreshed",
            subject=subject,
            client_id=client_id,
            resource=resource,
        )

    def token_revoked(self, *, token_id: str) -> None:
        """A refresh token was revoked, recorded by its id and nothing else."""
        self._emit("token_revoked", token_id=token_id)

    def code_issued(self, record: object) -> None:
        """The flow issued the harness's authorization code.

        The same identifiers as the other flow events, so one flow reads as one story from
        allocation to issuance. The code itself is not here and never is.
        """
        self._emit(
            "code_issued",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            resource=getattr(record, "resource", None),
            subject=self._subject_of(record),
        )

    def upstream_callback(self, record: object) -> None:
        """The upstream callback was processed for a flow.

        Emitted after the state round-trip and at the moment the record is consumed, so it
        is the point at which a flow stops being resumable — which is what an operator
        reading the trail needs to know about a callback that transferred a credential.
        """
        self._emit(
            "upstream_callback",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            resource=getattr(record, "resource", None),
            subject=self._subject_of(record),
        )

    def signin_result(self, record: object, *, result: str) -> None:
        """The credential API call's outcome, which is the flow's decisive event.

        The result is one of a small fixed vocabulary chosen here — `accepted`, or the
        refusal's kind — never Core's own response text, which can echo the request it was
        given. Paired with `upstream_callback`, this answers the question an operator
        actually asks about a sign-in: the callback arrived, and Core did or did not store
        the credential.
        """
        self._emit(
            "signin_result",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            resource=getattr(record, "resource", None),
            subject=self._subject_of(record),
            result=result,
        )

    def flow_leg_failed(self, record: object, *, leg: str, reason: str) -> None:
        """A flow leg failed, with the leg's name and this gateway's own reason text.

        `reason` is always fixed text chosen by the gateway or a message it constructed
        from a status code — never a value from a request and never a credential. The leg
        name says where in the flow the failure sits, which is what tells an operator
        whether to look at the identity provider, at Core, or at the upstream.
        """
        self._emit(
            "flow_leg_failed",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            resource=getattr(record, "resource", None),
            leg=leg,
            reason=reason,
        )

    def flow_branch_refused(self, record: object, *, reason: str) -> None:
        """A flow was refused on a routing branch, with a fixed-vocabulary reason.

        The reasons this carries are a small closed vocabulary chosen by the gateway — the
        impossible-branch refusal (`non_oauth_toolset`) and the unknown-name refusals at the
        flow's authenticated reads (`unknown_toolset` for the toolset namespace, `unknown_app`
        for the apps namespace) — never a value from a request and never a credential.
        Recorded with the flow's identifiers, because unlike a pre-allocation refusal this
        one happens on a live flow and the operator reads it as that flow's failure.
        """
        self._emit(
            "flow_branch_refused",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            resource=getattr(record, "resource", None),
            subject=self._subject_of(record),
            reason=reason,
        )

    def credential_free_short_circuit(self, record: object) -> None:
        """An app flow minted with no upstream stage, and the reason recorded.

        The app kind is credential-free by construction, so its flow mints after the
        identity leg and the app read and nothing else — no signed-in check, no kind branch,
        no credential call, no upstream round-trip. This record is what answers *that* the
        flow minted that way and *why* (the resource kind), so a burst of app mints reads on
        the trail as what it is rather than as an ordinary issuance. It carries the flow's
        identifiers and the resource kind, no credential and no caller input.
        """
        self._emit(
            "credential_free_short_circuit",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            resource=getattr(record, "resource", None),
            resource_kind=getattr(record, "resource_kind", None),
            subject=self._subject_of(record),
        )

    def attribution_required(self, record: object) -> None:
        """The consent/attribution decision page rendered, and the flow now waits.

        This is the trail's record that a flow reached the checkpoint and stopped for the
        user's act — so an attribution a crafted link induced is distinguishable from one
        the user's own harness run began, and an approval burst reads as one. Carries the
        flow's identifiers, the resolved client id and its registrant-supplied name, the
        redirect destination, and the resource, all non-credential facts.
        """
        self._emit(
            "attribution_required",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            client_name=getattr(record, "client_name", None),
            redirect_uri=getattr(record, "redirect_uri", None),
            resource=getattr(record, "resource", None),
            resource_kind=getattr(record, "resource_kind", None),
            subject=self._subject_of(record),
        )

    def attribution_approved(self, record: object) -> None:
        """The user approved the attribution: the decision was recorded and the flow continued.

        The semantics are the checkpoint's own: the approval is written to the registry
        keyed to the flow's verified subject, and the flow continues to the stage the
        decision deferred. Recorded with the same non-credential facts as the page's
        rendering, so the two events read as one decision on the trail.
        """
        self._emit(
            "attribution_approved",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            client_name=getattr(record, "client_name", None),
            redirect_uri=getattr(record, "redirect_uri", None),
            resource=getattr(record, "resource", None),
            resource_kind=getattr(record, "resource_kind", None),
            subject=self._subject_of(record),
        )

    def attribution_refused(self, record: object) -> None:
        """The user denied the attribution: the flow is consumed and no code is issued.

        The refusal is a user's decision, not a fault: the flow's record is destroyed, its
        identity material dropped, and no OAuth error is redirected anywhere. The event
        carries the same non-credential facts as the other two, so a refusal pattern is
        readable from the trail.
        """
        self._emit(
            "attribution_refused",
            flow_id=getattr(record, "flow_id", None),
            client_id=getattr(record, "client_id", None),
            client_name=getattr(record, "client_name", None),
            redirect_uri=getattr(record, "redirect_uri", None),
            resource=getattr(record, "resource", None),
            resource_kind=getattr(record, "resource_kind", None),
            subject=self._subject_of(record),
        )

    @staticmethod
    def _subject_of(record: object) -> object:
        """The user a flow belongs to, read from the claim snapshot on its record."""
        claims = getattr(record, "identity_claims", None)
        if isinstance(claims, dict):
            return claims.get("sub")
        return None
