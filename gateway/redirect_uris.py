"""The redirect-URI shape rule: the loopback exception, and the scheme admission rule.

Two facts live here because they are one fact seen twice. A redirect URI may be **`https`**,
or **`http` on a loopback host** (`localhost`, `127.0.0.1`, `[::1]`, any port) — the RFC 8252
§7.3 loopback shape a native app's ephemeral-port listener needs. The *admission* rule
refuses everything else, because a plain-`http` redirect on a real host is the collector the
authorization response — the code and the echoed `state` — would cross in cleartext; the
*exact-match* rule's loopback-port exception is that same shape, read one use later.

The rule is stated once, here, and imported by every site that admits a redirect URI: the
DCR registration body check, the CIMD document validation, the pre-registered startup
validation, and the durable store's load path. One copy means the four sites cannot drift —
a scheme admitted at one is admitted at all, and a host set narrowed here narrows
everywhere.

The module imports nothing from the gateway package: it is a leaf, so the sites that enforce
the rule — including the settings model, which the rest of the package imports — can all
depend on it without a cycle.
"""

from __future__ import annotations

from urllib.parse import urlsplit

# The hosts RFC 8252 §7.3 names as loopback, plus the `localhost` spelling §8.3 says behaves
# as they do. The set is closed: a name or literal outside it gets no exception, however
# loopback-like it looks (`0.0.0.0`, a private range, or a name that merely resolves there is
# not a loopback redirect target).
LOOPBACK_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})

# The one sentence every admission-site refusal ends with, so the four sites state the same
# rule in the same words and an operator who meets one has met them all.
ADMISSION_RULE = (
    "a redirect URI must be `https`, or `http` on a loopback host "
    "(localhost, 127.0.0.1, or [::1])"
)


def loopback_target(uri: str) -> tuple[str, str, str, str, str] | None:
    """A redirect URI's comparable components when it is a loopback `http` URI, else None.

    A native app serving a loopback callback cannot pre-register the port it will get: it
    binds an ephemeral port per launch (RFC 8252 §7.3), so the port is the one component a
    loopback redirect URI is matched without (§8.4). Everything else stays comparable and
    the comparison is on all of it — the path byte-exact, the query and fragment included,
    so dropping or folding either is not something this function permits.

    Only the scheme and host are read in their normalized form, which is not a folding
    decision: RFC 3986 §3.1 and §3.2.2 make neither case-sensitive, and `urlsplit` is what
    normalizes them. The path, query, and fragment are the raw text of the URI.

    Returning `None` is the refusal path: a URI that is not loopback-`http` earns no
    exception, so a request cannot self-declare its way into one. Credentials in the URI
    are refused for the same reason — they are not part of any loopback redirect target,
    and a URI carrying them is not the URI the client registered.
    """
    try:
        parts = urlsplit(uri)
    except ValueError:
        # A malformed URI (an unterminated IPv6 literal, say) is not a loopback target;
        # it falls back to exact string equality, which it also fails.
        return None
    if parts.scheme != "http" or parts.hostname not in LOOPBACK_HOSTNAMES:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    return (
        parts.scheme,
        parts.hostname,
        parts.path,
        parts.query,
        parts.fragment,
    )


def scheme_admission_refusal(uri: str) -> str | None:
    """The reason a redirect URI fails the admission rule, or `None` when it is admitted.

    Admitted: `https` on any host, or `http` on a loopback host. The refusal is one sentence
    naming the rule, because the caller composes it into a message for a specific audience
    (a registrant, a document author, an operator) and the rule is the part that must read
    the same everywhere. An empty string is not a URI and is refused here like any other
    value that is neither of the two shapes.
    """
    try:
        parts = urlsplit(uri)
    except ValueError:
        return ADMISSION_RULE
    if parts.scheme == "https":
        return None
    if loopback_target(uri) is not None:
        return None
    return ADMISSION_RULE
