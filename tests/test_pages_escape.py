"""The pages' escape discipline, proven for path-shaped interpolants (task 3.6).

The SIA's T-EP3-b mitigation: the decision page and the interstitial interpolate a resource
path, and a path is caller-derived, percent-encoded material — a path crafted to decode to
markup-shaped bytes (`%3C%61%3B…`) must not reach the page unescaped, and the escape
discipline is asserted against the shared builder rather than assumed from the name shape.

The rows drive the page builders directly, feeding each interpolation point a path-shaped
value whose *decoded* form carries markup. They assert the interpolated value arrives
escaped — no raw markup from the interpolant — so a builder that stopped escaping (or an
interpolation point that skipped it) fails here.
"""

from __future__ import annotations

import time

from gateway.flow import (
    decision_page,
    interstitial_page,
    mint_navigation_page,
)
from gateway.state import FlowRecord

# Path-shaped inputs whose decoded/raw form is markup in an HTML context. MARKUP_PATH is the
# percent-encoded spelling a router carries; RAW_MARKUP_PATH is the same content raw (the
# guard refuses these on the served surfaces, but the page builder must not depend on that).
MARKUP_PATH = "%3Ca%3Bscript%3E"  # decodes to `<a;script>`
RAW_MARKUP_PATH = "<a;script>"
MARKUP_CLIENT_NAME = '<b>"&'


def _flow(*, resource_path: str, client_name: str | None = None) -> FlowRecord:
    """A flow record whose resource field (the interpolated path) is caller-shaped."""
    now = time.monotonic()
    return FlowRecord(
        flow_id="a-flow-id",
        client_id="a-client-id",
        redirect_uri="http://127.0.0.1:8766/callback",
        code_challenge="a-challenge",
        code_challenge_method="S256",
        resource=f"http://localhost:8090/dial/{resource_path}/mcp",
        toolset=resource_path,
        resource_kind="toolset",
        client_name=client_name,
        client_source="test",
        state=None,
        created_at=now,
        expires_at=now + 600,
    )


def _assert_interpolant_escaped(rendered: str, raw: str, *, where: str) -> None:
    """The raw interpolant does not appear unescaped, and its escaped form does.

    `raw` is the hostile string fed to an interpolation point. If the builder escapes it,
    the raw form is absent from the output and the `&lt;…`/`&amp;…` form is present.
    """
    assert raw not in rendered, f"{where}: the raw value reached the page: {raw!r}"
    escaped = (
        raw.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    assert escaped in rendered, f"{where}: the escaped form is absent: {escaped!r}"


def test_the_decision_page_escapes_a_path_shaped_resource() -> None:
    """The decision page's resource interpolation escapes a markup-shaped path."""
    flow = _flow(resource_path=MARKUP_PATH)

    rendered = decision_page(flow)

    # A raw `<`/`>` can never be the encoded value, but a builder that decoded before
    # escaping would emit one; assert the encoded spelling's markup never appears raw.
    assert "<a;script>" not in rendered


def test_the_decision_page_escapes_a_raw_markup_path() -> None:
    """The same discipline holds for a raw markup-shaped path."""
    flow = _flow(resource_path=RAW_MARKUP_PATH)

    rendered = decision_page(flow)

    _assert_interpolant_escaped(
        rendered, RAW_MARKUP_PATH, where="decision page, raw path"
    )


def test_the_decision_page_escapes_a_hostile_client_name_beside_a_hostile_path() -> (
    None
):
    """Every interpolation point escapes: the path and the registrant name together."""
    flow = _flow(resource_path=RAW_MARKUP_PATH, client_name=MARKUP_CLIENT_NAME)

    rendered = decision_page(flow)

    _assert_interpolant_escaped(rendered, RAW_MARKUP_PATH, where="decision page, path")
    _assert_interpolant_escaped(
        rendered, MARKUP_CLIENT_NAME, where="decision page, client name"
    )


def test_the_interstitial_escapes_a_path_shaped_resource() -> None:
    """The interstitial's toolset interpolation escapes a markup-shaped path."""
    flow = _flow(resource_path=MARKUP_PATH)

    rendered = interstitial_page(flow, "https://upstream.example/authorize")

    assert "<a;script>" not in rendered


def test_the_interstitial_escapes_a_raw_markup_path() -> None:
    """The interstitial's escape discipline holds for a raw markup-shaped path too."""
    flow = _flow(resource_path=RAW_MARKUP_PATH)

    rendered = interstitial_page(flow, "https://upstream.example/authorize")

    _assert_interpolant_escaped(
        rendered, RAW_MARKUP_PATH, where="interstitial, raw path"
    )


def test_the_mint_note_page_escapes_a_path_shaped_destination() -> None:
    """The mint page's navigation destination is escaped before it reaches the attribute.

    The destination is a validated registered redirect, but the escape discipline is
    asserted so a value carrying markup could not turn the URL into markup.
    """
    destination = f"http://127.0.0.1:8766/cb?a={RAW_MARKUP_PATH}"

    rendered = mint_navigation_page(destination)

    assert RAW_MARKUP_PATH not in rendered
    assert "&lt;a;script&gt;" in rendered
