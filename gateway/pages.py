"""The gateway's HTML page surface: one stylesheet, one header family, one builder.

Every HTML response the gateway serves — the attribution interstitial and the
plain-language error and flow pages — is built through `html_page`, which stamps the
web-hardening header family on it. One builder rather than per-page headers, because the
family is a property of the two page classes rather than of any one page: a per-page
spelling is one omission away from one page class silently drifting out of the family.

The family, and why each directive earns its place on *these* pages:

- **`Content-Security-Policy: default-src 'none'`** — a second layer under the pages'
  escaping. The interstitial renders a registrant-supplied `client_name` and the error
  pages render flow context, and escaping is what keeps either from becoming markup; a
  policy admitting no script source keeps it from *executing* if escaping ever regresses.
  No page needs script at all — the interstitial delivers the upstream request by
  navigation (a `meta refresh` with an anchor beside it), which is why no `script-src`
  source appears anywhere in the policy.
- **`style-src` by hash** — the one non-default thing these pages need. The stylesheet is
  a single constant (`PAGE_STYLE`) shared by every page and its SHA-256 is computed from
  that text here, so the served `<style>` content *is* the string that was hashed: the
  permission cannot go stale the way a hash maintained by hand beside each template
  would, and markup injected into a page matches no hash and therefore buys no styling.
  `'unsafe-inline'` would also be defensible (style injection is not an execution
  primitive, and `default-src 'none'` leaves CSS no source to fetch from), but the hash
  keeps each page's own stylesheet the only permitted one.
- **`base-uri 'none'`** — no page resolves a relative URL, and an injected `<base>` would
  relocate every relative URL the page does carry.
- **`frame-ancestors 'none'`**, with the legacy **`X-Frame-Options: DENY`** beside it —
  an auto-continuing page advances an OAuth flow, so framed by an attacker's page it would
  advance that flow inside a victim's browser holding the victim's identity-provider
  session. The legacy header covers the browsers that ignore the directive.
- **`form-action 'self'`** — the decision page carries the one form the page surface has
  (the approve and deny buttons), and confining form submission to the gateway's own
  origin closes the retargeting shape: injected markup that rewrote the form's action
  would submit to nowhere but the gateway. Stated family-wide, on the policy every page
  carries, rather than per-page, so no page class can drift off it.
- **`Referrer-Policy: no-referrer`** — the sharpest one here. The interstitial renders at
  the identity provider's callback, whose URL carries the provider's authorization code
  (exchanged server-side before the page renders) and the flow id as `state`, and the
  page's own behavior is to navigate onward to the upstream's authorize endpoint: a
  default `Referer` would deliver one party's issued code and flow state to a different
  party's page and its third-party scripts. That is a cross-party leak, so nothing bounds
  it; one line closes the class, on the error pages too — they reflect user-controlled
  context and closing it there costs nothing.
- **`Cache-Control: no-store`** — a cached interstitial or flow page replayed is a
  stale-flow resubmission. The JSON and redirect responses carry the same rule
  (`gateway/errors.py`'s `_NO_STORE`), where `Pragma` accompanies it; the pages keep both
  spellings of the one rule for the same reason.
- **`X-Content-Type-Options: nosniff`** and an explicit **`charset=utf-8`** on the
  `Content-Type` header — each page carries a `<meta charset>` already, but the header is
  what is read before the body is parsed: the meta tag is the fallback, not the carrier.

HSTS is deliberately absent. The gateway never sees the client's scheme (it sits behind
the front router), the committed listener is plain http on 8090 where the directive is
inert, and a deployment that terminates TLS adds it at its own listener — the layer that
owns the scheme.
"""

from __future__ import annotations

import base64
import hashlib

from fastapi.responses import HTMLResponse

# The stylesheet every page shares. One constant rather than a rule set repeated in each
# template, because the policy below pins it by hash: a page whose style text differed
# from this would render unstyled, and this is the text the hash is computed from.
PAGE_STYLE = """
body { font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 40rem;
       line-height: 1.5; }
h1 { font-size: 1.4rem; }
.note { background: #f4f4f5; padding: 1rem; border-radius: .5rem; }
"""


def _style_source() -> str:
    """The CSP hash of the shared stylesheet, over the very text the pages serve.

    The window between what is hashed and what is rendered is closed by construction: the
    templates substitute `PAGE_STYLE` itself, so an edit to the stylesheet changes both.
    """
    digest = hashlib.sha256(PAGE_STYLE.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


# Computed once, at import: the stylesheet is a constant, so its hash is one too.
_STYLE_SOURCE = _style_source()

# The `<style>` block the templates substitute, with no whitespace added around it: the
# browser hashes the element's text content exactly, so the block has to carry `PAGE_STYLE`
# byte for byte or the hash authorizes a stylesheet the page does not have.
STYLE_BLOCK = f"<style>{PAGE_STYLE}</style>"


def page_headers() -> dict[str, str]:
    """The web-hardening header family, as the mapping a response is built with.

    A fresh mapping per call rather than a shared constant: these are handed to a response
    object, and a module-level dict would let one page's mutation reach every later page.
    """
    return {
        "Content-Security-Policy": (
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; "
            f"style-src '{_STYLE_SOURCE}'"
        ),
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Type": "text/html; charset=utf-8",
    }


def html_page(body: str, *, status_code: int = 200) -> HTMLResponse:
    """An HTML response carrying the family.

    The single construction path for both page classes: a page that is served without
    going through here is a page outside the family, which is what the header-assertion
    tests exist to catch.
    """
    return HTMLResponse(body, status_code=status_code, headers=page_headers())
