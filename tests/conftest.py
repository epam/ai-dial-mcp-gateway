"""Shared test fixtures.

Settings are constructed with `_env_file=None`, which disables `.env` reading, so the
suite is independent of whatever local configuration happens to be present — including
the developer's real `.env`, whose presence must never change a test's outcome.

The signing key is generated per test session rather than committed: a key in a fixture
file would be a key in the repository, and the refusals around key material are part of
what the tests exercise.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gateway.app import create_app
from gateway.keys import SigningKey
from gateway.runtime import Runtime
from gateway.settings import Settings
from pydantic import SecretStr

# The operator-declared identity-provider session bound, used as the bound every test's
# refresh TTL must fit under. Stated once here so a test that changes it is explicit about
# doing so.
IDP_LIFESPAN_SECONDS = 86_400

# The custody key every test's settings carry. A fresh one would be fine too, but a fixed
# value lets a test that rotates it name the same id the rest of the suite uses.
CUSTODY_KEY_ID = "test-key"
CUSTODY_KEY_B64 = base64.b64encode(secrets.token_bytes(32)).decode()

# The toolset the mapping tests use. One entry is enough to exercise every path that
# needs a mapped toolset, and the name doubles as the routed path segment.
TOOLSET_NAME = "notion"

# An app name, for the paths that need a served app. Its namespace is disjoint from the
# toolset's, and a name may exist as both — the tests that care about the disjointness
# use this same spelling on both kinds.
APPS_NAME = "skills-demo"

# A loopback redirect URI, in the shape a local-harness client uses.
LOOPBACK_REDIRECT_URI = "http://127.0.0.1:8766/callback"

# A client id registered out of band, for the paths that need one resolved without a
# fetch or a registration call.
PRE_REGISTERED_CLIENT_ID = "pre-registered-harness"

# The local development instance's identity-provider shape, as the fixtures the tests
# drive. The gateway's settings model is provider-neutral and its shipped defaults name
# no provider, so the suite states the local instance's issuer and back-channel base
# here — once, like the custody key — and every settings object a test builds exercises
# the leg against this shape.
LOCAL_REALM_ISSUER = "https://keycloak:8443/realms/dial"
LOCAL_REALM_BACKCHANNEL_BASE_URL = "http://keycloak:8900"

# The local realm's client secret, for the gateway's confidential registration. The
# client's secret is required at startup in both positions of the PKCE toggle — the
# gateway refuses to start without one — so the fixture supplies the local profile's
# value the way it supplies the local issuer, and a test that varies it passes its own.
IDP_CLIENT_SECRET = "the-local-realm-client-secret"

# The local instance's discovery document, as the gateway fetches it: at the back-channel
# base (scheme and host swapped, the issuer's path kept) with the well-known suffix
# appended, advertising the local instance's own endpoint spelling — the authorize
# endpoint at the browser-facing issuer, the token endpoint and key-set URI on the
# back-channel base with the issuer's path kept.
LOCAL_REALM_DISCOVERY_URL = (
    f"{LOCAL_REALM_BACKCHANNEL_BASE_URL}"
    f"{urlsplit(LOCAL_REALM_ISSUER).path}/.well-known/openid-configuration"
)


def discovery_url_of(settings: Settings) -> str:
    """The discovery URL the gateway fetches for these settings.

    The same construction the client performs: the well-known path joined to the
    issuer's path with exactly one separator — the issuer's own spelling is never
    rewritten, so an issuer whose canonical form ends in `/` is joined, not doubled —
    and re-addressed to the back-channel base's origin where one is set.
    """
    parts = urlsplit(settings.idp_issuer)
    override = settings.idp_backchannel_base_url
    if override:
        base = urlsplit(override)
        origin = f"{base.scheme}://{base.netloc}"
    else:
        origin = f"{parts.scheme}://{parts.netloc}"
    return f"{origin}{parts.path.rstrip('/')}/.well-known/openid-configuration"


def discovery_document_of(settings: Settings) -> dict[str, str]:
    """The local instance's discovery document for these settings.

    The local realm's own endpoint spelling, advertised the way a discovery document is:
    the authorize endpoint at the browser-facing issuer, the token endpoint and key-set
    URI on the back-channel base with the issuer's path kept, and an `issuer` member
    equal to the configured one — the document the leg's validation accepts. The
    configured issuer is joined, never normalized: a trailing slash in its canonical
    form is part of the pin, and the paths are built with exactly one separator.
    """
    parts = urlsplit(settings.idp_issuer)
    path = parts.path.rstrip("/")
    issuer_base = settings.idp_issuer.rstrip("/")
    override = settings.idp_backchannel_base_url
    backchannel = (
        f"{urlsplit(override).scheme}://{urlsplit(override).netloc}"
        if override
        else f"{parts.scheme}://{parts.netloc}"
    )
    return {
        "issuer": settings.idp_issuer,
        "authorization_endpoint": f"{issuer_base}/protocol/openid-connect/auth",
        "token_endpoint": f"{backchannel}{path}/protocol/openid-connect/token",
        "jwks_uri": f"{backchannel}{path}/protocol/openid-connect/certs",
    }


def make_settings(**overrides: object) -> Settings:
    """Build settings with the environment switched off, for tests that vary one field.

    `kwargs` are typed loosely because pydantic validates them; the point of this helper
    is that a test never has to repeat the `.env`-off argument that keeps it hermetic.

    The roles source path is supplied because it has no default by design, so every
    settings object a test builds would otherwise have to state it. The toolset mapping
    is left to the caller: an empty mapping is a valid configuration, and a test that
    wants one should say which mapping it means.
    """
    values: dict[str, object] = {
        "idp_sso_session_max_seconds": IDP_LIFESPAN_SECONDS,
        "roles_source_path": "roles",
        "gateway_custody_keys": {CUSTODY_KEY_ID: CUSTODY_KEY_B64},
        "idp_issuer": LOCAL_REALM_ISSUER,
        "idp_backchannel_base_url": LOCAL_REALM_BACKCHANNEL_BASE_URL,
        "idp_client_secret": SecretStr(IDP_CLIENT_SECRET),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


@pytest.fixture
def settings() -> Settings:
    """A minimal valid configuration, read from nothing but these arguments."""
    return make_settings()


def surface_settings(**overrides: object) -> Settings:
    """Settings for a test that drives an endpoint and therefore needs a usable surface.

    Beyond `make_settings` this supplies the two things a request path requires: a toolset
    restriction with one entry (every resource resolves against it) and the roles source
    path (it has no default by design).
    """
    values: dict[str, object] = {
        "roles_source_path": "roles",
        "toolsets": {TOOLSET_NAME: {}},
        "pre_registered_clients": {
            PRE_REGISTERED_CLIENT_ID: {
                "redirect_uris": [LOOPBACK_REDIRECT_URI],
                "client_name": "A pre-registered harness",
            }
        },
    }
    values.update(overrides)
    return make_settings(**values)


@pytest.fixture(scope="session")
def private_key_pem() -> str:
    """A generated RSA key PEM, for the tests that need real signing material.

    Session-scoped because generating an RSA keypair is the slowest thing the suite does,
    and none of the tests that sign need a key of their own.
    """
    return generate_key_pem()


def generate_key_pem(key_size: int = 2048) -> str:
    """A fresh RSA private key PEM, for tests that need a key of their own.

    Generated rather than committed: a key in a fixture file would be a key in the
    repository, and the tests around key material are exactly the ones that must not
    inherit one.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def generate_public_key_pem() -> str:
    """A fresh RSA public key PEM, for the test that a public key is not a signing key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


@pytest.fixture
def signing_key(private_key_pem: str) -> SigningKey:
    return SigningKey(private_key_pem)


def make_runtime(settings: Settings, private_key_pem: str) -> Runtime:
    """Assemble a runtime around a generated key, for tests that need a live app.

    The key is injected through `model_copy` rather than through the environment, which
    keeps the test's configuration hermetic while still exercising the real key-loading
    path.
    """
    return Runtime.build(
        settings.model_copy(update={"gateway_signing_key": SecretStr(private_key_pem)})
    )


def mock_discovery_on(router: respx.Router, settings: Settings) -> respx.Route:
    """Serve the local instance's discovery document on a test's own router.

    For the tests that build their app and router by hand rather than through
    `make_client`: the same document, on the router the test already steers.
    """
    return router.get(discovery_url_of(settings)).mock(
        return_value=httpx.Response(200, json=discovery_document_of(settings))
    )


@contextmanager
def make_client(settings: Settings, private_key_pem: str) -> Iterator[TestClient]:
    """A running test client over a gateway built from these settings.

    A context manager rather than a fixture because most tests here vary the
    configuration, and each variation needs its own app: state assembled at startup — the
    registration store, the flow map — must not be shared between two configurations.

    Redirects are not followed. An authorization error is delivered *as* a redirect
    carrying the error in its query string, and following it would send the test to the
    client's loopback callback, where the response it needs to assert on is gone.

    The local instance's discovery document is served here, from a router of its own, so
    every client this helper builds can resolve the identity leg's endpoints. The router
    is tried after any router the calling test itself entered (respx walks its routers in
    registration order), so a test that mocks the discovery fetch — to refuse a document,
    or to make the provider unreachable — steers it by mocking first; and a request this
    document's route does not match falls through to the test's own routes as before.
    """
    with respx.mock(assert_all_called=False) as discovery_router:
        mock_discovery_on(discovery_router, settings)
        with TestClient(
            create_app(runtime=make_runtime(settings, private_key_pem)),
            follow_redirects=False,
        ) as client:
            yield client


@pytest.fixture
def runtime(settings: Settings, private_key_pem: str) -> Runtime:
    return make_runtime(settings, private_key_pem)


def runtime_of(client: TestClient) -> Runtime:
    """The runtime behind a test client.

    `TestClient.app` is typed as a bare ASGI callable, so this is where the test suite
    states the one fact the framework's type does not carry: the app a client drives is
    the one the factory built.
    """
    app = cast(FastAPI, client.app)
    return cast(Runtime, app.state.runtime)


@pytest.fixture
def app(runtime: Runtime) -> FastAPI:
    return create_app(runtime=runtime)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    """A client for the gateway with a live runtime behind it."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def surface_client(private_key_pem: str, tmp_path: Path) -> Iterator[TestClient]:
    """A client for a gateway configured with a mapped toolset and a store of its own."""
    with make_client(
        surface_settings(dcr_store_path=str(tmp_path / "dcr-registrations.json")),
        private_key_pem,
    ) as test_client:
        yield test_client


# ------------------------------------------------- the web-hardening header family

# The directives the family pins, in the order the header spells them, with the one
# value that is derived rather than constant left as a placeholder: `style-src` carries a
# hash of the page's own stylesheet, which is what lets this helper check the served text
# against the policy rather than against a copy of the hash. `form-action 'self'` is
# family-wide: the decision page carries the one form the surface has, and the directive
# is stamped on every page's policy so no page class can drift off it.
CSP_PREFIX = (
    "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'; style-src "
)

# Anything that would let the page execute or fetch script or load a remote resource: a
# `script-src` directive at all, an `unsafe-eval`/`unsafe-inline` token, or a bare host
# source in `default-src`. Checked as a property rather than by exact string equality on
# the whole policy, so a future page that needs one more *harmless* source fails the
# assertion for review instead of silently widening what the pages may load.
#
# `'self'` is deliberately absent from this list: it appears exactly once, on
# `form-action`, where it confines form submission to the gateway's own origin — a
# narrowing, not a widening. `_assert_self_only_confines_forms` pins that it appears
# nowhere else.
_FORBIDDEN_IN_CSP = (
    "script-src",
    "'unsafe-eval'",
    "http:",
    "https:",
)


def _assert_self_only_confines_forms(policy: str, where: str) -> None:
    """`'self'` must appear only as the `form-action` source, never as a fetch source.

    The family admits no remote source; `form-action 'self'` is the one place a `'self'`
    token belongs, and it buys only that a form submits to the gateway. Any other
    occurrence would be a source the policy admits for loading or executing, which is the
    widening the family exists to prevent.
    """
    self_occurrences = policy.count("'self'")
    assert self_occurrences == 1, (
        f"{where}the CSP carries 'self' {self_occurrences} times: {policy}"
    )
    assert "form-action 'self'" in policy, (
        f"{where}the CSP's only 'self' is not on form-action: {policy}"
    )


def assert_hardening_headers(response: object, *, label: str = "") -> None:
    """Assert the whole web-hardening family on one served HTML page.

    One helper for both page classes, mirroring `gateway/pages.py`: the property under test
    is a property of the family, so a per-page spelling here would be the same duplication
    the implementation avoids. `label` names the page in every failure message, so a caller
    asserting several pages in one test can say which one lost the family.

    The CSP's `style-src` is asserted *against the page it was served with* — the SHA-256 of
    the page's own `<style>` text content — because that is the property that makes the
    permission safe: a page whose markup differs from what the hash authorizes would be
    styled by nothing, and a hash copied from a constant would pass while authorizing a
    stylesheet no page serves.
    """
    where = f"{label}: " if label else ""
    headers = _headers_of(response)
    body = _body_of(response)

    policy = headers["content-security-policy"]
    assert policy == CSP_PREFIX + "'" + _style_hash_of(body) + "'", where
    for forbidden in _FORBIDDEN_IN_CSP:
        assert forbidden not in policy, f"{where}the CSP admits {forbidden!r}: {policy}"
    _assert_self_only_confines_forms(policy, where)

    assert headers["referrer-policy"] == "no-referrer", where
    assert headers["cache-control"] == "no-store", where
    assert headers["x-content-type-options"] == "nosniff", where
    assert headers["x-frame-options"] == "DENY", where
    assert headers["content-type"] == "text/html; charset=utf-8", where
    # The gateway serves no cookie on any path, so a page that started setting one would be
    # a new surface rather than a member of this family.
    assert "set-cookie" not in headers, where


def _style_hash_of(body: str) -> str:
    """The CSP token for the page's single `<style>` element, hashed as a browser hashes it.

    Over the element's text content exactly as it appears in the served document, which is
    the reading CSP specifies — so this is the same computation the browser performs, and
    a stray character between the tags shows up here rather than only in a browser.
    """
    blocks = re.findall(r"<style>(.*?)</style>", body, re.DOTALL)
    assert len(blocks) == 1, f"the page carries {len(blocks)} style blocks"
    digest = hashlib.sha256(blocks[0].encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def _headers_of(response: object) -> dict[str, str]:
    """A response's headers as a lowercase mapping, for `TestClient` and bare responses."""
    raw = getattr(response, "headers", None)
    assert raw is not None, "the object under test is not a response"
    return {key.lower(): value for key, value in raw.items()}


def _body_of(response: object) -> str:
    """A response's body as text, whichever of the two response shapes it is."""
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    body = getattr(response, "body", b"")
    return bytes(body).decode("utf-8")
