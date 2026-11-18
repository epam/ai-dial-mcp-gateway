"""Tests for the application factory, its liveness endpoint, and the signing key.

The key-material assertions are the point of this file's second half: the signing key is
identity-provider-grade, so what it must never do — appear in a log line, appear in a
rendered configuration, or load from a value that is not a real key — is tested as
behaviour rather than asserted as a convention.
"""

from __future__ import annotations

import logging
from http import HTTPStatus
from pathlib import Path

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gateway.app import create_app
from gateway.errors import ConfigurationError
from gateway.keys import SigningKey, load_signing_key
from gateway.settings import Settings
from pydantic import SecretStr

from tests.conftest import (
    CUSTODY_KEY_B64,
    CUSTODY_KEY_ID,
    IDP_LIFESPAN_SECONDS,
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    generate_key_pem,
    generate_public_key_pem,
    make_client,
    make_runtime,
    make_settings,
    surface_settings,
)

# The container-internal port the gateway binds; the front router publishes the public
# one, so this is never host-exposed.
DEFAULT_INTERNAL_PORT = 8091


def test_healthz_answers_ok(client: TestClient) -> None:
    """The compose-boot gate probes this path, so it must answer 200 with a JSON body."""
    response = client.get("/healthz")

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {"status": "ok"}


def test_healthz_does_not_require_credentials(private_key_pem: str) -> None:
    """Liveness must be answerable whatever else the configuration holds.

    A probe that needed configuration would report a working process as down.
    """
    runtime = make_runtime(make_settings(), private_key_pem)

    with TestClient(create_app(runtime=runtime)) as client:
        response = client.get("/healthz")

    assert response.status_code == HTTPStatus.OK


def test_app_carries_the_resolved_settings(app: FastAPI, runtime: object) -> None:
    """Routers read one settings object from app state, not the environment."""
    assert app.state.settings is app.state.runtime.settings
    assert app.state.runtime is runtime


def test_schema_endpoints_are_not_exposed(client: TestClient) -> None:
    """The docs and schema routes are closed: they are not part of a harness's surface."""
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == HTTPStatus.NOT_FOUND, path


def test_the_sign_in_status_route_is_gone(client: TestClient) -> None:
    """The status surface is removed entirely, both namespaces.

    A request to the retired path reaches no gateway handler: the path is not in the app's
    route table, so it answers the framework's own 404 rather than an authenticated status
    document. The path shape a harness would once have used is asserted gone at the app
    boundary, which is where its absence is decidable without the router.
    """
    assert client.get("/dial/notion/status").status_code == HTTPStatus.NOT_FOUND


def test_the_retired_status_reason_tokens_are_absent() -> None:
    """The status-only refusal tokens retire with the endpoint they served.

    They are looked for across the shipped package rather than in any one table: the
    pre-allocation refusal reasons are chosen at their call sites, so a token that
    outlived its surface would reappear there. The check is what a grep of every emit
    site would be, committed so the retirement cannot silently regress.

    Each token is matched as the quoted literal it is, not as a bare substring: the token
    endpoint's own `invalid_token_request` reason is a different, surviving token whose
    name merely starts with the retired one's.
    """
    package = Path(__file__).resolve().parent.parent / "gateway"

    for retired in ('"missing_token"', '"invalid_token"'):
        for source in package.rglob("*.py"):
            assert retired not in source.read_text(encoding="utf-8"), (
                f"{source.name} still names the retired status-only reason {retired}"
            )


def test_an_unhandled_failure_is_logged_with_its_traceback(
    runtime: object, caplog: pytest.LogCaptureFixture
) -> None:
    """The handler's own contract: the client gets fixed text, the operator gets the trace.

    A handler that suppressed Starlette's default logging and logged nothing itself would
    make every unexpected failure invisible — a defect that can only be rediscovered, never
    diagnosed. The instrument is a route that raises, driven through the client with the
    exception swallowed so the test measures the record rather than the re-raise.
    """
    app = create_app(runtime=runtime)  # type: ignore[arg-type]

    @app.get("/explode")
    async def explode() -> None:
        # The message carries a value that must not be reflected; `noqa` because this test
        # raises a bare exception on purpose, and the message is the thing under test.
        raise RuntimeError("a value from the request: code=super-secret-code")  # noqa: TRY003

    with (
        caplog.at_level(logging.ERROR, logger="gateway.app"),
        TestClient(app, raise_server_exceptions=False) as client,
    ):
        response = client.get("/explode")

    # Fixed text and no reflection: the exception's own message does not reach the response.
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert response.json()["error"] == "server_error"
    assert "super-secret-code" not in response.text
    assert "RuntimeError" not in response.text

    # The negative control and the positive measurement together: a record exists, it names
    # the exception type, and the traceback is in it.
    assert caplog.records, "the failure must produce a log record"
    assert any(record.exc_info is not None for record in caplog.records), (
        "the record must carry the traceback"
    )
    rendered = caplog.text
    assert "RuntimeError" in rendered
    assert "explode" in rendered


def test_passing_a_runtime_and_a_different_settings_is_refused(
    runtime: object, private_key_pem: str
) -> None:
    """Two views of one configuration must not disagree.

    The routes read the runtime's settings, so an app built with a different settings
    object beside it would report a configuration it does not use — a debugging trap that
    is cheaper to refuse than to diagnose.
    """
    with pytest.raises(ValueError, match="different settings"):
        create_app(settings=make_settings(), runtime=runtime)  # type: ignore[arg-type]


# ---------------------------------------------------------------- the signing key


def test_signing_key_is_required_at_startup() -> None:
    """A gateway with no key cannot mint a token, so it must not start."""
    with pytest.raises(ConfigurationError, match="gateway_signing_key"):
        make_runtime(make_settings(), "")


def test_signing_key_refuses_a_non_key_value() -> None:
    """The refusal names the expected shape, and never echoes the material."""
    with pytest.raises(ConfigurationError, match="PEM private key"):
        SigningKey("not a key at all")


def test_signing_key_refuses_a_public_key() -> None:
    """A public key is not a signing key, and the failure would otherwise be silent.

    It parses as PEM and looks like key material; only the type check catches it, before
    the first token attempt fails somewhere far away.
    """
    with pytest.raises(ConfigurationError, match="RSA private key"):
        SigningKey(generate_public_key_pem())


def test_signing_key_refuses_a_key_below_the_minimum_size() -> None:
    """An undersized key is identity-provider material with the strength taken out."""
    with pytest.raises(ConfigurationError, match="at least 2048 bits"):
        SigningKey(generate_key_pem(key_size=1024))


def test_jwks_publishes_exactly_the_public_material(signing_key: SigningKey) -> None:
    """The JWKS is the public key and nothing else — no private component, ever."""
    document = signing_key.jwks()

    assert len(document["keys"]) == 1
    jwk = document["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == signing_key.kid
    # The modulus and exponent are what verification needs; the private components (`d`,
    # `p`, `q`, …) have no representation in this document.
    assert set(jwk) == {"kty", "use", "alg", "kid", "n", "e"}


def test_key_id_is_derived_from_the_public_key(signing_key: SigningKey) -> None:
    """Two keys cannot present the same `kid`.

    The id is a hash of the public material, so publishing a new key cannot accidentally
    re-use a name Core already trusts — the property the rotation procedure depends on.
    """
    assert SigningKey(generate_key_pem()).kid != signing_key.kid


def test_signing_key_repr_carries_no_material(signing_key: SigningKey) -> None:
    """A key that renders safely is a key that can be logged by accident safely."""
    rendered = repr(signing_key)

    assert signing_key.kid in rendered
    assert "PRIVATE KEY" not in rendered
    assert "BEGIN" not in rendered


def test_signing_key_is_not_rendered_by_the_settings_object() -> None:
    """The configuration object must be loggable with the key injected."""
    secret = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----"
    settings = make_settings(gateway_signing_key=secret)

    assert secret not in f"{settings!r} {settings.model_dump()}"


def test_no_key_material_appears_in_captured_logs(
    private_key_pem: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The startup path, an audited request, and a served JWKS must not log the key.

    The key is parsed, hashed into a `kid`, and served as a JWKS. Each of those steps
    touches the material, and each of them is exercised here with the log captured.
    """
    caplog.set_level(logging.DEBUG)
    runtime = make_runtime(surface_settings(), private_key_pem)

    with TestClient(create_app(runtime=runtime)) as client:
        # A request that allocates a flow, so it writes an audit record the assertions
        # below can prove the capture holds.
        client.get(
            "/dial/authorize",
            params={
                "response_type": "code",
                "client_id": PRE_REGISTERED_CLIENT_ID,
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "code_challenge": "a-challenge",
                "code_challenge_method": "S256",
                "resource": runtime.settings.toolset_resource_uri(TOOLSET_NAME),
            },
        )
        client.get("/dial/jwks.json")
        client.get("/healthz")

    rendered = "\n".join(record.getMessage() for record in caplog.records)

    # The negative control: the capture is proven to hold this request's audit record, so
    # an absence of key material below is a measurement rather than an empty log.
    assert "flow_allocated" in rendered
    assert PRE_REGISTERED_CLIENT_ID in rendered

    assert "PRIVATE KEY" not in rendered
    assert private_key_pem.strip() not in rendered
    # Not even a fragment of the base64 body: a line of it would be enough to correlate.
    body_line = private_key_pem.strip().splitlines()[1]
    assert body_line not in rendered


def test_env_escaped_newlines_in_the_key_are_restored() -> None:
    """A key that arrives with escaped newlines is still a key.

    An environment variable cannot always carry real newlines, so the escaped form is
    what a secret store or a compose interpolation produces; refusing it would refuse a
    correctly configured deployment.
    """
    pem = generate_key_pem()

    escaped = Settings(
        _env_file=None,
        idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
        roles_source_path="roles",
        gateway_custody_keys={CUSTODY_KEY_ID: CUSTODY_KEY_B64},
        gateway_signing_key=SecretStr(pem.replace("\n", "\\n")),
        idp_client_secret="the-client-secret",
    )

    loaded = load_signing_key(escaped)

    assert loaded.kid == SigningKey(pem).kid


def test_a_token_signed_by_the_key_verifies_against_its_jwks(
    signing_key: SigningKey,
) -> None:
    """The key and the JWKS describe the same keypair.

    This is the property Core relies on: it fetches the JWKS and verifies a token by the
    `kid` in the token's header.
    """
    token = signing_key.sign({"sub": "someone", "iss": "https://example.test"})

    header = jwt.get_unverified_header(token)
    assert header["kid"] == signing_key.kid
    assert header["alg"] == "RS256"
    decoded = jwt.decode(
        token,
        signing_key.public_key(),
        algorithms=["RS256"],
        audience=None,
        options={"verify_aud": False},
    )
    assert decoded["sub"] == "someone"


def test_key_loader_refuses_settings_that_carry_no_key() -> None:
    """A settings object with the key unset is refused by name, before any parsing."""
    settings = Settings(
        _env_file=None,
        idp_sso_session_max_seconds=IDP_LIFESPAN_SECONDS,
        roles_source_path="roles",
        gateway_custody_keys={CUSTODY_KEY_ID: CUSTODY_KEY_B64},
        idp_client_secret="the-client-secret",
    )

    with pytest.raises(ConfigurationError, match="not set"):
        load_signing_key(settings)


# ------------------------------------------------- the CORS/back-channel posture pin


def test_no_as_surface_endpoint_serves_a_cors_header(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The authorization-server surface is back-channel only: no `Access-Control-*` anywhere.

    The posture today is true by omission — no CORS middleware exists — which is exactly why
    it needs a pin: one future `add_middleware(CORSMiddleware)` line, added for some
    unrelated convenience, would silently open the token endpoint to browser origins. The
    test walks every endpoint of the surface — the browser-facing routes and the back-channel
    ones alike — and asserts no response carries any `Access-Control-*` header, so the
    posture cannot drift without this failing.
    """
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )
    with make_client(settings, private_key_pem) as client:
        requests: list[tuple[str, str]] = [
            ("GET", "/dial/authorize"),
            ("GET", "/dial/callback/idp"),
            ("GET", "/dial/callback/upstream"),
            ("POST", "/dial/consent"),
            ("POST", "/dial/token"),
            ("POST", "/dial/revoke"),
            ("GET", "/.well-known/oauth-authorization-server"),
            ("GET", "/.well-known/openid-configuration"),
            ("GET", "/.well-known/oauth-authorization-server/apps/skills-demo/mcp"),
            ("GET", "/.well-known/openid-configuration/dial/notion/mcp"),
            ("GET", "/.well-known/oauth-protected-resource/dial/notion/mcp"),
            ("POST", "/dial/register"),
        ]
        for method, path in requests:
            response = client.request(method, path)
            leaked = [
                name
                for name in response.headers
                if name.lower().startswith("access-control-")
            ]
            assert not leaked, f"{method} {path} served {leaked}"


def test_an_options_preflight_at_the_token_endpoint_is_the_frameworks_405(
    private_key_pem: str, tmp_path: Path
) -> None:
    """No preflight is handled: `OPTIONS /dial/token` is the framework's method refusal.

    RFC 9700 §2.6 permits CORS at the token endpoint as a MAY; the gateway declines it,
    surface-wide, and declines the preflight with it — so the answer is the framework's own
    405 for a method no route serves, with no CORS headers beside it. A browser frontend is
    not a supported client shape.
    """
    settings = surface_settings(
        dcr_enabled=True, dcr_store_path=str(tmp_path / "store.json")
    )
    with make_client(settings, private_key_pem) as client:
        response = client.request("OPTIONS", "/dial/token")

    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED
    assert not [n for n in response.headers if n.lower().startswith("access-control-")]
