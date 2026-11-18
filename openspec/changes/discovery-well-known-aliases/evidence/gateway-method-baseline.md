# The gateway's method and 404 baseline on the discovery surface

Measured 2026-11-16 against the current gateway app (FastAPI 0.162.0, Starlette 1.10.0)
through the test suite's own client factory (`tests/test_app.py`'s `surface_settings` and
`make_client`), in a throwaway test module that was deleted after the run. No router is
involved: this is what the gateway app itself answers.

| Request | Status | `Content-Type` | `Allow` | `Access-Control-*` |
|---|---|---|---|---|
| `GET /.well-known/oauth-authorization-server` | 200 | `application/json` | — | none |
| `HEAD /.well-known/oauth-authorization-server` | 405 | `application/json` | `GET` | none |
| `OPTIONS /.well-known/oauth-authorization-server` | 405 | `application/json` | `GET` | none |
| `POST /.well-known/oauth-authorization-server` | 405 | `application/json` | `GET` | none |
| `GET /.well-known/openid-configuration` | 404 | `application/json`, body `{"detail":"Not Found"}` | — | none |
| `GET /.well-known/foo` | 404 | `application/json`, body `{"detail":"Not Found"}` | — | none |

Two facts the design uses:

- **The canonical route's method behavior is the framework's** — `GET` only, `HEAD`
  included in the `405` set (FastAPI's `APIRoute` does not add `HEAD` to a `GET`
  route). The aliases inherit exactly this behavior by being registered on the same
  handler (design.md, D6).
- **The gateway's own unrouted 404 body is `{"detail":"Not Found"}` as
  `application/json`.** The router's closed-namespace `404` uses the same literal body
  and type, so a client sees one 404 shape whichever of the two answers (design.md, D4).
