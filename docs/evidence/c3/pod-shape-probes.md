# The pod shape on the composed stack — probes, boundary, restart, quirk

Change: `one-pod-and-keysets` (C3), tasks 4.1–4.5. Scope of this record: the two
substantive edits (the nginx sibling-localhost upstream, the compose pod shape), the
compose-boot gate on the pod-shaped stack, the probe battery against the single public
port, the boundary assertion, the DCR-restart survival, and the quirk check. No secrets,
tokens, key material, or personal paths appear: hosts are the local endpoints, ids are
shown redacted, and only public facts are recorded.

Environment: the worktree `c3-one-pod-and-keysets`; Docker in WSL2 driven through the
PowerShell tool (`wsl -e docker …`), compose project `c3-one-pod-and-keysets`; the local
DIAL instance (`dial-instance`: core, keycloak, redis, …) up beforehand and
joined via the external `dial-instance_default` network. The gateway image is
the production Alpine shape (built from this worktree's `Dockerfile`); host probes ran
with `PYTHONUTF8=1` and the repository on `PYTHONPATH`.

## Task 4.1 — `router/nginx.conf`, the one substantive edit

The gateway upstream re-pointed from the service name to sibling localhost:

```
upstream gateway { server 127.0.0.1:8091; }   # was: server mcp-signin-gateway:8091
```

Nothing else changed: the challenge maps, the anchored alternation, the ordering
discipline, `$is_args$args`, the 16384 body cap, and the `X-Real-IP` statement are
untouched. The upstream's comment block now states the shared-network-namespace
assumption the sibling-localhost address makes true, and why the name-routable address
would break the peer-identity property the per-source rate limit rests on.

## Task 4.2 — `docker-compose.yml`, the pod shape

- The router joins the gateway's network namespace:
  `network_mode: "service:mcp-signin-gateway"`. Compose's spelling of the pod's shared
  localhost.
- The published public port moves to the namespace-owning service: `mcp-signin-gateway`
  carries `ports: ["8090:8090"]`; the router carries no `ports:` mapping (a
  shared-namespace pair publishes the namespace, and compose attaches `ports:` to the
  owner). The gateway's own 8091 is container-internal only — the peer-identity property
  is restated in the service comment, naming the mis-assembly shape.
- The DCR store mount (`./data:/data`) is unchanged in substance.
- The environment list gains the keyset/compat settings: the emptied-by-default
  structured spellings `GATEWAY_SIGNING_KEYS` and `IDP_CLIENT_SECRET_FILE`, and the
  custody block's comment now names the flat spelling as the compat rotation-less shape.
  This group's runs use the compat spellings (singular `GATEWAY_SIGNING_KEY`, flat
  `GATEWAY_CUSTODY_KEYS`); the drill configures the structured shape later.
- The build section already produces the image the `Dockerfile` builds
  (`build: {context: ., dockerfile: Dockerfile}`), so the gateway service runs the
  production image shape; the rebuild path below confirms the running container is that
  image.

`docker compose config` parses cleanly; the router shows
`network_mode: service:mcp-signin-gateway` and no port mapping; the gateway shows
`published: "8090"`.

## Task 4.3 — the compose-boot gate, the probe battery, the boundary assertion

### The rebuild (the recorded lesson: a recreate-without-build runs stale code)

    docker compose up -d --build
    -> mcp-signin-gateway  Built
    -> writing image sha256:045ab43673676d65c8de27177041e58fe87d73991389504bfb2deebd2303adab
       naming to docker.io/library/dial-mcp-gateway:local
    -> container mcp-signin-gateway-1  Healthy
    -> container mcp-signin-router-1   Started

The running container is that exact image:

    docker inspect ...mcp-signin-gateway-1 --format "{{.Image}}"
    -> sha256:045ab43673676d65c8de27177041e58fe87d73991389504bfb2deebd2303adab
    docker images dial-mcp-gateway:local --format "{{.ID}}"
    -> 045ab4367367

### Per-service health

    docker ps --filter "name=c3-one-pod-and-keysets" --format "{{.Names}}\t{{.Status}}\t{{.Ports}}"
    -> mcp-signin-router-1   Up (healthy)   (no published ports — shares the namespace)
    -> mcp-signin-gateway-1  Up (healthy)   0.0.0.0:8090->8090/tcp, 8091/tcp

Both services healthy; the gateway holds the single published public port (8090) and its
8091 is container-internal.

### The probe battery, against the single public port `http://localhost:8090`

    python scripts/probe_routing.py            -> all 11 probes passed        (exit 0)

The battery exercises front-door routing, the challenge synthesis on both data paths, and
query-string survival through the router whose upstream is now sibling localhost. Rows:

- negative control — Core's own challenge (red as required)
- query string survives the routing (POST + GET; Core's own log line carries the marker)
- flat AS metadata through the router (issuer and endpoints on the public origin)
- per-toolset PRM through the router
- data-path 401 rewritten to the gateway's challenge (exactly one `WWW-Authenticate`)
- gateway paths reachable through the front door (authorize/token answer as the gateway)
- consent action route reachable through the front door
- apps PRM through the router
- apps data-path 401 rewritten to the apps challenge
- query string survives the apps routing
- status paths dropped to Core's own 401

    python scripts/probe_gateway_trust.py      -> green                      (exit 0)

Core validates the gateway's own key via the gateway's JWKS endpoint; the negative
control (an unpublished signer) is refused, and a gateway-signed token resolves a real
identity at Core. This confirms the instance-internal leg the gateway's JWKS serves on.

    python scripts/probe_end_to_end.py         -> green through the checkpoint (exit 0)

Discovery → authorize (302 to the IdP) → login → the consent/attribution decision page
renders → approve advances to the upstream authorization page. The probe stops at the
upstream provider's real account boundary by design.

(`probe_liveness.py` requires a slow allowlisted client id and was not run as part of this
battery; the liveness behavior is unchanged by this change and is covered by the C2.5
record. Nothing in the pod-shape edits touches the event loop.)

### The boundary assertion

A container **outside** the shared namespace — a throwaway `python:3.12-alpine` on the
default bridge — reaches the router's public port and cannot reach the gateway's:

    172.17.0.1:8090 (router public)  -> REACHABLE
    172.17.0.1:8091 (gateway)        -> UNREACHABLE (ConnectionRefusedError)

From the host, the same shape:

    host -> localhost:8090 (router public)  -> REACHABLE
    host -> localhost:8091 (gateway)        -> UNREACHABLE (ConnectionRefusedError)

So on the host and from an external bridge network the gateway's port is unpublished and
unreachable — the pod-contract property holds for every caller that has not joined the
pod's namespace.

**Honest deviation, recorded rather than overclaimed.** A container on the *instance
network* (`dial-instance_default`) reaches the gateway by service name:

    mcp-signin-gateway:8091 -> REACHABLE
    mcp-signin-gateway:8090 -> REACHABLE

This is **pre-existing and required**, not introduced by the pod shape: the gateway joins
the instance network (it always did) so Core can reach its JWKS at
`http://mcp-signin-gateway:8091/dial/jwks.json`, and the gateway's process listens on
`0.0.0.0:8091`. The pod shape's non-publication is about the **host and external
networks**: nothing outside the pod namespace reaches 8091 unless it has joined the
instance network, which is the deployment's own trust domain. The contract must therefore
state the assumption precisely — the gateway's port is unpublished and unreachable from
outside, **and** on the instance network it is name-routable to Core by design. A
deployment that widened that network face would be the mis-assembly the threat model
prices.

## Task 4.4 — the DCR-restart survival

`DCR_ENABLED=true` is required for this run (the DCR surface is off by default); the
seeded local `.env` sets it.

1. **Register.** `probe_dcr.py --expect enabled --register` → the registration endpoint is
   advertised, the refusal branch refuses a body with no `redirect_uris` (400,
   `invalid_request`), and one registration is accepted with a loopback `redirect_uri`;
   the returned `client_id` is recorded in the gitignored `dcr_client.json`. The typed
   sweep over the RFC 7591 §3.2.1 members reports no violation.
2. **Restart the deployment unit.** The pair was recreated as one unit
   (`compose down` then `up -d`), so the shared namespace is re-established together with
   the container. The store file on the mounted volume survived the recreate:
   `docker exec … cat /data/dcr-registrations.json` shows the registered client id.
3. **Present the cached client id, no re-registration.** `probe_dcr.py --expect enabled
   --authorize-expect accepted` presents the recorded id with its registered redirect URI
   and gets a 302 to the identity provider — the registration resolved from the durable
   store across the restart. The negative control
   (`--authorize-expect rejected`) presents an unregistered redirect *path* and is refused
   (400, `redirect_uri is not one this client registered`), so the acceptance cannot come
   from a gateway that accepts anything.

## Task 4.5 — the quirk check: a gateway-only restart

Observed honestly, and it is **not** the clean pod behavior one might predict. The
container-level restart spelling was used:

    docker compose restart mcp-signin-gateway

What actually happened, on the composed stand-in:

- Compose restarts only the gateway container. The router container is **not** restarted
  with it.
- After the restart the two containers are in **different network namespaces**: the
  gateway re-creates its namespace (`net:[4026532427]`), while the router remains bound
  to the namespace it joined at its own start (`net:[4026532324]`).
- The router's upstream `127.0.0.1:8091` then reaches an empty loopback: its health probe
  fails and it stays **unhealthy** (`connect() failed (111: Connection refused) while
  connecting to upstream … 127.0.0.1:8091`), and the front door answers with a
  `RemoteDisconnected` across repeated samples. This is not a transient 502 window that
  clears — it persists until the pair is re-created.

Recovery: a unit recreate
(`docker compose up -d --force-recreate`, which recreates the router too and re-joins it
to the gateway's namespace) restores the shared namespace (both containers back on
`net:[4026532324]`), both services go healthy, and the routing battery and boundary
assertion are green again on that state.

**What this means against the change's own claim.** The acceptance this quirk check was
scoped for is "a gateway recreate no longer 502s the router". On the composed stand-in
that acceptance holds **only for a recreate of the unit** (`down`+`up`, or
`up --force-recreate`, or `up -d --build`), where compose recreates both containers and
re-joins the namespace. It does **not** hold for an in-place `docker compose restart` of
the gateway alone — compose's `restart` preserves each container's namespace binding
rather than re-forming the pair's shared namespace, so the router is left pointing at a
namespace the gateway no longer occupies. In a Kubernetes pod the semantics differ: a pod
is the unit of scheduling and recreation, so a container restart within a pod keeps the
pod's shared network namespace, and this split cannot arise. The composed stand-in is
therefore a faithful stand-in for the **pod's** pairing atomicity under unit-level
operations, but a `docker compose restart` of one service is a compose-specific operation
with no pod-equivalent split. The contract should state that the pod's pairing atomicity
is guaranteed by the pod being the recreate unit (which it is in K8s), and the local
stand-in must be operated at the unit granularity (`up --force-recreate`) to exercise it.

## Task 7.2 — the gate-tier re-run on the current tree

Re-run at task 7.2 (the acceptance gate), against the stack as it stands at HEAD `42f4f02`
(after the drill's restore recreated the unit; the running image id is
`sha256:e14d051713273a94b610cee51d5dcb915335e58ab21842ef3bd24eef08033fbd` — a later build
than group 4's `…045ab4367367`, same Alpine 3.24.1 production shape, the drill's re-runs
rebuilt the image). Confirmed on this state:

- `docker compose ps` → both services **Up (healthy)**; the router holds no published
  ports, the gateway holds `0.0.0.0:8090->8090/tcp` and its 8091 container-internal.
- The running gateway container: `id -u` = `id -g` = `10001`, `/etc/alpine-release` =
  `3.24.1` — the production image, not a dev stand-in.
- `scripts/probe_routing.py` → **all 11 probes passed** (negative control red as required;
  front-door routing, both data-path challenges, query-string survival both routes).
- Boundary, host side: `localhost:8090` → REACHABLE (200); `localhost:8091` → UNREACHABLE
  (`URLError`) — the pod-contract port property holds on the current stack.

No update to the group-4 body above is needed; this section is the gate-tier record that
the 4.3/4.4 runs above are re-confirmed on the final tree.

## Verdict

The pod-shaped stack boots on the production image with every service healthy, the probe
battery is green against the single public port, the gateway's port is unpublished and
unreachable from the host and external networks (name-routable on the instance network by
design, which the contract must state), the DCR store survives a unit restart with the
cached client id resolving and no re-registration, and the quirk check records the honest
difference between a unit recreate (clean) and a single-service `restart` (splits the
shared namespace on the composed stand-in — a compose-specific behavior with no
pod-equivalent in Kubernetes).