# Finding — the DCR store's bind mount is on DrvFs, where the atomic save's `chmod` fails

Found during group 8 (DCR live verification), task 8.2. Recorded for the def
cycle; no behavioral fix applied in this group.

## Symptom

With `DCR_ENABLED=true` and the gateway recreated, a registration the endpoint's own
validation accepts is refused with a **500-class failure reported as 400**:

```
POST http://localhost:8090/dial/register  {"client_name":"group8-dcr-probe",
     "redirect_uris":["http://127.0.0.1:8768/callback"]}
-> HTTP 400
{"error":"invalid_request",
 "error_description":"the registration could not be written to the gateway's store at
 /data/dcr-registrations.json; no registration was created. An administrator should
 check that the volume is writable."}
```

The store file is never created: `ls /data` inside the container shows only `.gitkeep`
and the leftover temporary file of the failed save.

## Evidence

The mount is writable — the error's own suggestion is wrong, which is why the diagnosis
had to go below it:

```
$ wsl -e docker exec ai-dial-mcp-gateway-mcp-signin-gateway-1 sh -c "touch /data/x && echo OK && rm /data/x"
OK
```

The save's own sequence, replayed in the container, localizes the failing call to
`chmod`:

```
mkstemp ok /data/dcr-registrations.json.clne0z8p.tmp
write ok
FAILED PermissionError [Errno 1] Operation not permitted:
  '/data/dcr-registrations.json.clne0z8p.tmp'
```

Isolated to the two calls in order:

```
chmod  -> OSError 1 [Errno 1] Operation not permitted: '/data/t.ufqcy297.tmp'
replace -> ok
```

The same `chmod` on a pre-existing file also fails (`chmod 600 /data/.gitkeep` exits
non-zero), so the refusal is not about file ownership or the temp file's mode.

## Root cause

`gateway/store.py`'s `_save()` performs, in order: `mkstemp` in the store's directory,
write, `fsync`, **`temporary.chmod(0o600)`**, then `replace()`. `chmod` is called
*outside* the `try` that owns the write path, so its `OSError` propagates as an
unexpected failure — but it is the `chmod` that the underlying filesystem refuses.

The compose file bind-mounts the store from a **Windows host path**:

```yaml
- ./data:/data
```

On this deployment's WSL2 arrangement that path is `C:\...`, which reaches WSL as the
**DrvFs** (9p) filesystem (`C:\ on /mnt/c type 9p (... uid=1000,gid=1000 ...)`), not as
a native Linux filesystem. DrvFs does not implement POSIX permission changes: every file
presents the fixed `drwxrwxrwx`-shaped modes its mount options give it (`fmask=222`
in the mount line above), and `chmod(2)` on a file there returns `EPERM`. So the
owner-only mode the store's design requires cannot be set on this mount at all, and
every accepted registration fails at the save.

**The unit suite cannot see this.** Group 3.6's store tests run on the host filesystem
(`tmp_path`, and on Windows `os.chmod` is a near-no-op that succeeds), while the
enforcement is asserted in the Linux container — as group 6 recorded, that is the
skipped Windows test. Nothing in the suite composes the store with the mount the
compose file actually declares, so the failure exists only in the composed stack — the
class of gap the compose-boot gate exists to catch, and the check group 7's gate did
run: it starts the stack, but with `DCR_ENABLED` at its default **off**, so the save
path is never entered.

## Proposed fix (for the def cycle — not applied here)

Options, cheapest first; the spec gate decides whether the chosen one is a behavior
change:

1. **Deployment-level, no spec change:** move the store's bind mount off the Windows
   host path — a Docker **named volume**, or a WSL-native directory (e.g. under the
   Linux home, bind-mounted by absolute path). A named volume is on the VM's native
   filesystem, where `chmod` is enforced, and it keeps the
   "state-outlives-recreation" property the mount exists for. It gives up the
   host-visible path that D11 chose the bind mount for (an operator renaming a corrupt
   store aside by path); the equivalent operation becomes
   `docker run --rm -v <volume>:/data ... mv /data/dcr-registrations.json
   /data/dcr-registrations.json.corrupt`.
2. **Code-level, tolerance:** treat a `chmod` failure as non-fatal — the file mode is a
   hardening measure, not the durability the store exists for — and let the rename
   proceed, so a store on a filesystem without POSIX modes still works. This keeps the
   bind mount and the corrupt-store recovery-by-path, at the cost of the owner-only mode
   being best-effort rather than guaranteed. The mode assertion in the store's tests
   would then need to state the tolerance explicitly.
3. **Both:** tolerant `chmod` (2) plus a documented deployment note that the mount
   should be on a Linux-native filesystem for the mode to be enforced.

Whichever is chosen, the fix should come with a composed-stack check that exercises the
save path — the gap that let this reach group 8 is that no gate had ever run the store
against the mount the compose file declares.

## Resolution (authoring pass)

The design ruling is landed — design and tasks only; the code fix is the next
implementation pass, not done here.

- **Ruling: the owner-only mode is best-effort hardening, never a guarantee — and the
  mount stays a bind mount** (the finding's option 2, with the mount question ruled
  against option 1). The tamper-boundary ruling the design already carries — store
  integrity is the host/volume owner's responsibility, the same trust boundary and
  material class as the signing key — **is** the guarantee; the mode was defense-in-depth
  inside it. On this host the signing key itself arrives through `.env` on the same
  Windows-path repo folder the bind mount serves, so the boundary is already the
  operative control for material far more sensitive than the store — which holds no
  secret at all (client ids, redirect URIs, a display name, a timestamp; every client
  is public PKCE). On a mount without POSIX modes every file in the volume is equally
  world-shaped, so the mode there is unenforceable in principle, not an implementation
  gap. Moving the store to a Docker named volume (option 1) was rejected: it trades the
  operator-visible-by-path shape the bind mount was chosen for (corrupt-store recovery
  is one command by path — the remedy the startup error itself states — and a lost
  store is a visible missing file) for hardening the boundary already carries, while
  leaving the save hard-requiring a filesystem any future non-POSIX deployment would
  withhold in the same way; the tolerance belongs in the save, not in the deployment.
  Refusing DCR on such a host (option 3's shape) was rejected on the constraint the PoC
  runs on this Windows+WSL2 host. Nothing is lost where the mode is enforceable: on a
  POSIX-enforcing volume the owner-only mode lands exactly as before.
- **design.md (D11):** the write-through bullet now states the atomic save with the
  owner-only mode as best-effort — a filesystem that refuses permission changes is
  tolerated with a logged warning naming the store path, the rename proceeds, and a
  registration is never refused for it. The tamper-boundary bullet states the mode's
  position inside the host/volume-owner boundary and records the bind-mount-stays
  ruling with its reason.
- **Spec ruling: no ripple.** The durability requirement's scenarios pin
  persistence-before-response, restart persistence, dormancy/re-enable,
  corrupt-store startup refusal, lost-store self-healing, and the cap — none pins the
  file mode or the mount kind, and the requirement's "written atomically to one JSON
  file in a mounted volume" is unchanged: atomicity is the temporary file plus rename,
  which this mount does support (the isolation above showed `replace → ok`). The mode
  existed only as design text (D11), and the ruling lands there.
- **tasks.md:** a new **task 3.12** in group 3 (the 3.10/3.11 precedent of a
  field-diagnosed fix landing as its own task) — the tolerant `_save()` with the logged
  warning, the unit tests stating the tolerance explicitly, the `docker-compose.yml`
  store-volume comment and the docs DCR section aligned, and the composed-stack re-run
  that closes the gate gap this defect passed through: the 8.2 registration checks
  re-run with `DCR_ENABLED=true` on the committed `./data:/data` bind mount as this
  host mounts it, with the restart-persistence check, evidence to `evidence/dcr.md`.
- **Left for the next pass:** the `store.py` fix, the tests, the compose/docs alignment,
  and the composed re-run; no gateway source, spec, or configuration was changed in
  this pass.

`openspec validate --changes --strict` was re-run green after these edits.

## Resolution (implementation pass, task 3.12) — CLOSED

The implementation pass landed and the live-verification open item above is **CLOSED**.
All captures are in `evidence/dcr.md`'s "Task 3.12 — the composed-stack re-run" section.

- **Code fix:** `gateway/store.py`'s `_save()` wraps the pre-rename `chmod(0o600)` in its
  own `try/except OSError`. A refused mode change is logged at warning level naming the
  store path and the rename proceeds; a registration is never refused for it. The write
  path's own `OSError` handling (mkstemp/write/fsync/replace) is unchanged — a failed
  rename still refuses the registration and leaves no temporary file behind.
- **Tests:** three new tests in `tests/test_store.py` state the tolerance explicitly — a
  refused mode (`Path.chmod` patched to raise `EPERM`) proceeds with a logged warning
  naming the path, the record persisted, and no error propagated; a refused mode leaves
  persisted records unchanged; a refused rename still refuses with the corruption-class
  behavior. Suite: 335 passed, 1 skipped.
- **Texts aligned:** the `docker-compose.yml` store-volume comment and the DCR section of
  `docs/gateway-configuration.md` now state the mode as best-effort — enforced only where
  the mounted filesystem implements POSIX permission changes, and on a mount that does not,
  a logged warning naming the path with the host/volume-owner boundary carrying the
  exposure.
- **The gate gap closed live:** with `DCR_ENABLED=true` and the **committed `./data:/data`
  bind mount** (no ext4 override), a registration returns `201`, the store file gains
  exactly one record with no temporary file and no secret material, the gateway log
  carries the mode warning naming `/data/dcr-registrations.json`, the restart-persistence
  check over the same mount passes (the authorization request is accepted on the same
  client id, and the store file's hash is unchanged by the restart), and the deployment
  was returned to its default state (`DCR_ENABLED` off, metadata advertises no endpoint,
  `POST /dial/register` answers the documented `404`, the store file preserved).

  **One deployment fact from that run, recorded because it changes how the compose-boot
  gate should be run:** `docker compose up --force-recreate` recreates from the *existing
  image* and does not rebuild it. The first re-run after the code change therefore
  reproduced the original failure verbatim, because the container still held the pre-fix
  image; `docker compose build mcp-signin-gateway` before the recreate produced the green
  result. A `--force-recreate` alone measures the last build, not the working tree.