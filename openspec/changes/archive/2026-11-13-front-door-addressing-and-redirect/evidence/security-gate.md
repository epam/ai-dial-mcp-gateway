# Security review gate — front-door addressing and redirect

An independent reviewer subagent reviewed the change's diff against its security impact
analysis and the threat model (the security review gate, gate 4 of the repo rules).

## Verdict

**PASS** — zero blocking findings, one should-fix (SF-1), four notes (N-1…N-4).

The change's central claim — one canonical identity per resource across resolution, the
token audience, and the refresh match — holds on every resolution site except the one
SF-1 names. The guard, the redirect, and the read URL build were reviewed against their
threat-table rows; no blocking finding survived. Notes recorded without a change: N-1 and
N-2 are captured as residual notes in `design.md` §9 (the strict gap list); N-3 and N-4
are review-process observations that carry no code consequence. The full report lives with
the orchestrator's gate record.

## SF-1 — remediation

**Finding.** `gateway/authorize.py` `_resolve_resource`, the
`gateway_infer_resource_single_toolset` branch: the single configured `TOOLSETS` entry was
used raw as both the resolved `path` and the input to `toolset_resource_uri(entry)`, while
the sibling resolution path canonicalizes (`canonical = settings.canonical_path(path) or
path`). The delta spec's identity clause and M37 make canonicalization normative at every
resolution site. A guard-passing but non-canonical configured entry (e.g. `notio%6E`)
survives startup validation and reached this branch raw; the branch then failed closed —
the code grant's canonical-vs-canonical match could never succeed — but the one-identity
rule was violated and the inference escape hatch broke for that configuration.

**Fix.** One logical change, mirroring the sibling path's idiom: canonicalize the entry
before deriving the resolved path and the resource URI.

```
entry = next(iter(settings.toolsets))
canonical = settings.canonical_path(entry) or entry
return _ResolvedResource(
    kind="toolset",
    path=canonical,
    resource_uri=settings.toolset_resource_uri(canonical),
)
```

The resolved `path`, the resource URI, and everything downstream (the flow record's
`toolset` and `resource`, the token audience, the refresh match) now carry the canonical
form whatever the operator's spelling.

**Unit rows added** (`tests/test_authorize.py`):

`test_one_toolset_inference_canonicalizes_a_non_canonical_entry`, parametrized over an
over-escaped unreserved spelling (`notio%6E`) and its lowercase-hex twin (`notio%6e`).
Each asserts the inference branch resolves the entry to the canonical identity: the flow
record's `toolset` is `notion` and its `resource` is `http://localhost:8090/dial/notion/mcp`
— never the entry's own spelling.

**Negative control.** With the fix reverted, both rows fail with the raw spelling carried
through (`notio%6e`), proving the rows measure the fix.

**Results.** Full suite `pytest -q`: 761 passed, 1 skipped (759 + the 2 new rows).
`ruff check` clean on both touched files; `ruff format --check` clean modulo the
checkout's CRLF line endings (a pre-existing Windows working-tree condition on every file,
not introduced here).