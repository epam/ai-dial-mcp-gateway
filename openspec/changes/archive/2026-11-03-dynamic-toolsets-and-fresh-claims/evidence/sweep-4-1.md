# Task 4.1 landing + task 5.8 sweep — `docs/threat-model.md`

The threat-model landing pass for `dynamic-toolsets-and-fresh-claims`: task 4.1's
edit list applied to `docs/threat-model.md`, then the task 5.8 mechanical
completeness sweep run against the result. One file edited (`docs/threat-model.md`);
this record is the only evidence write.

## What was edited (the edit map)

**Header / at-a-glance.** Counts recomputed from the actual delta: **17 assets**;
**62 threats** (EP1 21, EP2 6, EP3 10, EP4 8, EP5 7, EP6 7, EP7 3); **23 residual
records** (22 disclosed open + RES-18 closed); **22 grouped mitigations**; the
revocation-summary table noted as new. Verified by counting the tables' rows
(`grep -c` per EP prefix, `^- \*\*RES-`, `^| A`, `^| M`).

**§1 The system as it stands.** Refresh-token sentence: the snapshot is deleted —
claims re-read fresh at every refresh, the token carries the encrypted custody
claim. Startup-check sentence: renamed onto `IDP_SSO_SESSION_MAX_SECONDS` as an
operator assertion about the provider's session policy. State inventory: the
minutes-bounded pending custody entries added; the process's persistent secrets
named as the signing key and the custody key; no long-lived per-session store. P3
sentences: the served set follows the request-time guard and the optional
restriction (discovery mirrors Core's registry-independent tier), the kind check is
the upstream stage's branch.

**§2 Impact.** Sensitive-asset sentence gains the custody key.

**§3 Register.** Amended: RES-2 (two persistent secrets; never-store exception),
RES-3 (token-use purposes incl. the ciphertext-delivered-once-per-rotation clause),
RES-4 (refresh grant joins the slow legs; "the one attacker-steered slow leg" no
longer names the set), RES-6 (bound shrinks to the access TTL), RES-9 (use vs
establish), RES-10 (second re-shape: the OAUTH-only class gone; the
impossible-branch loop the remaining residual), RES-15 (narrowed to a gain with the
stolen-token regression), RES-16 (startup half re-scoped), RES-19 (refresh-grant leg
gains: any-claims-for-an-existing-`sub` forgery, decrypted provider session refresh
token sniffing). Added: RES-20, RES-21 (four parts), RES-22, RES-23.

**§4 Assets.** A4 amended (no snapshot; carries A17); A5 amended (pending custody
entry); new A16 (custody key), A17 (encrypted custody claim at rest).

**§5 / §6 / §7 descriptive.** TB4 memory list gains the custody key, the transient
plaintext, the pending entries; attacker 2's enumeration goes to the dynamic-mode
set; EP1 description gains the guard-decided tier and the short-circuit; EP4 gains
the custody key and the custody seam; EP5 gains the refresh grant and the kind /
signed-in decisions, with the "no discovery leg" note.

**§8 Threat tables.** Amended: T1-4 (OQ-1 resolved in-line), T1-15 (widened set +
mirror bound), T1-16 (staleness rewritten to access TTL), T5-3 (existence edge).
Added rows: T1-17, T1-18, T1-19, T1-21, T1-22 (EP1); T4-8 (EP4); T5-7 (EP5). The
refresh-grant forgery/sniffing gains fold into T5-2's existing row; the
kind/signed-in branch-steering into T5-3's.

**§9 Grids.** T1-4 control 5 (access-token mint named; refresh no-marker `aud`),
T1-7 (per-request cost + the widened slow-leg set), T1-15 (dynamic enumerable set +
mirror bound), T1-16 (full rewrite), T4-2 (two secrets, no per-session store),
T5-1 (refresh-token purposes), T5-2 (control 4 extended), T5-3 (existence edge),
T5-4 (use-vs-establish, §8 row + controls + disposition), T6-2 control 4 (split),
T6-7 controls 6/7 (split).

**§10 Compromise / revocation.** Gateway-process row re-priced (custody key,
transient plaintext, no whole-store harvest); internal-compose-network row gains the
decrypted provider session refresh token; new **revocation-summary table**, carried
from `background/design.md` §6.3, with the re-priced IdP-session row.

**§11 Invariants.** Row 3 (GLOBAL-use sentence added), row 4 (bound shrinks).

**§12 Grouped mitigations.** M9 (snapshot-free refresh token; token-type
separation), M10 (OAuth-declaration removal; the moved halves), M13 (D5 amendment),
new M21, new M23. (Consult era's M22 is deleted with the consult — not landed.)

**§13 Dispositions.** T1-4, T1-7, T1-15, T1-16 amended; T1-17, T1-18, T1-19, T1-21,
T1-22, T4-2, T4-8, T5-2, T5-3, T5-4, T5-7 as the dispositions above.

**§14 OQ-1 resolved** (source `gateway/status.py:111-122`, dated 2026-11-01), moved
from the open to the resolved record.

## Final counts (counted, not copied)

| Table | Count |
|---|---|
| Assets (§4) | 17 |
| Threats (§8) | 62 — EP1 21, EP2 6, EP3 10, EP4 8, EP5 7, EP6 7, EP7 3 |
| Residual records (§3) | 23 (22 open + RES-18 closed) |
| Grouped mitigations (§12) | 22 |
| Revocation-summary table (§10) | new |

## Task 5.8 sweep — command list and result

Run against `docs/threat-model.md` after the edit pass. Each phrase-class grepped;
every hit either matches an explicit §7/task-4.1 list entry (an intentionally
retained or re-shaped statement — the file's own new-text homes) or is a defect.
**Result: zero stale hits.** The consult-era phrase-class has no hit at all: the
deleted consult never landed a model row.

| Phrase-class | Pattern | Hits | Verdict |
|---|---|---|---|
| pre-v3 store wording | `per-session store\|retention store\|keyed retention` | 4 (lines 593, 1287, 1839 + one within RES-2's new text) | All are the **negated** new wording ("there is no per-session store"); list entries. Not stale. |
| frozen / role snapshot | `snapshot` | 9 (lines 78, 180, 325, 396, 549, 963, 1736, 1773, 1776) | Each is the new snapshot-free wording or a "replaced the snapshot design" note; all list entries. Not stale. |
| userinfo mechanism | `userinfo\|claim source\|claim-source\|claim reachab` | 0 | No hit — the userinfo mechanism never landed in the model. |
| startup-only enforcement | `startup on every mapping entry\|checked once at startup\|at startup on every` | 3 (620, 1634, 1639) | Each carries the new configured-entry-only split ("*configured* restriction entry"; "for configured entries"); list entries (T6-7 / EP6 row / M10). Not stale. |
| OQ-1 as open | `OQ-1` | 1 (1890) | The single remaining occurrence is the §14 **resolved** record; T1-4's row (§8) and disposition (§13) carry the resolved statement. Not stale. |
| USER-level-only / GLOBAL-operator-action without use-vs-establish | `USER level only\|GLOBAL/app-level sign-in\|stays an operator action\|signs in at USER` | 2 (200, 602) | Both carry the use-vs-establish form (RES-9; T5-4's §8 row — "*establishes* at USER level only ... GLOBAL-level *use* ..."). List entries (RES-9, T5-4). Not stale. |
| unqualified `aud = [resource, marker]` mint | `aud = \[` | 3 (64, 719, 1776) | Line 64 and 719 name the access token's mint as the subject and state the refresh token's no-marker `aud`; line 1776 (M9) does the same. Amended by the token-type-separation pin. Not stale. |
| consult-era discovery vocabulary | `consult\|service key\|service-key\|dial_core_api_key\|concurrency bound\|503\|OQ-I\|RES-24` (case-insensitive) | 2 (513, 607) | Line 513 is the new "(No discovery leg exists here: the deleted consult ...)" note; line 607 is DT-EP5-3's merged-threat wording. Both are the **deletion's own record**, not a stale leak. Not stale. |
| pre-change / intermediate counts | `55 threat\|19 residual\|15 assets\|20 grouped\|59 threat\|23 residual\|17 assets\|21 grouped\|65 threat\|24 residual\|18 assets\|23 grouped` | 2 (27, 29) | Both are the new at-a-glance line ("17 assets", "62 threats ... 23 residual"). The old literal counts (55/19/15/20, 59/23/17/21, 65/24/18/23) appear nowhere. Not stale. |

Additional falsification greps run: `OAUTH-only\|no escape\|stays open\|phantom-refused\|M22\|mapped toolset` → 0 hits; `frozen\|role-snapshot\|snapshot-minted` → only the new negated/asterisk-note wording. The `accessTokenLifespan` occurrences (lines 81-83, 131, 599, 1293, 1397, 1836, 1843) are all the realm's own identity-token lifespan in unchanged contexts (in-flight token post-lift life, upstream-owned), never the retired startup check — which now reads `IDP_SSO_SESSION_MAX_SECONDS`.

No conflict or out-of-list defect was found that required a stop: every prescribed
§7 wording matched the model's actual current text or was a clean insertion.
