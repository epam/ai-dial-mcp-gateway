# Security Impact Analysis Instructions — vendored

**What this copy is.** The operator's security-impact-analysis instructions, vendored
verbatim into this repository so that no work here depends on a path outside it.
Canonical source: the operator's security-instruction set (document
`security-impact-analysis.md`), maintained outside this repository; snapshotted
2026-10-29. If the source evolves, the re-vendor is a deliberate direct commit to this
path — never a live dependency on the source's location.

**How it is used here.** The adapted method lives in
[`docs/security-analysis.md`](../../security-analysis.md), and it modifies this
instruction's *process* in one deliberate way: **the SIA runs in full on every change.**
The two-step depth dial below (the detailed exercise only if impact is medium/high)
exists to minimize a security team's involvement, and this repo runs the analysis
itself — so the dial is not used. Step 1's impact evaluation is still performed and
recorded; its level sets the security review gate's depth, never whether the analysis
happens. The taxonomy and control order this instruction references are vendored
verbatim in [`threat-modeling.md`](threat-modeling.md).

---

<Security-impact-analysis-instructions>

# Security Impact Analysis instructions
Security Impact Analysis (or SIA for short) of a new feature or code change is a small "threat modeling" exercise, its role is to highlight potential security impact of the new feature and help to design and implement it to minimize this impact. Security Impact Analysis should ideally be performed prior to implementation of the feature or code change. 
* Security Impact Analysis starts with providing a business description of a new feature and details how it's going to be implemented
* Step 1: evaluate security impact level on a high-level (no impact/low impact/medium impact/high impact; level of impact is determined based on what sensitive assets are involved and how much are they exposed to confidentiality/integrity/availability attacks if new feature is implemented; always give your reasons for the impact evaluation; ask additional questions if this is necessary for evaluation. 
* Step 2: If impact is medium/high, then the next step is to prepare for the detailed SIA session with the development team; you need to give a list of potential new threats, brought by this new feature's implementation and propose a list of controls and mitigations that should be incorporated into implementation to minimize the threats; besides "technical" threats, think about "mis-use cases", when new feature can be used to mis-use the system in a legitimate way; use threats and controls categorization defined in Threat-Modeling-instructions section; among proposed controls and mitigations, specify, which controls and mitigations already in-place or planned based on your knowledge of DIAL, DIAL Admin and feature implementation details; always ask additional implementation questions, you cannot see all potential technical and logical issues without knowing implementation details. 
</Security-impact-analysis-instructions>
