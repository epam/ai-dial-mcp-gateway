# Threat Modeling Instructions — vendored

**What this copy is.** The operator's threat-modeling instructions, vendored verbatim
into this repository so that no work here depends on a path outside it. The attack-type
taxonomy and the security-control categories and their order (both below) are the
operator's substance: they are reproduced exactly and are never paraphrased, reordered,
or redesigned in this repo. Canonical source: the operator's security-instruction set
(document `threat-modeling.md`), maintained outside this repository; snapshotted
2026-10-29. If the source evolves, the re-vendor is a deliberate direct commit to this
path — never a live dependency on the source's location.

**How it is used here.** The adapted method — vocabulary mapping, the per-change
security impact analysis, the full threat model's shape, validation — lives in
[`docs/security-analysis.md`](../../security-analysis.md); the operational checklist is
the local `security-analysis` skill. The adaptation modifies *process* only (for
example: the collaborative "stop and let others evaluate" step maps onto this repo's
review gates, stated there); the taxonomy and control order below are substance and are
never modified.

---

<Threat-Modeling-instructions>

# Threat Modeling Instructions
Always use the framework below when asked questions about Threat Modeling of some component or a system:
The general flow of the Threat Modeling:
* Step 1: analyze system's architecture, based on available materials; ask additional questions if something is not clear; 
    * the key points of the architecture, significant for the threat modeling are data flows - how sensitive assets flow through the system components and connections between them; they leave footprints as the move through the system. Those footprints represent targets for the attacks.
    * Identify sensitive assets the system works with (business and technical), their level of sensitivity for Confidentiality, Integrity and Availability, and what footprints they have with the system.
    * Identify potential attackers, using existing documentation and common sense, including legitimate business users and high-privileged users, such as technical support or administrators 
    * Identify Trust Boundaries, physical locations where people with certain level of permissions and business responsibilities usually live. All system components also live in certain Trust boundaries. Trust Boundaries are useful in building security controls to limit who can be there and access resources there. At the same time, Attack vectors always start from certain Trust Boundary.
* Step 2: for each component in the system, create a list of Threats; 
    * analyze one component or a flow at a time, then stop and let others to evaluate, ask questoins and comment your list of Threats for the component or a flow.
    * every component and a flow has an Attack surface, that can be used to compromise them and get access to the footprints
    * each Threat represents an attack vector, that starts from one of the Trust boundaries or other components and targets a particular sensitive asset's footprint on the component or the flow via a particular attack surface (e.g. open port, file system, memory etc)
    * Create a separate table of Threats for each attack surface entry point for the component, using attack types categorization (provided below), use the structure below:<br>
attack surface entry point for the component, attack type category (use only leaf-level categories, show a full path to the category), attack type name,  target sensitive footprint of the asset, what is being compromised (Confidentiality, Integrity or Availability), attack type description
    * While constructing a list of Threats, take into account component's or flow's nature, hosting details, technological stack and language it's written with. Each Attack Type category may have multiple entries, depending on the factores, mentioned above.

* Step 3: for each particular Threat propose a list of mitigation controls.
Below are the categories of attack types (threats) we use in our Threat modeling (this is hierarchical structure, indentation is used for parent-child relationship):

Use Control Misconfiguration (persuade a component to do the wrong thing without actually hacking it)
	Elevation of Privilege (identify places where Authentication or Authorization controls are missing, have flaws or misconfigured)
		Spoofing of caller's identity (guess or steal credentials or session of a legitimate user or other principal)
		Bypass Authorization 
	Denial of Service (make a component or its functions not available when they are needed)
		Resource Consumption (force component to consume too much resources - e.g. Memory, disk or CPU, causing it to become unresponsive)
		Crashing (craft an input that breaks the component)
Injection (of the malicious code, changing the normal flow of the component; "injection" here is a broad term, it includes not only traditional "injection" when user input is executed, but rather finding by attacker any way to "inject" executable code into a component)
Interception (of the data flows between system components)
	Eavesdropping	
	Spoofing of the target (Man in the middle)

Below are the categories of security controls we use in our Threat modeling, while considering mitigation of any particular Threat (this is hierarchical structure, indentation is used for parent-child relationship), the order is important, it defines how we should plan our defense-in-depth strategy:
- Reduce Attack Surface
- Isolation
- Authentication
- Authorization
- Data Protection
- Anti-Injection
- Anti-DoS
- Detective controls

Use this order to propose mitigations for a particular Threat. If controls in some category are not possible or applicable for a certain attack vector / threat, the category is mentioned anyway with the description why it's not applicable
Mitigations are proposed for every identified threat - it effectively means that we need to consider mitigations from every category (in the order, provided above) for every identified threat.
After all mitigations for all threats are proposed, we need to review the resulting list of mitigations and finalize it be grouping (since the same mitigation can be proposed for more than one threat). As a result, we have a list of mitigation, every mitigation is associated with a list of threats it addresses. This list should be provided as a result of Threat Modeling or Security Impact Analysis.

</Threat-Modeling-instructions>
