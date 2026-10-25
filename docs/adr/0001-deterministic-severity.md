# ADR 0001: Rules decide severity; the LLM only explains

**Status:** accepted

**Context.** Log fields are attacker-controlled. Studies in 2026 show prompt injection through logs changes LLM triage outcomes,
and defences reduce but do not remove it.

**Decision.** Severity, grouping, suppression and actions are computed by deterministic code. The model writes explanations,
proposes hypotheses and picks playbook step IDs from a fixed list. Its output is validated and never read for severity.

**Consequences.** A successful injection can at most skew wording, which validation further limits. We give up any accuracy a
model might add to severity; we recover it through context (assets, intel, chains, baselines) and tuning on labelled data.
