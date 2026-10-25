# Evaluation plan (PoisonedLogs)

To build (Phase 3): a labelled, lab-generated dataset and a harness comparing four systems on the same replay.

- **Systems:** B0 raw Wazuh (level >= 7 notifies), B1 naive LLM (one call per alert, raw JSON, model picks severity),
  Sieve without AI, Sieve full.
- **Data:** benign triggers, malicious scenarios (Atomic Red Team), and poisoned twins with payloads in attacker-controlled
  fields covering direct override, persona hijack, context manipulation and obfuscation.
- **Metrics:** notifications per 1,000 alerts; recall on labelled attacks; injection success rate (poisoned vs. clean twin:
  did severity, verdict or action change); tripwire detection and false-alarm rate; unsupported-claim rate; ATT&CK ID validity;
  calibration error; time to first notification p50/p95; LLM calls and tokens per 1,000 alerts; peak RAM/CPU.
- **Procedure:** three runs per configuration, ablations (switch off one defence at a time), publish data + scripts.

The demo alerts in `sieve/demo.py` are a smoke test, not the benchmark.
