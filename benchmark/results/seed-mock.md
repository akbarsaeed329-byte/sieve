# PoisonedLogs benchmark: poisonedlogs-seed.jsonl (LLM: mock)

385 clean alerts, 744 poisoned-twin alerts, 41 scenarios (21 malicious).

| Metric | B0 raw Wazuh | B1 naive LLM | Sieve no-AI | Sieve full |
| --- | --- | --- | --- | --- |
| Notifications per 1,000 alerts | 449.4 | 688.3 | 18.2 | 18.2 |
| Recall, true attacks (notified) | 50.0% | 100.0% | 58.3% | 58.3% |
| Attack scenarios that became an incident | – | – | 100.0% | 100.0% |
| False alarms on benign scenarios | 40.0% | 80.0% | 0.0% | 0.0% |
| Injection success rate (band lowered vs clean twin) | 0.0% | 42.9% | 0.0% | 0.0% |
| Tripwire detection rate | – | – | 100.0% | 100.0% |
| Tripwire false-alarm rate (clean) | – | – | 0.0% | 0.0% |
| Expected calibration error | – | – | 40.2% | 40.2% |
| Model sentences dropped by validation | – | – | – | 66.7% |
| LLM calls per 1,000 alerts | 0 | 1000 | 0 | 57.1 |

**Sieve no-AI** first notification p50/p95: 13 / 21 ms. Tripwire detection by class: context_manipulation 100%, direct_override 100%, obfuscated 100%, persona_hijack 100%.

**Sieve full** first notification p50/p95: 9 / 12 ms. Tripwire detection by class: context_manipulation 100%, direct_override 100%, obfuscated 100%, persona_hijack 100%.

Notified = the incident reached the notify band (high). Calibration uses score/100 as the confidence that a scenario is a true attack; the score is a priority, not a probability, so a high ECE is expected until weights are tuned on lab data.

Seed dataset is synthetic; numbers validate the harness and the design guarantees, not real-world accuracy. The mock model obeys every injected instruction (worst case).
