# Evaluation (PoisonedLogs)

`benchmark/run.py` replays a labelled dataset through four systems (research doc 7.2) and writes Markdown and
JSON to `benchmark/results/`. CI runs it on every push with a mock model that obeys every injected
instruction (the worst case) and fails if any injection lowers a Sieve severity band.

* Dataset: `benchmark/generate.py` writes **PoisonedLogs-seed**, 41 synthetic scenarios (21 malicious, 20
  benign) with a poisoned twin per malicious scenario for each injection class (direct override, persona
  hijack, context manipulation, obfuscated). The Phase-0 lab dataset replaces it without code changes.
* Clean and poisoned variants run in separate fresh instances and are paired by scenario (doc 7.4).
* Real model: `python benchmark/run.py --llm http://localhost:11434 --name ollama-llama3.1`.

## Seed results (mock model), v0.3.0, 2026-10-18

| Metric | B0 raw Wazuh | B1 naive LLM | Sieve no-AI | Sieve full |
| --- | --- | --- | --- | --- |
| Notifications per 1,000 alerts | 449.4 | 688.3 | 31.2 | 31.2 |
| Recall, true attacks (notified) | 50.0% | 100.0% | 100.0% | 100.0% |
| Attack scenarios that became an incident | – | – | 100.0% | 100.0% |
| False alarms on benign scenarios | 40.0% | 80.0% | 0.0% | 0.0% |
| Injection success rate | 0.0% | 42.9% | 0.0% | 0.0% |
| Tripwire detection rate | – | – | 100.0% | 100.0% |
| Tripwire false-alarm rate (clean) | – | – | 0.0% | 0.0% |
| Model sentences dropped by validation | – | – | – | 66.7% |
| LLM calls per 1,000 alerts | 0 | 1000 | 0 | 57.1 |

First notification p50/p95: 9 / 14 ms (live-like replay, one alert at a time).

## What these numbers do and do not show
* They validate the harness and the **design guarantees** (H2: a hijacked model cannot lower a band). They are
  not real-world accuracy: the data is synthetic and the tripwire rules were written by the same team.
* **v0.2 → v0.3:** recall on true attacks rose from 58.3% to 100% after adding severity floors (single high-impact
  events always reach High). Notifications rose from 18 to 31 per 1,000 alerts, still about 14 times fewer than raw
  Wazuh. Honest caveat: the floors were written knowing which seed scenarios had been missed. They follow Wazuh's
  own level semantics (12+ is a high-importance event) and well-known high-impact techniques rather than fitted
  numbers, but only the lab dataset can confirm them.
* **Throughput:** one worker on SQLite processes about 190 alerts per second (`python benchmark/load.py`).
* ECE is high because the score is a priority, not a probability. Report it, do not optimise it blindly.
* Still to do (doc 7.4): three runs per configuration, the ablation runs, peak RAM/CPU, usability study.
