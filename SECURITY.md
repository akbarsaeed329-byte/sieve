# Security Policy

Sieve is a security tool.  We hold it to a higher standard than most projects.

## Supported versions

The latest release on `main` is the only supported version.

## Reporting a vulnerability

**Do not open a public GitHub issue.**

Email **security@sieve-project.example** (replace with your real address) with:

- A description of the vulnerability
- Steps to reproduce
- Affected version
- Potential impact

We aim to acknowledge within 48 hours and issue a fix within 14 days for critical issues.

Contributors who responsibly disclose vulnerabilities are listed in `HALL_OF_FAME.md`.

## Known design choices and trade-offs

| Decision | Reason |
|---|---|
| LLM never decides severity | Eliminates the highest-impact injection surface |
| Attacker-controlled fields fenced but shown | Transparency; analysts need to see the data |
| Tripwire rules are public | Enables community improvement and benchmarking |
| Local model default | Prevents log data leaving the machine by default |
| API key stored in env var only | Never written to logs or the database |

## Threat model

See the research document, Section 8, for the full STRIDE threat model.

## Out of scope

- Attacks requiring physical access to the machine running Sieve
- Attacks against Wazuh itself (report to the Wazuh project)
- Social engineering of Sieve administrators
