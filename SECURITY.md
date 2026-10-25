# Security Policy

Sieve is a security tool.  We hold it to a higher standard than most projects.

## Supported versions

The latest release on `main` is the only supported version.

## Reporting a vulnerability

**Do not open a public GitHub issue.**

Report it privately through GitHub: open the **Security** tab of this repository and click
**Report a vulnerability** (https://github.com/akbarsaeed329-byte/sieve/security/advisories/new). Include:

- A description of the vulnerability
- Steps to reproduce
- Affected version
- Potential impact

Sieve is maintained by one person during an alpha. Expect an acknowledgement within 7 days; critical issues are
fixed first. Please allow reasonable time for a fix before public disclosure. Reporters are credited in the
release notes unless they prefer otherwise.

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
