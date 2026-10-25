# Contributing to Sieve

Thank you for helping make SOC tooling safer and more accessible.

## How to get started

```bash
git clone https://github.com/akbarsaeed329-byte/sieve
cd sieve
pip install -e ".[dev]"
cp config/sieve.example.yaml config/sieve.yaml
make lint test             # all tests must pass; core coverage must stay at 80%+
make web                   # only if you changed sieve/web (needs Node 20+)
make bench                 # if you touched the tripwire, fence, validation or scoring
```

## Good first issues

Look for issues labelled `good first issue` on GitHub.  Good starting points:

- Adding a new threat-intel plugin (see `docs/PLUGINS.md`)
- Writing a playbook YAML for a common attack scenario
- Adding more injection payloads to the test suite
- Writing documentation for an existing feature

## Pull request checklist

- [ ] `pytest -v` passes
- [ ] `ruff check sieve tests benchmark` passes
- [ ] `make bench` still reports 0% injection success for Sieve
- [ ] Any new untrusted field paths added to `UNTRUSTED_PATHS` in `pipeline/normalise.py`
- [ ] Any new LLM call goes through the fence in `llm/fence.py`
- [ ] Significant design decisions recorded as an ADR in `docs/adr/`

## Anything touching the LLM or auth layers

These need a second review from a maintainer with the `llm-security` or `auth` label.
Post in the PR description what injection scenarios you considered and how you tested them.

## Code style

`ruff` is the linter and formatter.  Run `ruff format sieve tests` before pushing.

## Licence

By contributing you agree that your contribution will be licensed under Apache 2.0.
