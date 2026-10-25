# Contributing to Sieve

Thank you for helping make SOC tooling safer and more accessible.

## How to get started

```bash
git clone https://github.com/yourhandle/sieve
cd sieve
pip install -e ".[dev]"
cp config/sieve.example.yaml config/sieve.yaml
pytest -v                  # all tests must pass before you push
```

## Good first issues

Look for issues labelled `good first issue` on GitHub.  Good starting points:

- Adding a new threat-intel plugin (see `sieve/notify/` for the pattern)
- Writing a playbook YAML for a common attack scenario
- Adding more injection payloads to the test suite
- Writing documentation for an existing feature

## Pull request checklist

- [ ] `pytest -v` passes
- [ ] `ruff check sieve tests` passes
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
