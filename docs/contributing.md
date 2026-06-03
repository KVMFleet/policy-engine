# Contributing

PRs welcome. The library is small; non-trivial contributions can
typically be reviewed in a day.

## Local dev setup

```bash
git clone https://github.com/KVMFleet/policy-engine
cd policy-engine
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running checks

```bash
ruff check .
mypy kvmfleet_policy_engine
pytest
```

CI runs the same three. PRs must pass all of them.

## What we'll merge

- **Bug fixes** with a reproducing test.
- **Improved error messages** when a confusing rule-fire reason can
  be made clearer.
- **Documentation improvements**, including this doc.
- **Additional test coverage** for edge cases (DST transitions,
  timezone weirdness, off-by-one boundary conditions).

## What we'll push back on

- **New rule types without a strong case.** We deliberately ship
  four. Adding a fifth raises the library's surface area and the
  cognitive cost for every reader. Open an issue first to discuss
  whether your use case really needs a new rule type or can be
  expressed by the existing four.
- **DSL extensions.** No Rego, no Polar, no expression language.
  If your needs require expressing policies in code-shaped rules,
  embed [OPA](https://www.openpolicyagent.org/) or
  [Cedar](https://www.cedarpolicy.com/) instead. We're proud of
  staying small.
- **Async APIs.** The library is sync + pure on purpose. Wrap it
  in an async layer if your caller is async.
- **Database integration.** The library does not load policies or
  write audit rows. Those belong in the caller's persistence layer.

## Coding conventions

- `ruff` defaults (line length 100).
- `mypy --strict`.
- Type hints on every public function and dataclass field.
- Comments explain the *why*, not the *what*. Especially when a
  contract decision (e.g. "skip rules with missing context"
  vs "fail-closed-on-missing") needs justification.
- Tests live in `tests/`. Use `hypothesis` for property-based tests
  where edge cases multiply (time / dates / boundaries).

## Release process

Maintainers only:

1. Bump version in `pyproject.toml` and `kvmfleet_policy_engine/__init__.py`.
2. Update `CHANGELOG.md`.
3. Tag the commit `v<version>`.
4. CI publishes to PyPI on tag push (once trusted-publishing is set up).

## License

By contributing, you agree your contribution is licensed under the
Apache 2.0 License (the project's license).
