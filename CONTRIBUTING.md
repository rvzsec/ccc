# Contributing to C³

Thank you for considering contributing to C³. This guide covers what you need to know.

## Where to start

- **Bug reports and feature requests** - open a [GitHub Issue](https://github.com/rvzsec/ccc/issues).
- **Code contributions** - open a Pull Request against the `main` branch.

## Development setup

```bash
git clone https://github.com/rvzsec/ccc.git && cd ccc
make build                  # build the ccc:local Docker image
make test                   # run the test suite
```

The `Makefile` has contributor targets:

```bash
make audit      # verify every pinned dependency hash
make shell      # interactive shell inside the container
make state      # dump state volume contents
make logs       # tail audit.jsonl
```

All tests use `unittest` and can also be run directly:

```bash
python -m unittest discover -v -s tests
```

## Design principles

- **No new dependencies without a clear justification.** C³ has four direct dependencies, all hash-pinned. Adding a dependency means adding it to `requirements.lock` with `pip install --require-hashes`.
- **State is flat files, never a database.** `recent.json`, `audit.jsonl`, `last_run.txt`, and a lock file. No schema migrations, no connection pools.
- **Failure modes are documented.** Every exit code has a meaning. Every network failure has a recovery behavior. Add the same for any new code.
- **Tests prove correctness of dedup and signal gating.** The existing test suite at `tests/test_dedup.py` and `tests/test_critical.py` covers window math, hash cache, CPE matching, and HTML escaping. Add tests for new functionality.

## Code style

- Python 3.11+ with type annotations (`from __future__ import annotations`).
- Strings from untrusted sources (NVD, CISA, product names) are HTML-escaped before rendering in cards.
- `pydantic` models use `extra="forbid"` to catch misspelled config keys.
- The `ccc/` package is the core library. `cli.py` handles CLI arg parsing and exit codes. `runner.py` is the pure orchestration layer.

## Pull request process

1. Open an issue describing what you're changing and why, unless it's a trivial fix.
2. Fork the repo, create a branch, make your changes.
3. Run `make test` and `make audit` to verify nothing is broken.
4. Open a PR against `main`. The description should explain what changed and why.

## License

C³ is MIT licensed. By contributing, you agree to license your contribution under the same terms.
