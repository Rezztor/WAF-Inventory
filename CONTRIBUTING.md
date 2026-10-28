# Contributing to WAF Inventory

WAF Inventory is open source, not open contribution. Rezztor Technologies writes all of its code, and pull requests
from outside are closed without review, so the ownership of every line stays in one place.

You are free to use, change and run the code under the AGPL-3.0, including on your production network, and to keep your
own fork. What helps most:

- **Bug reports and feature ideas** as GitHub issues: what you did, what happened, what you expected.
- **Security problems** privately, through GitHub's "Report a vulnerability" on this repository, not as a public issue.

## Workflow (maintainers and forks)

Branch from `main` and merge back into `main`. The suite has to be green, and a behaviour change comes with its test.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]" ruff
ruff check src tests && pytest -q
```
