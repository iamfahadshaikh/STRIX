# Contributing to STRIX

Thanks for your interest in improving STRIX.

## Before You Start

- Use STRIX only for authorized security testing on systems you own or have permission to test
- Open an issue before large architectural changes
- Keep pull requests focused, well-tested, and clearly scoped

## Development Setup

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install dependencies from requirements.txt.
4. Run scanner checks and tests locally.

## Branch and Commit Style

- Branch naming examples:
  - feature/short-description
  - fix/short-description
  - docs/short-description
- Commit message style:
  - feat: add new capability
  - fix: resolve specific bug
  - docs: update documentation
  - refactor: improve code structure
  - test: add or improve tests

## Pull Request Checklist

- Code runs without syntax errors.
- Tests or quick verification were executed.
- No secrets or credentials were committed.
- Documentation is updated when behavior changes.
- PR description includes problem, approach, impact, and test evidence.

## Reporting Bugs

Please include:

- OS and Python version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Sanitized logs or traces

## Scope Rules

Contributions that encourage unauthorized scanning, weaken evidence requirements, or reduce safety controls are not accepted.
