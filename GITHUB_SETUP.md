# GitHub Setup Checklist

Some maturity steps live in GitHub settings rather than the codebase. Use this checklist after pushing the current repo.

## Branch protection

Protect your default branch and require:

- pull requests before merge
- at least 1 approving review
- conversation resolution before merge
- status checks to pass before merge
- linear history

Recommended required check:

- `CI / test (3.11)`
- `CI / test (3.12)`

## Repository settings

- enable GitHub Actions
- disable force pushes to the protected branch
- disable branch deletion on the protected branch
- require signed commits if your buyers or investors care about stricter controls

## Suggested workflow

1. feature branch
2. open PR
3. CI passes
4. review + merge
5. Railway auto-deploys after merge

## What the repo already includes

- GitHub Actions CI workflow
- customer-facing security documentation
- deployment guide
- role-based portal/admin restrictions
