# 2042: ready_for_review trigger types

CA m2586 (DS-8553): fold `ready_for_review` into the red-main fix PR #2042,
per handbook ci-template v1.35.3 / code-review v5.10.12. No new PR.

## Change

- `.github/workflows/ci.yml`, `pull_request` types:
  `[opened, synchronize, reopened]` -> `[opened, synchronize, reopened, ready_for_review]`.
- `.github/workflows/code-review.yml`, `pull_request_target` types:
  `[opened, reopened, synchronize, labeled]` -> `[opened, reopened, synchronize, labeled, ready_for_review]`.

A draft PR marked ready for review now starts CI and the code review at once,
without waiting for the next push. No trigger, job, action, secret or variable
is added.

## Checks

- actionlint on both files: clean.
- No test under `test/` pins the `types:` lines, so `make test-scripts` is not
  needed for this change.

## Out of scope

- `qwen-review.yml` keeps its types (not named by the order).
- `automerge.yml` already lists `ready_for_review`.
