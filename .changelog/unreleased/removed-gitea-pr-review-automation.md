### Removed

- **The in-repo PR review automation is gone; review orchestration lives in
  go-quicbaas.** `.github/workflows/opencode-review.yml`,
  `claude-review.yml` and `automerge.yml` are deleted — the label-driven
  reviewer routing (`agent:*` / `model:*` / `effort:*`), the verdict parsing
  and the Gitea auto-merge arming all went with them. Two implementations of
  the same control were conflicting; this repository now hosts none of it.

  `ci.yml`, `coverage.yml`, `docker-tests.yml`, `nightly.yml` and
  `release.yml` are unaffected — none referenced the review workflows except
  one comment, which is updated. `.github/scripts/apt-deps.sh` and
  `require-tool.sh` are CI dependency helpers, not review automation, and stay.

  The `agent:*`, `model:*`, `effort:*`, `code-review` and `review:*` labels are
  left in place: they are Gitea data rather than automation, and whatever
  drives reviews next may want the same vocabulary.
