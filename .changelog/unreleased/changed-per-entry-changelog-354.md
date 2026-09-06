- **Changelog entries are now per-PR files under `.changelog/unreleased/`,
  assembled into `CHANGELOG.md` when a release is cut** (#354). Editing the
  top of `[Unreleased]` made every merge conflict with every other open PR —
  measured at one forced rebase plus a full CI cycle per open PR per merge —
  and let entries land in a released section that did not ship them (#361's
  failure class, which occurred twice). A PR now adds one
  `<section>-<slug>.md` file; `scripts/changelog-assemble.sh` (called by
  `release-alpha.sh` at cut time) groups the files under the new version
  heading in fixed section order and deletes them in the same commit. A file
  naming no known section fails the cut loudly rather than dropping the entry.
  `## [Unreleased]` remains in `CHANGELOG.md` and stays empty by convention.
