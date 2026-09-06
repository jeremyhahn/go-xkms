# Per-entry changelog files

Every PR that changes behaviour adds **one file** under `.changelog/unreleased/`
instead of editing `CHANGELOG.md`. Two PRs never touch the same file, so a
merge can no longer invalidate every other open PR (#354), and an entry cannot
land in a released section it does not belong to (#361) — entries reach
`CHANGELOG.md` only when a release is cut, under the version that actually
ships them.

## File name

    <section>-<slug>.md

`<section>` is one of `security`, `fixed`, `added`, `changed`, `removed`,
`deprecated` — it selects the `###` heading the entry is assembled under.
`<slug>` is short kebab-case, unique enough to avoid collisions (the issue
number is a good suffix: `fixed-socket-perm-race-357.md`).

## File content

The entry exactly as it should appear in `CHANGELOG.md`: a `- **bold lead**`
bullet in the established house style (what changed and why it matters, then
mechanism, files, verification, issue refs). No heading, no front matter —
the file body is spliced verbatim under the section heading.

## Assembly

`scripts/changelog-assemble.sh <version>` (called by `scripts/release-alpha.sh`
at cut time) creates `## [<version>] - <date>` under `## [Unreleased]`, groups
the entries by section in a fixed order (Security, Added, Changed, Deprecated,
Removed, Fixed), splices them, and **deletes the assembled files** in the same
commit. An empty `.changelog/unreleased/` means the release carries whatever
`CHANGELOG.md` already says — the script is a no-op and the release gate's
heading check still applies.

`CHANGELOG.md`'s `## [Unreleased]` section stays, and stays empty by
convention; anything placed there directly is a review error.
