# Release engineering — engineering

**Status:** implemented.
**Last verified:** 2026-09-06.

## Surface

`scripts/release-alpha.sh`, driven by `make release-alpha`. It is the only
supported way to cut a release; nothing imports it as a library except its own
test.

## Declared constants

| Name | Contents |
|---|---|
| `TAG_NAMESPACES` | `""`, `sdk/go/`, `xkey/` |
| `PIN_EDGES` | nine `<file>:<module>` pairs over `go.mod`, `sdk/go/go.mod`, `xkey/go.mod`, `web/desktop/go.mod` |
| `RELEASE_FILES` | **derived** from `PIN_EDGES`: `VERSION` plus every file carrying an edge |

Re-derive after any module change:

```sh
git ls-tree -r --name-only HEAD | grep 'go.mod$'
grep -n 'jeremyhahn/go-xkms' <each>
```

`test/scripts/release-alpha.test.sh` performs exactly that derivation and
compares it with `PIN_EDGES`, so drift fails a unit test rather than a release.
`RELEASE_FILES` is derived from `PIN_EDGES` rather than listed beside it: a
`go.mod` declared as carrying an edge but omitted from the staged set would be
rewritten and validated and then left out of the release commit, which passes
every check and ships a stale pin.

## Pure functions

Tested in isolation; each is a function of its arguments alone.

| Function | Contract |
|---|---|
| `is_alpha_semver v` | true only for `v<digits>.<digits>.<digits>-alpha` |
| `next_version v level` | one field advanced, lower fields zeroed; returns 1 on an unknown level |
| `version_gt a b` | field-by-field numeric comparison, not `sort -V` |
| `max_version` | greatest well-formed version on stdin; malformed lines discarded, not coerced |
| `pin_version file module` | the version of a **require** pin, ignoring `replace` entries |
| `rewrite_pin root file module from to` | moves one edge, keeping `// indirect` |
| `require_pins_at root want phase` | every declared edge present and at `want`; reports each offender |
| `changelog_has_heading file version` | `## [version]` at the **start** of a line |
| `escape_dots s` | BRE-literal dots |

Sourcing the script with `RELEASE_ALPHA_LIB=1` defines these and returns before
anything touches the repository.

`scripts/changelog-assemble.sh` folds `.changelog/unreleased/*.md` entry files
into `CHANGELOG.md` under the version being cut; `release-alpha.sh` invokes it
before the heading check whenever entries are pending, and stages the result on
a real cut. Sourcing it with `CHANGELOG_ASSEMBLE_LIB=1` exposes
`assemble`/`entry_section` for `test/scripts/changelog-assemble.test.sh`. The
contributor-facing convention lives in `.changelog/README.md`.

```
changelog-assemble.sh [--root DIR] <version-without-v> [<date>]
```

`--root` names the tree to assemble in — the one holding `CHANGELOG.md` and
`.changelog/unreleased` — and defaults to the repository the script lives in.
It exists because assembly is **destructive**: the CLI deletes every entry file
it splices, so a caller rehearsing a release must be able to point the whole
operation at a scratch copy. `release-alpha.sh` passes the tree it is writing
to, which is the repository on a real cut and the `mktemp -d` copy under
`--dry-run`.

`assemble` refuses a `CHANGELOG.md` that does not carry **exactly one**
`## [Unreleased]` heading. `make release` extracts a version's notes with

```sh
sed -n "/## \[$VERSION\]/,/^## \[/{...;p;}" CHANGELOG.md
```

so a release section runs from its heading to the next line beginning `## [`.
A second `[Unreleased]` makes that bound ambiguous: the notes are truncated or
swallow a neighbouring document's entries depending on which occurrence the
tool picks (go-xkms#356). A file that reached that state is refused rather
than spliced into blindly.

Two properties of `CHANGELOG.md` follow from that `sed`, and both are load
bearing:

- **A version heading must be unique.** The range restarts, so two `##
  [0.1.0-alpha]` headings emit *both* sections as one release's notes.
- **Nothing may trail the oldest release section except under a heading that
  itself begins `## [`.** The last section has no terminator otherwise and
  runs to end of file. This is why the absorbed go-trusted-ca history sits
  under `## [go-trusted-ca] - merged 2026-04-16` rather than a prose heading,
  and why its own version headings are demoted to `###`: the bracketed
  heading bounds the oldest go-xkms release, and the demoted ones cannot be
  mistaken for go-xkms releases.

## Invariants

- The version is an input. No step reads the tag namespace to decide *what* to
  publish, only to decide whether the stated version is acceptable.
- Nothing is written until every precondition and version check has passed.
- **`--dry-run` leaves the working tree byte-identical and the index empty.**
  Every write it makes — the pin rewrite *and* the changelog assembly — lands
  in a scratch copy under `mktemp -d`, so a rehearsal cannot leave a partially
  rewritten pin set or a consumed set of changelog entries behind however it
  exits; there is no restore trap to get wrong. A dry run runs no git write
  subcommand at all, which is asserted directly in the test suite through the
  `$GIT` seam rather than only inferred from the tree.
- The pin set is validated **before** anything is written, so a tree that is
  going to be refused is refused with its `.changelog` entries intact.
- Tags are created from the resolved release commit, are annotated and
  explicitly signed, and every one has its signature confirmed **on the object**
  before anything is pushed.
- The push is `--atomic` over exactly the branch and the three tag refs this run
  created.

## Errors

Every refusal exits non-zero through `die`, prefixed `release-alpha:`, and
states what was and was not changed. Refusals before the commit have written
nothing; a refused push says explicitly that nothing was published.

Refusals *after* the release commit exists route their cleanup advice through
`cleanup_hint`, which names the local tags **and** the commit:

```
Nothing was pushed; undo the local state with: git tag -d <tags> && git reset --hard <base>
```

The commit is created before the tags are signed, so a run that dies at the
signing check leaves an unsigned `chore(release)` commit on the branch. A hint
naming only the tags left the operator standing on it, to discover it at the
push where `main` enforces signed commits.

## Deliberate non-goals

Concurrency. A second release running against the same worktree at the same
time is not defended against — see go-xkms#211. The clean-tree precondition
makes the common single-operator mistake impossible instead.

## Tests

`make test-scripts` (also reached by `make test`) runs
`test/scripts/release-alpha.test.sh`. Most of it covers the pure functions —
the `v0.7.9 -> v0.7.10` carry, the `0.9.10 > 0.9.9` ordering that lexical
comparison gets wrong, the `replace`-block-first shape of `xkey/go.mod`, and
stale, deleted and missing-file edges.

The last section is end to end, and is the exception the tree-identity
invariant earns: the defect it covers is entirely a question of *which tree*
the impure steps write to, which no test of the pure functions can see. It
builds a throwaway repository under `mktemp -d` carrying the shape the script
demands — a `VERSION` file, every declared pin edge, a CHANGELOG with an
`## [Unreleased]` heading, pending entries and copies of both scripts — runs
`--dry-run` against it with the host's git config disabled, and asserts a
before/after manifest (`git status --porcelain` plus a content hash of
`CHANGELOG.md` and every `.changelog` file) is unchanged. A real cut is driven
as far as the tag-signing check, with `gpg.program` pointed at `/bin/false`,
which is as far as a test may go: everything after it publishes.

The remaining git seams — the push, signature confirmation on a real key — are
exercised by cutting a real release, not simulated. A harness that fakes them
is the dependent artifact of go-xkms#211, not of this script.
