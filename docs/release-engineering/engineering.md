# Release engineering — engineering

**Status:** implemented.
**Last verified:** 2026-09-03.

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

## Invariants

- The version is an input. No step reads the tag namespace to decide *what* to
  publish, only to decide whether the stated version is acceptable.
- Nothing is written until every precondition and version check has passed.
- `--dry-run` rewrites a scratch copy under `mktemp -d`, never the worktree, so
  a rehearsal cannot leave a partially rewritten pin set behind however it
  exits — there is no restore trap to get wrong.
- Tags are created from the resolved release commit, are annotated and
  explicitly signed, and every one has its signature confirmed **on the object**
  before anything is pushed.
- The push is `--atomic` over exactly the branch and the three tag refs this run
  created.

## Errors

Every refusal exits non-zero through `die`, prefixed `release-alpha:`, and
states what was and was not changed. Refusals before the commit have written
nothing; a refusal after the tags are created names the `git tag -d` needed to
clean up; a refused push says explicitly that nothing was published.

## Deliberate non-goals

Concurrency. A second release running against the same worktree at the same
time is not defended against — see go-xkms#211. The clean-tree precondition
makes the common single-operator mistake impossible instead.

## Tests

`make test-scripts` (also reached by `make test`) runs
`test/scripts/release-alpha.test.sh`: 55 cases over the pure functions,
including the `v0.7.9 -> v0.7.10` carry, the `0.9.10 > 0.9.9` ordering that
lexical comparison gets wrong, the `replace`-block-first shape of
`xkey/go.mod`, and stale, deleted and missing-file edges.

The parts that touch git are exercised by `--dry-run` and by cutting a real
release. They are not simulated: a harness that fakes those seams is the
dependent artifact of go-xkms#211, not of this script.
