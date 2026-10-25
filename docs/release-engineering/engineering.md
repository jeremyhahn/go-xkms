# Release engineering — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.

## Surface

`scripts/release-alpha.sh`, driven by `make release-alpha`, PREPARES a release
as a pull request and stops. `scripts/release-tag.sh`, driven by `make
release-tag`, TAGS and publishes a release already merged to `main`. Together
they are the only supported way to cut a release (go-xkms#419, go-xkms#211);
nothing imports either as a library except `release-tag.sh` itself, which
sources `release-alpha.sh` for its shared declarations, and their own tests.

`scripts/exportsurface` is a small standalone Go program (`package main`
under `scripts/exportsurface/`) that `release-alpha.sh` builds and runs as
part of its precondition checks; see below.

`scripts/release-assets.sh`, driven by `.github/workflows/release.yml`, is the
workflow's view of a Gitea release's assets: `list`, `expected VERSION` (the
asset names the build matrix produces — the one statement of the matrix
outside the workflow), `verify VERSION` (exit 1 naming what the release
lacks), `verify-complete VERSION` (go-xkms#1026: `verify` plus a required
`checksums.txt` and a check for any asset the matrix does NOT expect —
`create-checksums` runs plain `verify` because it runs *before*
`checksums.txt` exists; the workflow's final `verify-release-assets` job runs
`verify-complete` because by then it must exist too), `download DIR [GLOB]`,
and `upload FILE...`, which is idempotent: an asset present with the same
SHA-256 is left alone, one with a different digest is replaced, one that is
absent is added. It reads `RELEASE_API`, `RELEASE_REPO`, `RELEASE_TAG` and
`RELEASE_TOKEN` from the environment, and `DRY_RUN=1` makes `upload` print its
decisions without changing anything.

`scripts/check-public-literals.sh` (go-xkms#1030) is the public-release
readiness gate: it fails with `file:line` output if any file in the tree
carries a lab-network address, a fleet host name, or an owner workstation
path. The exact literals are declared once, in the script's own `PATTERN`
and its header comment — not repeated here, so there is exactly one place to
keep them current as the fleet changes. It scans with `grep -rIniE`, so
binary files are skipped automatically (`-I`), and excludes `.git` (file or
directory, so it works from an ordinary checkout or a worktree), `.claude/`,
`CLAUDE.md`, `AGENTS.md` and its own source — those are agent-instruction
files the owner publishes on a separate schedule, not part of the scrub. A fleet
host name that is also an ordinary word is matched as its exact full host
name, not a wildcard on the bare word: the bare word appears legitimately
(a public gTLD, an unrelated test fixture value), so widening the match
would flag those as false positives. `make check-public-literals` runs it against the
repository root; the script takes an optional root-directory argument
(`ROOT`, default the repository root) so its own test can point it at a
scratch tree instead.

`scripts/retry.sh` (go-xkms#1026) is a generic bounded-attempt/linear-backoff
wrapper — `retry.sh [--attempts N] [--backoff SECONDS] -- CMD [ARG...]`,
defaulting to 3 attempts and a 15s base backoff — used by `release.yml`
around the `build-binaries` container build and the two Docker image scan
builds, all three of which have failed on runner infrastructure (a docker
daemon timeout, a binfmt cache race) rather than on the code being built. It
does not distinguish an infrastructure failure from a code failure — nothing
outside the wrapped command can — so a genuine build defect also retries and
then fails with its own real exit code, just three times over.

`build-binaries`' four-leg matrix (standard/amd64, standard/arm64, fips/amd64,
fips/arm64) builds every leg **natively inside the same amd64
`golang:bookworm` container** — no leg passes `--platform` to `docker create`
and no leg runs `docker/setup-qemu-action` (go-xkms#1032, following on
go-xkms#1026's fips/arm64 leg, which established the pattern first). The two
`arm64` legs cross-compile via `GOARCH=arm64`: fips/arm64 needs no C toolchain
at all (`CGO_ENABLED=0`, pure Go), and standard/arm64 additionally
`dpkg --add-architecture arm64`s the container, installs
`gcc-aarch64-linux-gnu` plus the arm64 variant of every dev package the leg
already installs for amd64, and sets `CC=aarch64-linux-gnu-gcc` before the
static `-linkmode external -extldflags -static` build — the same approach
`make release-server` already uses for `xkmsd` (`Makefile:969`). This was
spiked locally before being adopted: a full cross-compiled build of
`xkmsctl`, `xkmsd` and `xkey` with the leg's exact tags and ldflags produced
statically linked aarch64 ELF binaries, confirmed with `file`. The one dev
package genuinely in doubt going in, `libtss2-dev` (tpm2-tss ships no static
`.a` on Debian, only `.so`, on either architecture), turned out not to matter
for the outcome: this leg's TPM backend (`google/go-tpm`,
`github.com/google/go-tpm-tools`) is pure Go with no cgo dependency on
libtss2 at all, and `go-icu-regex`/`gousb` are likewise not reachable under
the leg's own build tags (`gousb` sits behind a separate `usb` tag this leg
does not pass). The packages stay installed to match the previously-QEMU'd
leg's footprint unchanged, but the actual cgo surface this leg statically
links is narrower than the apt list suggests: `miekg/pkcs11` (`dlopen`-based,
no static lib needed) plus glibc's own NSS lookups (`os/user`, `net`'s cgo
resolver) — which is why `-static` still links cleanly with no tpm2-tss/ICU/
USB static archive in the picture. If a future backend or tag genuinely
starts reaching one of the icu/usb/tss2 cgo paths under `CGO_ENABLED=1`,
re-verify static-archive availability for `arm64` before assuming this leg's
`-static` link still holds.

## Declared constants

| Name | Declared in | Contents |
|---|---|---|
| `TAG_NAMESPACES` | `release-alpha.sh` | `""`, `sdk/go/`, `xkey/` |
| `API_MODULES` | `release-alpha.sh` | `.`, `sdk/go`, `xkey` — same three, without the trailing slash a directory path does not carry |
| `PIN_EDGES` | `release-alpha.sh` | nine `<file>:<module>` pairs over `go.mod`, `sdk/go/go.mod`, `xkey/go.mod`, `web/desktop/go.mod` |
| `RELEASE_FILES` | `release-alpha.sh` | **derived** from `PIN_EDGES`: `VERSION` plus every file carrying an edge |

`release-tag.sh` declares none of these itself. It sources `release-alpha.sh`
with `RELEASE_ALPHA_LIB=1` — which defines every constant and pure function
above the argument-parsing guard and returns before touching the repository —
so `TAG_NAMESPACES`, `PIN_EDGES` and the pure functions below are read from
exactly one place. `API_MODULES` is unused by `release-tag.sh`, which does
not run the growth gate; it is not redeclared there either.

Re-derive `PIN_EDGES` after any module change:

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

Tested in isolation in `test/scripts/release-alpha.test.sh`; each is a
function of its arguments alone.

| Function | Contract |
|---|---|
| `is_alpha_semver v` | true only for `v<digits>.<digits>.<digits>-alpha` |
| `next_version v level` | one field advanced, lower fields zeroed; returns 1 on an unknown level |
| `version_gt a b` | field-by-field numeric comparison, not `sort -V` |
| `max_version` | greatest well-formed version on stdin; malformed lines discarded, not coerced |
| `bump_level current next` | `patch`\|`minor`\|`major`, derived from comparing MAJOR/MINOR alone — never reads `--bump` |
| `pin_version file module` | the version of a **require** pin, ignoring `replace` entries |
| `rewrite_pin root file module from to` | moves one edge, keeping `// indirect` |
| `require_pins_at root want phase` | every declared edge present and at `want`; reports each offender |
| `changelog_has_heading file version` | `## [version]` at the **start** of a line |
| `changelog_entries_pending dir` | true when `dir` holds at least one non-`README.md` entry file |
| `escape_dots s` | BRE-literal dots |
| `forge_repo_url url` | the forge's web URL for the repository, `<scheme>://<host>[:<port>]/<owner>/<repo>` (no `.git`, no userinfo), from an `ssh://`, scp-like or `http(s)://` remote URL; an SSH remote maps to `http` on `GITEA_HTTP_PORT` (default `3001`); empty for a local path, a `file://` URL, or a path that is not exactly `<owner>/<repo>` |
| `json_string s` | `s` as a JSON string literal, `\` and `"` escaped |

Sourcing either script with `RELEASE_ALPHA_LIB=1` defines these and returns
before anything touches the repository.

`scripts/changelog-assemble.sh` folds `.changelog/unreleased/*.md` entry files
into `CHANGELOG.md` under the version being cut; `release-alpha.sh` invokes it
before the heading check whenever entries are pending, and stages the result on
a real cut. `release-tag.sh` never invokes it — by the time a release reaches
`release-tag.sh`, the heading is re-checked, not assembled. Sourcing
`changelog-assemble.sh` with `CHANGELOG_ASSEMBLE_LIB=1` exposes
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
to: the fetched tip's `mktemp -d` copy under `--dry-run`, the operator's own
checkout (now on the new release branch) on a real cut.

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

## `scripts/exportsurface`: the exported-API diff

A standalone `package main`, built by `release-alpha.sh` with `GOWORK=off go
build` into a scratch directory and invoked as a subprocess — not imported —
so its own build failure is a plain, nameable precondition failure rather than
a compile error in the release script's own package (it has none; it is a
shell script).

```
exportsurface --old DIR --new DIR --module PATH [--module PATH ...]
```

`DIR` is a module's directory relative to both `--old` and `--new`; repeat
`--module` once per published module (`release-alpha.sh` passes `.`, `sdk/go`
and `xkey`). For each, `exportsurface` walks every package directory reachable
under it — except one beginning another Go module (has its own `go.mod`),
named or nested under `internal`, `testdata` or `vendor`, or whose package
clause is `main` — and parses its non-test `.go` files with `go/parser`
(`go/packages`/`go/doc` are deliberately not used: either needs a resolved
module graph, which is neither fast nor offline-safe as a release
precondition). It records every exported top-level function, type, const and
var, plus — for a struct or interface — every exported field or method,
labelled `<module>:<pkg-relative-dir>.<Name>` (a method labelled
`<module>:<pkg>.<Type>.<Method>`). It prints one `+ <symbol>` line per symbol
present only in `--new` and one `- <symbol>` line per symbol present only in
`--old`, and exits non-zero only on a usage or parse error — growth is not a
failure here; refusing a release over it is `release-alpha.sh`'s policy, read
from the tool's stdout, not the tool's own exit code.

**`--old`/`--new`/`--module` are validated against path traversal in two
independent layers** (gosec G703, CWE-22). `resolveRoot` makes `--old`/`--new`
absolute and clean once; `resolveModuleRoot` then refuses a `--module` value
that is absolute, that contains a literal `".."` segment, or that — after
joining and cleaning — `filepath.Rel` reports as outside `root` (a
`*pathEscapeError`, checked directly by `escapesRoot`'s own tests rather than
only through cases the segment scan happens to let reach it). That string-level
check is not the containment guarantee, though: `filepath.Clean`/`Abs` LEXICALLY
evaluate a `".."` instead of refusing it, and neither can see a symlink under
`root` that itself points outside it. `collectModule` therefore also opens an
`os.Root` at `root` (Go 1.24+) and reaches every file through it (`fs.Stat`,
`fs.WalkDir`, `fs.ReadDir`, `fs.ReadFile` over `root.FS()`, never the raw
`os`/`path/filepath` equivalents) — real containment enforced at the syscall
level, which is what actually stops the symlink case
(`TestCollectModule_RejectsSymlinkEscape`), and incidentally why gosec's own
taint analyzer no longer has anything to flag: `os.Root`'s methods are not in
its configured `os.Stat`/`filepath.WalkDir` sink list at all.

`release-alpha.sh` runs it only when `bump_level CURRENT NEXT` is `patch`, and
only when the previous release's root tag (`$CURRENT`) exists locally (it does
not for a repository's first release, and the gate is a no-op then). `--old`
is that tag materialized via `git archive`; `--new` is the fetched tip already
materialized as `READROOT` for every other precondition. Any `+` line fails
the run, naming every added symbol.

## Invariants

- The version is an input. No step reads the tag namespace to decide *what* to
  publish, only to decide whether the stated version is acceptable.
- Nothing is written until every precondition and version check has passed —
  including the exported-API growth gate, which therefore runs before the
  branch is created or the pin rewrite starts.
- `release-alpha.sh` reads `VERSION`, the pins, the changelog and the previous
  release's tag from a **fetch of `--remote`/`--branch`**, never from the
  operator's own checkout — a stale local `main` cannot pass a check it never
  reads (go-xkms#211).
- **`--dry-run` leaves the operator's working tree and checked-out branch
  byte-identical.** Every write it makes — the pin rewrite *and* the changelog
  assembly — lands in a scratch copy of the fetched tip under `mktemp -d`, so a
  rehearsal cannot leave a partially rewritten pin set, a consumed set of
  changelog entries, or a new local branch behind however it exits; there is
  no restore trap to get wrong. A dry run runs no git write subcommand at all
  (fetch and `git archive` are reads), which is asserted directly in the test
  suite through the `$GIT` seam rather than only inferred from the tree.
- A real cut checks out `release/<version>` FROM the fetched tip — never from
  the operator's prior `HEAD` — commits the version bump, the pin rewrite and
  the assembled changelog onto that one branch, and pushes **only that
  branch**. `main` (local or remote) is never written.
- `release-alpha.sh` opens the release pull request itself, titled exactly
  `chore(release): <version>` (the release commit's subject), from
  `release/<version>` into `--branch`, on the forge named by `--remote`'s
  configured URL (`git config remote.<name>.url`, so an `insteadOf` rewrite
  does not change which forge is meant). The forge URL and `FORGE_TOKEN` are
  both proven, by a read of the repository through the forge API, before
  anything is fetched or written, in a dry run as well as a real cut. The
  token reaches `curl` as a header read from a file descriptor, never as a
  command-line argument.
- `release-tag.sh` asserts, every time, fetched fresh: local `HEAD` is exactly
  `--branch`, checked out and byte-identical to the just-fetched
  `--remote`/`--branch`; `VERSION` at that commit (read from the object, not
  the working tree) is exactly `--version`; a commit reachable from that tip
  carries the message `release-alpha.sh` produces for `--version` (a squash
  merge's `(#<pr>)` suffix is the one accepted variation); and the reciprocal
  pins and the `CHANGELOG` heading are still correct at that exact commit —
  re-checked against the object, not trusted from review.
- Tags are created from the resolved release commit, are annotated and
  explicitly signed, and every one has its signature confirmed **on the object**
  before anything is pushed.
- The push is `--atomic` over exactly the refs the run created: the branch
  ref alone for `release-alpha.sh`, the three tag refs alone for
  `release-tag.sh`.

## Errors

Every refusal from either script exits non-zero through its own `die`
(`release-alpha: ...` / `release-tag: ...`) and states what was and was not
changed. Refusals before a write has happened have written nothing; a refused
push says explicitly that nothing was published.

`release-alpha.sh` refusals *after* the release branch is checked out route
their cleanup advice through `cleanup_hint`, which names the branch and the
ref to return to:

```
Nothing was pushed; undo the local state with: git checkout <previous-ref> -q && git branch -D release/<version>
```

The one `release-alpha.sh` failure after its push is the forge refusing the
pull request (any status other than `201`, for example `409` when one is
already open). The branch is already pushed, so the message gives the status,
the exact title and the `compare/` URL to open the pull request by hand.

`release-tag.sh` refusals *after* a tag is created (but before the atomic
push) route through its own `cleanup_hint`, which names only the local tags —
there is no commit or branch for it to unwind, since it never writes to the
working tree at all:

```
Nothing was pushed; undo the local state with: git tag -d <tags>
```

## Deliberate non-goals

Concurrency, beyond what fetch-and-assert already closes. A second `prepare`
running against the same worktree at the same time is not defended against;
the clean-tree precondition makes the common single-operator mistake
impossible instead. Cutting from a fully isolated, disposable checkout — which
would make that concurrency class structurally unreachable rather than merely
unlikely — was considered under go-xkms#211 and declined; see
architecture.md.

## Tests

`make test-scripts` (also reached by `make test`) runs
`test/scripts/release-alpha.test.sh`, `test/scripts/release-tag.test.sh`,
`test/scripts/release-assets.test.sh`, `test/scripts/changelog-assemble.test.sh`,
`test/scripts/retry.test.sh` and `test/scripts/check-public-literals.test.sh`,
alongside the non-release script suites `clean-test-containers.test.sh`,
`softhsm-pin.test.sh` and `check-test-helpers.test.sh` (`Makefile:1021`).

`check-public-literals.test.sh` runs the gate against synthetic scratch trees
under `mktemp -d` only — never against this repository's own tree, so it
cannot go red because something else in the tree changed. It asserts: a clean
tree (generic private-range test data, an `example.com` address, a `$HOME`
placeholder) passes; each of the five literal categories is caught with its
own `file:line`; a bare fixture-style string built from the same word is not
mistaken for the one known fleet name in that family; and `CLAUDE.md`,
`AGENTS.md` and `.claude/` are excluded at any depth. Each scratch tree is
a git repository with its files tracked, because the gate reads tracked files
only: an untracked file holding a literal is not reported, a tracked one is
reported as `path:line` without its text, and a tree outside git is refused
with exit 2. The planted literals
are themselves assembled from split fragments rather than written out whole,
so this test's own source does not trip the gate it exercises.
`release-assets.test.sh` stands up a local HTTP stub of the two Gitea endpoints the asset
script uses and asserts the whole decision table: `expected` is the matrix,
`verify` names exactly the missing assets, `verify-complete` additionally
requires `checksums.txt` and names any asset the matrix does not expect,
`download` honours the glob, and `upload` skips an identical asset, replaces
a differing one (DELETE then POST) and adds an absent one, with the requests
the stub recorded as the evidence.

`retry.test.sh` drives `scripts/retry.sh` against a fake command that fails a
fixed number of times before succeeding (`--backoff 0` throughout, so the
suite stays fast): it asserts the eventual-success case stops retrying the
moment the command succeeds, the exhausted-budget case propagates the
wrapped command's own exit code rather than swallowing it, a command that
succeeds on the first try is never retried, and malformed `--attempts`/no
command at all are refused with a distinct usage exit code (2) that a
wrapped command's own failure (whatever it happens to be) is never confused
with.

`release-alpha.test.sh` covers the pure functions directly — the `v0.7.9 ->
v0.7.10` carry, the `0.9.10 > 0.9.9` ordering that lexical comparison gets
wrong, the `replace`-block-first shape of `xkey/go.mod`, stale/deleted/missing
edges, `bump_level`'s MAJOR-then-MINOR precedence, and `forge_repo_url` over
the ssh, scp-like, http and https remote forms and the shapes that name no
forge — and then, end to end, a throwaway fixture repository (under
`mktemp -d`, host git config disabled) with its own **bare `dev` remote**: a
fixture with no remote cannot exercise a script whose entire job is fetching
one. The `dev` remote is configured with a forge URL and an `insteadOf`
rewrite to the bare repository, and the forge API is a fake `$CURL` that
records each request. The end-to-end cases assert: a dry run reads the network
but writes nothing (asserted through the `$GIT` seam, not just tree identity)
and opens no pull request; a missing `FORGE_TOKEN`, a remote that names no
forge, an unknown remote and a token the forge rejects are each refused before
anything is written; prepare
validates against what was JUST FETCHED, not a stale local checkout, even when
the local checkout has never seen the remote's real state; a duplicate release
branch (local or remote) is refused; the exported-API growth gate refuses an
implied or explicit PATCH that grew the API and allows the identical growth
under MINOR; and a real cut lands the release commit on a new branch, leaves
`main` (local and remote) untouched, pushes only the branch, opens the pull
request on the forge its http remote names, titled exactly
`chore(release): <version>` from the release branch into `main`, prints the
pull request's URL, and refuses to prepare the same version twice; and a pull
request the forge refuses fails the run with the hand-opening instructions.

`release-tag.test.sh` covers the same shape of fixture, extended with a real
`chore(release): <version>` commit (`mkrelease_commit`, reproducing exactly
what a real `release-alpha.sh` cut leaves) and real SSH tag signing with this
repository's own agent key
(`~/.agent-identity/keys/agent-go-xkms.key` — never the
owner's hardware key). It asserts each of the four preconditions refuses on
its own: a local `HEAD` behind the fetched tip, a checkout on the wrong
branch, a `VERSION` not matching `--version`, a `VERSION` match with no
reachable release commit, an inconsistent pin set at the release commit, and a
missing `CHANGELOG` heading at the release commit — and that a clean run
creates and pushes all three tags atomically, each pointing at the release
commit, each carrying a verified SSH signature, each present on the bare
remote, and that tagging the same version twice is refused.
