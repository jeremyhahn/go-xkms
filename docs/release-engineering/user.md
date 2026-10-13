# Release engineering — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.

## Cutting a release, in two steps (go-xkms#419, go-xkms#211)

Step one PREPARES a pull request and stops. Step two, run only after that pull
request has been reviewed and merged, TAGS and publishes. Nothing publishes
without a merged pull request in between — that is the whole point.

### Before anything reaches `main`: CI-only gates must pass

`make test` and `make lint` are not the whole gate. CI's `Lint`, `Static
Analysis` and `Architecture Gates` jobs run checks no local default target
does — `make fmt-check`, `make secure-analyzer` (go-qrdb's secure-memory
analyzer over every module and tag set), `make secure-analyzer-selftest`,
`make vet-integration`, `make check-public-literals`, and the sdk/go-only
import gates for `xkmsctl` and `xkey` — and a dependency bump can turn any of
them red with no change to this repository's own code. Every change,
release commits included, reaches `main` through a pull request whose CI run
is fully green, `CI Gate` included. Never push straight to `main` to save a
CI cycle: v0.48.0-alpha did, and shipped a red `main` (gofmt drift, 118
go-qrdb v0.25 secure-analyzer findings, and `pkg/*` imports in `xkmsctl` and
`xkey`) that v0.49.0-alpha exists to repair. Run the make targets listed in
`.github/workflows/ci.yml` locally before opening the pull request.

### Step one: prepare

**1. Decide the version.** Pre-1.0, MINOR is where breakage lives: a breaking
change is `0.9.1-alpha -> 0.10.0-alpha`, not `0.9.2-alpha`. A PATCH release
that adds exported Go API to a published module is refused outright (see
below); if that is what your change does, it is a MINOR release.

**2. Have the CHANGELOG section, or the entries that become it.** Either write
a `## [X.Y.Z-alpha]` heading at the start of a line and commit it, or leave the
per-PR entry files in `.changelog/unreleased/` and let the cut assemble them
(see `.changelog/README.md`). The release workflow rejects a tag with neither —
*after* the tags are permanent — so both scripts refuse first.

**3. Rehearse.**

```sh
make release-alpha VERSION=0.10.0-alpha BUMP=minor DRY_RUN=1
```

Read the diff. It should touch `VERSION`, all four `go.mod` files and — when
entries are pending — `CHANGELOG.md`, and nothing else; it names the release
branch it would push and each entry file the cut would consume.

The rehearsal fetches `main` from `dev` (or `--remote`) and reads everything
from that fetched tip — never from your local checkout, which may be behind
it. It writes nothing: it assembles into a scratch copy, so your
`.changelog/unreleased/` entries and `CHANGELOG.md` are exactly as they were
when it exits, no local branch is created, and nothing is staged. `git status`
afterwards is empty.

**4. Prepare it.** From a clean tree (any branch — the release is cut from
the FETCHED tip of `main`, not from whatever you have checked out):

```sh
make release-alpha VERSION=0.10.0-alpha BUMP=minor
```

This checks out a new local branch `release/v0.10.0-alpha`, commits the
version bump, the pin rewrite and the assembled changelog onto it, and pushes
**that branch only** — never `main`. It then opens the pull request into
`main`, titled `chore(release): v0.10.0-alpha`, on the forge your `dev` remote
points at, and prints its URL and the follow-up command.

Both the rehearsal and the cut need the project agent's forge token in
`FORGE_TOKEN`. Without it, or with a token the forge rejects, they refuse
before fetching or writing anything. If the forge refuses the pull request
after the push (one is already open, say), the run prints the `compare/` URL
and the exact title, so you can open it by hand.

**5. Get the pull request reviewed.** This is the step the old,
one-script flow had no room for. Nothing is published yet: `main` — local or
remote — was never touched, and no tag exists anywhere.

### Step two: tag, after the pull request merges

**6. Check out the release branch, up to date.**

```sh
git checkout main
git pull --ff-only dev main
```

**7. Tag it.**

```sh
make release-tag VERSION=0.10.0-alpha
```

This fetches `main` again, asserts your checkout is exactly that fetched tip,
asserts `VERSION` at that commit is `0.10.0-alpha`, asserts a
`chore(release): v0.10.0-alpha` commit is reachable from it (the pull request
you just merged, not a hand edit), re-checks the pins and the CHANGELOG
heading at that commit, and only then creates and pushes the three signed
tags — atomically.

**8. Verify from outside the repository.** In-repo builds resolve through local
`replace` directives and cannot see a stale pin, so this is the only check that
observes the thing the pin bump exists for:

```sh
cd "$(mktemp -d)" && go mod init check
GOWORK=off go get github.com/jeremyhahn/go-xkms/sdk/go@v0.10.0-alpha
```

## When `make release-alpha` refuses

| Message | Do this |
|---|---|
| `the working tree is not clean` | Commit or stash. A release commit must contain this release and nothing else. |
| `local branch 'release/<v>' already exists` | `git branch -D release/<v>` if a previous prepare run did not finish, or pick the next version. |
| `'release/<v>' already exists on <remote>` | A release is already prepared for that version. Open its pull request, or pick the next version. |
| `is not greater than the current version <c> on <remote>/<branch>` | You did not pass `VERSION`, or you passed one already published — checked against the REMOTE, not your local checkout. |
| `tag <v> already exists -- <v> is taken in the <ns> namespace` | Pick the next version; published tags are immutable and are never moved. |
| `--bump <l> on <c> is <e>, but --version says <n>` | One of the two is wrong. Decide which. |
| `<v> is a PATCH on <c> but adds exported Go API` | Either this is not really a patch — pass `--bump minor` and a minor `--version` — or the additions do not belong in this release. |
| `CHANGELOG.md has no '## [<V>]' section beginning a line` | Add it and commit it. Check it is at the line start. |
| `reciprocal pins are not all at <V>` | The fetched tip's pins disagree with its `VERSION`, or a module changed and `PIN_EDGES` was not updated with it. |
| `the branch push was refused` | Someone published the same branch name first, or the remote rejected it. The commit is still local on the release branch; the message names how to discard it. |

## When `make release-tag` refuses

| Message | Do this |
|---|---|
| `HEAD is detached` / `on branch '<x>' -- releases are tagged from '<branch>' only` | Check out the release branch (`main` by default). |
| `HEAD (<h>) is not <remote>/<branch>'s fetched tip (<t>)` | `git merge --ff-only <remote>/<branch>` (or re-clone/re-checkout) so your `HEAD` is exactly the merged tip, then retry. |
| `VERSION at <remote>/<branch> is '<a>', not '<b>'` | Confirm the right release pull request actually merged before tagging. |
| `no 'chore(release): <v>' commit is reachable from <remote>/<branch>` | The release pull request has not merged, or `VERSION` was hand-edited outside `release-alpha.sh`. Merge the real pull request. |
| `refusing to tag <v> -- the reciprocal pins ... are not all at <v>` | The merged release commit is itself inconsistent — this should not happen if review caught it; treat as a new issue, not a retry. |
| `refusing to tag <v> -- CHANGELOG.md ... has no '## [<v>]' section` | Same as above: the merged commit is missing something review should have caught. |
| `tag <ns><v> already exists` | This version is already published in that namespace; pick the next one. |
| `the atomic push was refused, so NOTHING was published` | Someone published first, or the remote rejected it. The tags are still local; the message names how to discard them. |

## After a failed run

Nothing is published unless the final line says so.

A `release-alpha.sh` run that failed after checking out the release branch
leaves that branch and its commit local, never pushed. The refusal names both
and the command that undoes them:

```
Nothing was pushed; undo the local state with: git checkout <previous-ref> -q && git branch -D release/<version>
```

A `release-tag.sh` run that failed after creating a tag (but before the push)
leaves that tag local. Its refusal names it:

```
Nothing was pushed; undo the local state with: git tag -d <tags>
```

A run that failed before its first write — `--dry-run` always included — wrote
nothing at all: there is nothing to undo.

## When the release workflow fails after the tag is pushed

`release.yml` runs on the tag push, exactly as before this change — it did not
change what triggers it, only what can reach that trigger (`release-tag.sh`
only, never a direct push to `main`). Its build matrix has four legs (amd64
and arm64, standard and FIPS), each uploading its own binaries and per-asset
`.sha256` files; `Create Master Checksums` then verifies the release carries
every asset the matrix produces and uploads `checksums.txt`.

### Infrastructure resilience (go-xkms#1026)

Three of seven tags in one measured window shipped an incomplete release
because a runner-infrastructure failure — not a code defect — took out a leg
and nothing after it ran. Two mitigations landed for this, one architectural
and one defensive:

- **No `build-binaries` leg uses QEMU** (go-xkms#1032, following
  go-xkms#1026's fips/arm64 leg). All four legs build natively inside one
  amd64 container: the FIPS build is `CGO_ENABLED=0` on both architectures,
  and the standard arm64 leg cross-compiles with `GOARCH=arm64` and
  `CC=aarch64-linux-gnu-gcc` against arm64 dev packages. `build-docker` and
  `build-docker-cli` keep `docker/setup-qemu-action`, but only for their
  multi-arch step, and both are guarded to `github.server_url ==
  'https://github.com'`, so neither runs on this Gitea instance.
- **Bounded retries, on the two things that actually failed:** the
  `build-binaries` container build (`docker create`/`cp`/`start`/`cp`) and the
  two amd64 Docker-image scan builds (`scripts/retry.sh`, 3 attempts, linear
  backoff). A code failure still fails, just three times over instead of
  once — the same shell loop cannot distinguish a bad build from a flaky
  daemon, so it does not try to.
- `docker/setup-qemu-action` runs with `cache-image: false` wherever it still
  runs, so it never writes to (or races) the shared
  hostedtoolcache binfmt image — the specific ENOENT copy race the issue
  recorded at v0.24.0-alpha.
- `build-binaries`' matrix caps at `max-parallel: 2`, so at most two of the
  four legs compete for a runner host's docker daemon at once.

None of this changes what a release publishes: the same 21 assets (20 from
the build matrix, plus `checksums.txt`), the same names, on the same
Docker image tags.

### Recovery

If a leg still fails for a reason unrelated to the code, **re-run the
workflow** — from the run's page, or `POST
/repos/<owner>/<repo>/actions/runs/<id>/rerun`, the only rerun endpoint Gitea
exposes. Every job runs again, and that is fine:

- a leg whose assets are already on the release finds each one present with
  the same SHA-256 and leaves it alone;
- the leg that flaked uploads what was missing;
- the checksums job checks the release, not this run, so it completes once
  the asset set is whole, and the announcement follows.

A tag cannot be re-cut (versioning §3), so this is the only recovery path;
before #447 it did not exist, and one flaked leg cost the release its
checksums for good. If `Verify the release carries every matrix asset` still
fails after the re-run, something is genuinely missing: the step names it.

### The final check: `Verify Release Assets`

The last job in the workflow, `verify-release-assets`, runs whenever a
release object exists at all — `if: always()`, independent of whether every
other job in the run went green — and calls `scripts/release-assets.sh
verify-complete <version>`. Unlike the checksums job's own verification (which
necessarily runs *before* `checksums.txt` exists, to decide whether creating
it is safe), this is the run's true terminal state: it requires the full 21
asset set — the build matrix plus `checksums.txt` — names anything `missing:`
or `unexpected:`, and fails loudly on either. A green run here is the only
statement in the workflow that the published release is actually complete,
regardless of which individual jobs happened to succeed in that run.
