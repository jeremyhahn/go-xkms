# Release engineering — user guide

**Status:** implemented.
**Last verified:** 2026-09-08.

## Cutting a release

**1. Decide the version.** Pre-1.0, MINOR is where breakage lives: a breaking
change is `0.9.1-alpha -> 0.10.0-alpha`, not `0.9.2-alpha`.

**2. Have the CHANGELOG section, or the entries that become it.** Either write
a `## [X.Y.Z-alpha]` heading at the start of a line and commit it, or leave the
per-PR entry files in `.changelog/unreleased/` and let the cut assemble them
(see `.changelog/README.md`). The release workflow rejects a tag with neither —
*after* the tags are permanent — so the script refuses first.

**3. Rehearse.**

```sh
make release-alpha VERSION=0.10.0-alpha BUMP=minor DRY_RUN=1
```

Read the diff. It should touch `VERSION`, all four `go.mod` files and — when
entries are pending — `CHANGELOG.md`, and nothing else; it lists the three tags
and names each entry file the cut would consume.

The rehearsal writes nothing. It assembles into a scratch copy, so your
`.changelog/unreleased/` entries and `CHANGELOG.md` are exactly as they were
when it exits, and nothing is staged. `git status` afterwards is empty, and the
real cut that follows will not trip its own clean-tree precondition.

**4. Cut it.** From `main`, up to date, with a clean tree:

```sh
make release-alpha VERSION=0.10.0-alpha BUMP=minor
```

**5. Verify from outside the repository.** In-repo builds resolve through local
`replace` directives and cannot see a stale pin, so this is the only check that
observes the thing the pin bump exists for:

```sh
cd "$(mktemp -d)" && go mod init check
GOWORK=off go get github.com/jeremyhahn/go-xkms/sdk/go@v0.10.0-alpha
```

## When it refuses

| Message | Do this |
|---|---|
| `the working tree is not clean` | Commit or stash. A release commit contains the release and nothing else. |
| `on branch '<x>' -- releases are cut from 'main' only` | Check out `main`. Use `--branch` only to rehearse. |
| `HEAD is detached` | Check out `main`. |
| `is not greater than the current version` | You did not pass `VERSION`, or you passed one already released. |
| `already exists -- <V> is taken in the <ns> namespace` | Pick the next version; published tags are immutable and are never moved. |
| `--bump <l> on <c> is <e>, but --version says <n>` | One of the two is wrong. Decide which. |
| `CHANGELOG.md has no '## [<V>]' section beginning a line` | Add it and commit it. Check it is at the line start. |
| `reciprocal pins are not all at <V>` | The tree's pins disagree with `VERSION`, or a module changed and `PIN_EDGES` was not updated with it. |
| `failed to create the signed tag` | No signing key. Release through `software/scripts/agent-git.sh`, or set `user.signingkey` and `gpg.format`. |
| `the atomic push was refused, so NOTHING was published` | Someone published first, or the remote rejected the branch. The commit and tags are still local; the message names how to discard them. |

## After a failed run

Nothing is published unless the final line says so. A run that failed after the
release commit was created leaves that commit — unsigned, if it died at the
signing check — and possibly the three local tags. The refusal message names
both and the command that undoes them:

```
Nothing was pushed; undo the local state with: git tag -d <tags> && git reset --hard <base>
```

Run it before retrying, so the next attempt does not die on "tag already
exists" or start from a tree that already holds the release.

A run that failed *before* the commit, `--dry-run` included, wrote nothing at
all: there is nothing to undo.

## When the release workflow fails after the tag is pushed

`release.yml` runs on the tag push. Its build matrix has four legs (amd64 and
arm64, standard and FIPS), each uploading its own binaries and per-asset
`.sha256` files; `Create Master Checksums` then verifies the release carries
every asset the matrix produces and uploads `checksums.txt`.

If one leg fails for a reason unrelated to the code (the shared runner's
QEMU toolcache race is the known one), **re-run the workflow** — from the
run's page, or `POST /repos/<owner>/<repo>/actions/runs/<id>/rerun`, the only
rerun endpoint Gitea exposes. Every job runs again, and that is fine:

- a leg whose assets are already on the release finds each one present with
  the same SHA-256 and leaves it alone;
- the leg that flaked uploads what was missing;
- the checksums job checks the release, not this run, so it completes once
  the asset set is whole, and the announcement follows.

A tag cannot be re-cut (versioning §3), so this is the only recovery path;
before #447 it did not exist, and one flaked leg cost the release its
checksums for good. If `Verify the release carries every matrix asset` still
fails after the re-run, something is genuinely missing: the step names it.

