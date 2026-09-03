# Release engineering — user guide

**Status:** implemented.
**Last verified:** 2026-09-03.

## Cutting a release

**1. Decide the version.** Pre-1.0, MINOR is where breakage lives: a breaking
change is `0.9.1-alpha -> 0.10.0-alpha`, not `0.9.2-alpha`.

**2. Write the CHANGELOG section and commit it.** Move the `## [Unreleased]`
content under a `## [X.Y.Z-alpha]` heading at the start of a line. The release
workflow rejects a tag without it — *after* the tags are permanent — so the
script refuses first.

**3. Rehearse.**

```sh
make release-alpha VERSION=0.10.0-alpha BUMP=minor DRY_RUN=1
```

Read the diff. It should touch `VERSION` and all four `go.mod` files and
nothing else, and list the three tags.

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

Nothing is published unless the final line says so. A run that failed before
the push leaves a local release commit and possibly the three local tags — the
refusal message names them. Remove them before retrying, so the next attempt
does not die on "tag already exists".
