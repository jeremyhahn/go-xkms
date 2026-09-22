# Release engineering — CLI

**Status:** implemented.
**Last verified:** 2026-09-21.

Cutting a release is two commands, run at different times by possibly
different people: `make release-alpha` PREPARES a pull request and stops;
`make release-tag`, run only after that pull request has merged, TAGS and
publishes it (go-xkms#419, go-xkms#211).

## `make release-alpha`

```
make release-alpha VERSION=<X.Y.Z-alpha> [BUMP=patch|minor|major] [DRY_RUN=1] [RELEASE_REMOTE=<name>]
```

| Variable | Required | Meaning |
|---|---|---|
| `VERSION` | yes | The exact version to prepare. Defaults to the `VERSION` file, which is never greater than itself, so omitting it is refused. |
| `BUMP` | no | Declares the kind of release. Refused unless `next_version(current, BUMP)` equals `VERSION`. The exported-API growth gate below does not need this to be set. |
| `DRY_RUN` | no | Rehearse everything against a scratch copy of the fetched remote tip. Writes nothing, pushes nothing. |
| `RELEASE_REMOTE` | no | Remote to fetch from and push the release branch to. Default `dev`. |

## The script directly

```
scripts/release-alpha.sh --version X.Y.Z-alpha [--bump LEVEL] [--dry-run]
                         [--remote NAME] [--branch NAME]
```

`--branch` overrides the branch releases are cut from (default `main`) and is
the only way to rehearse against a branch other than `main`.

A real (non-`--dry-run`) cut fetches `--branch`, checks out a new local branch
`release/X.Y.Z-alpha` from that fetched tip, assembles the changelog, moves
the pins, bumps `VERSION`, commits, and pushes **the branch only** — never
`main`. It prints the pull request URL and the follow-up command:

```
release-alpha: pushed release/0.10.0-alpha to dev at a1b2c3d...
release-alpha: open a pull request: http://git.example.internal/jeremyhahn/go-xkms/compare/main...release/0.10.0-alpha
release-alpha: once that pull request is reviewed and merged, run: make release-tag VERSION=0.10.0-alpha
```

## `make release-tag`

```
make release-tag VERSION=<X.Y.Z-alpha> [RELEASE_REMOTE=<name>]
```

| Variable | Required | Meaning |
|---|---|---|
| `VERSION` | yes | The exact version to tag. Must equal `VERSION` in the merged release commit exactly. |
| `RELEASE_REMOTE` | no | Remote to fetch from and push the tags to. Default `dev`. |

Run this only after `make release-alpha`'s pull request has merged, from a
local checkout of the release branch (`main` by default) that is at or can
fast-forward to the merged tip:

```
scripts/release-tag.sh --version X.Y.Z-alpha [--remote NAME] [--branch NAME]
```

There is no `--dry-run`: every one of `release-tag.sh`'s checks is a read, and
a run that fetches, refuses, and writes nothing needs no rehearsal to preview.

## Examples

Rehearse a patch release, printing the exact diff the release commit would
carry:

```sh
make release-alpha VERSION=0.9.2-alpha BUMP=patch DRY_RUN=1
```

The preview covers the changelog as well as the pins. With entries pending in
`.changelog/unreleased`, the diff includes the `## [X.Y.Z-alpha]` section they
would be assembled into, and each entry a real cut would consume is named:

```
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@
 ## [Unreleased]
+
+## [0.9.2-alpha] - 2026-09-06
+
+### Fixed
+
+- **thing** ...
release-alpha: would remove .changelog/unreleased/fixed-thing-1.md
release-alpha: DRY RUN -- would push release/v0.9.2-alpha to dev and open a pull request into main:
```

The assembly runs in the scratch copy: the entry files are still there on the
fetched tip afterwards, nothing local was touched, and no local branch was
created.

Rehearse from a feature branch, where the "fetch `main`" default would
otherwise validate against the wrong tip:

```sh
scripts/release-alpha.sh --version 0.9.2-alpha --bump patch --dry-run \
	--branch "$(git symbolic-ref --short HEAD)"
```

Cut a breaking pre-1.0 release — MINOR is where breakage lives before 1.0:

```sh
make release-alpha VERSION=0.10.0-alpha BUMP=minor
# ... pull request reviewed and merged ...
make release-tag VERSION=0.10.0-alpha
```

Run the unit tests for the pure functions and the fetch/checkout/tag flow:

```sh
make test-scripts
```

## Refusals you should expect

From `make release-alpha`:

```
$ make release-alpha VERSION=0.9.2 DRY_RUN=1
release-alpha: --version '0.9.2' is not a X.Y.Z-alpha version

$ make release-alpha VERSION=0.9.2-alpha BUMP=minor DRY_RUN=1
release-alpha: --bump minor on v0.9.1-alpha is v0.10.0-alpha, but --version says v0.9.2-alpha. Fix whichever one is wrong

$ make release-alpha VERSION=0.9.1-alpha DRY_RUN=1
release-alpha: v0.9.1-alpha is not greater than the current version v0.9.1-alpha on dev/main. Pass the version to publish: make release-alpha VERSION=<X.Y.Z-alpha>

$ make release-alpha VERSION=0.9.2-alpha DRY_RUN=1
release-alpha: v0.9.2-alpha is a PATCH on v0.9.1-alpha but adds exported Go API:
  + sdk/go:pkg/foo.NewThing
Pass --bump minor (and a minor --version) if this is meant to ship, or remove the additions
```

From `make release-tag`:

```
$ make release-tag VERSION=0.10.0-alpha
release-tag: HEAD (a1b2c3d) is not dev/main's fetched tip (f9e8d7c) -- fast-forward first: git merge --ff-only dev/main

$ make release-tag VERSION=0.10.0-alpha
release-tag: VERSION at dev/main is '0.9.9-alpha', not '0.10.0-alpha' -- fetch and confirm the right release pull request merged before tagging

$ make release-tag VERSION=0.10.0-alpha
release-tag: no 'chore(release): v0.10.0-alpha' commit is reachable from dev/main -- merge the release pull request (scripts/release-alpha.sh) first
```

Add the `## [X.Y.Z-alpha]` CHANGELOG section and commit it **before**
preparing. The release workflow requires it, and it checks after the module
tags have been pushed and become permanent; both scripts' preflight uses the
same anchored match so the refusal comes first, twice.
