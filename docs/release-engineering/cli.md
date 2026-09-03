# Release engineering — CLI

**Status:** implemented.
**Last verified:** 2026-09-03.

## `make release-alpha`

```
make release-alpha VERSION=<X.Y.Z-alpha> [BUMP=patch|minor|major] [DRY_RUN=1] [RELEASE_REMOTE=<name>]
```

| Variable | Required | Meaning |
|---|---|---|
| `VERSION` | yes | The exact version to publish. Defaults to the `VERSION` file, which is never greater than itself, so omitting it is refused. |
| `BUMP` | no | Declares the kind of release. Refused unless `next_version(current, BUMP)` equals `VERSION`. |
| `DRY_RUN` | no | Rehearse everything, change nothing. |
| `RELEASE_REMOTE` | no | Remote to publish to. Default `dev`. |

## The script directly

```
scripts/release-alpha.sh --version X.Y.Z-alpha [--bump LEVEL] [--dry-run]
                         [--remote NAME] [--branch NAME]
```

`--branch` overrides the release branch (default `main`) and is the only way to
rehearse from a feature branch.

## Examples

Rehearse a patch release, printing the exact diff the release commit would
carry and the three tags it would publish:

```sh
make release-alpha VERSION=0.9.2-alpha BUMP=patch DRY_RUN=1
```

Rehearse from a feature branch, where the branch precondition would otherwise
refuse first:

```sh
scripts/release-alpha.sh --version 0.9.2-alpha --bump patch --dry-run \
	--branch "$(git symbolic-ref --short HEAD)"
```

Cut a breaking pre-1.0 release — MINOR is where breakage lives before 1.0:

```sh
make release-alpha VERSION=0.10.0-alpha BUMP=minor
```

Run the unit tests for the pure functions:

```sh
make test-scripts
```

## Refusals you should expect

```
$ make release-alpha VERSION=0.9.2 DRY_RUN=1
release-alpha: --version '0.9.2' is not a X.Y.Z-alpha version

$ make release-alpha VERSION=0.9.2-alpha BUMP=minor DRY_RUN=1
release-alpha: --bump minor on v0.9.1-alpha is v0.10.0-alpha, but --version says v0.9.2-alpha. Fix whichever one is wrong

$ make release-alpha VERSION=0.9.1-alpha DRY_RUN=1
release-alpha: v0.9.1-alpha is not greater than the current version v0.9.1-alpha. Pass the version to publish: make release-alpha VERSION=<X.Y.Z-alpha>
```

Add the `## [X.Y.Z-alpha]` CHANGELOG section and commit it **before** releasing.
The release workflow requires it, and it checks after the module tags have been
pushed and become permanent; the preflight here uses the same anchored match so
the refusal comes first.
