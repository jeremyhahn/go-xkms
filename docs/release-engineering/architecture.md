# Release engineering — architecture

**Status:** implemented.
**Last verified:** 2026-09-03 against `scripts/release-alpha.sh`.

## What a release is

One version, published simultaneously in **three lockstep tag namespaces**:

```
v<X.Y.Z>-alpha            the root module
sdk/go/v<X.Y.Z>-alpha     github.com/jeremyhahn/go-xkms/sdk/go
xkey/v<X.Y.Z>-alpha       github.com/jeremyhahn/go-xkms/xkey
```

All three point at the same commit, and that commit carries the version in
`VERSION` plus **nine reciprocal `go.mod` pins** moved to it. `web/desktop` is
the repository's fourth module but is not published: it replaces all three
siblings with local paths and no consumer ever resolves it, so it has no tag
namespace. Its pins are still part of the edge set, because leaving them behind
would let the four modules drift out of step in the tree.

## The invariant

> A release publishes exactly one new version, greater than the current version
> in every lockstep namespace and taken in none of them, from a clean tree on
> the release branch — or it publishes nothing.

## The version is stated, not derived

`make release-alpha VERSION=0.9.2-alpha` requires the version. This is the
central design decision and it is a decision about the shape of the question.

Deriving the version asks an **open** question — *what is the greatest version
anywhere?* Its answer depends on local tags, remote tags, reachability,
malformed tags, three namespaces, partial publications, and whether each lookup
succeeded; every one of those is a separate failure mode discovered one at a
time. Validating a stated version asks a **closed** one, against a checklist
that is finite and does not grow when a new edge case appears:

1. well-formed `X.Y.Z-alpha`;
2. greater than `VERSION`;
3. greater than the current tag in each of the three namespaces;
4. not already present in any of them;
5. in agreement with `BUMP`, when `BUMP` is given.

`BUMP=patch|minor|major` is therefore a *declared intent* cross-checked against
the stated version, never a derivation. It is what makes a breaking pre-1.0
release expressible: the previous recipe hardcoded `PATCH+1`.

## Pin edges are declared, not counted

The nine `(file, module)` edges are listed in the script. The rejected
alternative — count pins at the current version, count again at the new one,
compare — fails open twice: a **stale** edge is counted in neither total, and a
**deleted** edge is absent from both, so the totals match while the release
ships a module that no longer pins its sibling. Naming each edge turns a
deletion into a failure and a legitimate dependency change into a one-line edit
reviewed alongside it. `test/scripts/release-alpha.test.sh` re-derives the edge
set from the tree and fails when the declaration drifts.

## Bounds rather than guards

The script refuses to start on a dirty tree or a detached HEAD, and refuses to
run off the release branch. These are **preconditions**, not race guards: they
delete the "someone's unrelated edits were swept into the release commit" class
outright, and they make the `git add` of the release files exact by
construction.

The script deliberately does **not** defend the seams between its first read
and its final push against a concurrent writer. Doing so means cutting the
release from an isolated, disposable checkout so those races are unreachable
rather than guarded, which changes where releases happen — an architecture
decision, tracked as go-xkms#211.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Derive the version from `git describe` | The open question above. A glob such as `--match 'v*'` is not a version check, and it sees one namespace of three. |
| Compare pin *counts* before and after | Fails open on stale and deleted edges alike. |
| Discover pin edges by scanning `go.mod` | A removed reciprocal require then looks like a correct release rather than a defect. |
| `git tag -a` | Signs only when `tag.gpgSign` happens to be set, so agents got signed tags and humans unsigned ones. `-s` asks for it. |
| `git tag -v` to confirm signing | SSH-signed tags need an `allowedSignersFile` to verify; a correctly signed tag reports as unverifiable. The object is read instead. |
| `git push --tags` | Publishes every local tag, including leftovers from an abandoned attempt. |
| Non-atomic push | A partly published lockstep release cannot be withdrawn, only followed by another version. |
