# Release engineering — architecture

**Status:** implemented.
**Last verified:** 2026-09-21 against `scripts/release-alpha.sh` and
`scripts/release-tag.sh`.

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

## Two steps, not one (go-xkms#419, go-xkms#211)

A release used to be cut and published by one script, direct to `main`, with
no pull request anywhere in the path — `scripts/release-alpha.sh` committed
the version bump, created all three signed tags, and pushed the commit **and**
the tags to `main` atomically. On 2026-09-06 two releases raced for the same
base commit exactly because that path had no review gate to hold either one:
one run had a PR open and was waiting for review; the other reached the direct
path first and published `v0.9.5-alpha` — a PATCH release carrying nine new
exported symbols, a new config key and a new CLI command, none of which a
thirty-second review would have passed as a patch.

The fix is two scripts with one job each, not one script with a flag:

1. **`scripts/release-alpha.sh` / `make release-alpha` PREPARES.** It fetches
   the release branch, validates everything a release must satisfy, writes the
   version bump and pin rewrite to a **new branch** (`release/<version>`), and
   pushes **that branch only**. It prints the pull request URL and stops.
   Nothing is tagged, nothing is published to `main`. This is what
   go-xkms#419 calls "option 1": the tag step becomes a separate command run
   against a merge commit that has already passed CI and review, restoring the
   ordinary issue → branch → PR → review → merge flow to the one artifact —
   an immutable module tag — that least affords a mistake.
2. **`scripts/release-tag.sh` / `make release-tag` TAGS**, run only after that
   pull request has been reviewed and merged. It re-fetches `main`, asserts
   the commit it is about to tag is exactly what was reviewed, and only then
   creates and pushes the three signed tags atomically.

A direct push to `main` can no longer produce a tag under any circumstance:
nothing but `release-tag.sh` ever creates one, and it refuses to run against
anything it did not just fetch and verify.

## The invariant

> A release publishes exactly one new version, greater than the current version
> in every lockstep namespace and taken in none of them, from a commit that
> was fetched, reviewed and merged — or it publishes nothing.

## Fetch-and-assert, not a disposable checkout (go-xkms#211 "option B")

go-xkms#211 asked whether releases should be cut from an isolated, disposable
checkout of the remote tip, making the TOCTOU class between a release's first
read and its last push structurally unreachable rather than guarded. That
option — cutting from a checkout nothing else holds a handle on — was
**considered and declined**. What both scripts do instead:

- **`release-alpha.sh` fetches `--branch` from `--remote` and reads `VERSION`,
  the reciprocal pins and `CHANGELOG.md` from THAT fetched tip** (materialized
  read-only via `git archive`), never from whatever happens to be checked out
  locally. A stale local `main` cannot pass a check it never reads, and the
  branch a real cut creates is checked out FROM the fetched tip, not from the
  operator's prior `HEAD`.
- **`release-tag.sh` fetches `--branch` again and asserts three things before
  it creates anything**: local `HEAD` is byte-identical to the just-fetched
  tip (not merely a descendant — equal), `VERSION` at that commit (read from
  the git object, not the working tree) is exactly `--version`, and a commit
  reachable from that tip carries the exact `chore(release): <version>`
  message `release-alpha.sh` produces (a squash merge's appended `(#<pr>)` is
  the one accepted variation). It then re-validates the pins and the
  `CHANGELOG` heading against the resolved release commit rather than trusting
  review to have caught a divergence — a tag is immutable, and this is the
  last refusal available before one exists.

Both scripts still write into the operator's own checkout and index for
whatever they mutate (a new branch and a commit, or a set of tag objects), and
both still refuse to run on a dirty tree rather than defending every seam a
concurrent writer could hit. That is unchanged from before: this issue is
about REACHING the network's state honestly, not about isolating the run from
every other process on the host.

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
2. greater than `VERSION` at the fetched tip;
3. greater than the current tag in each of the three namespaces;
4. not already present in any of them;
5. in agreement with `BUMP`, when `BUMP` is given;
6. does not grow the exported Go API of a published module under an
   *effective* PATCH bump (see below).

`BUMP=patch|minor|major` is therefore a *declared intent* cross-checked against
the stated version, never a derivation. It is what makes a breaking pre-1.0
release expressible: the previous recipe hardcoded `PATCH+1`.

## The exported-API growth gate (go-xkms#419, go-xkms#421)

The incident that motivated the two-step split also exposed a second gap: the
script accepted `--bump patch` for a release that added nine exported Go
symbols, because nothing compared the diff's *shape* against the bump's
*claim*. `release-alpha.sh` now refuses that class outright.

**Gated on the DERIVED level, not on `--bump` being passed.** `bump_level
CURRENT NEXT` compares MAJOR and MINOR alone and returns `patch`, `minor` or
`major` — it never reads the `--bump` flag. The incident release shipped with
no `--bump` given at all, so gating on the flag's presence would not have
caught it; gating on what the two stated versions actually imply does, and it
agrees with `--bump` whenever `--bump` is given, because that agreement was
already enforced earlier in the same run.

**The comparison itself never runs `go build`.** `scripts/exportsurface` is a
small, dependency-free Go program that parses (with `go/parser`, not
`go/packages`) the non-test `.go` files of every candidate directory under a
module, skipping `internal/`, `testdata/`, `vendor/`, a directory that begins
another Go module (has its own `go.mod`), and a `package main` (nothing ever
imports it). It records each exported top-level function, type, const, var,
and — for a struct or interface — each exported field or method, labelled
`<module>:<pkg-relative-dir>.<Name>`. Given the same three published modules
(`.`, `sdk/go`, `xkey`) materialized twice — once from the previous release's
tag via `git archive`, once from the fetched tip about to become the new
release — it prints what was added and what was removed. `release-alpha.sh`
refuses the run when the derived level is `patch` and anything was added,
naming every added symbol in the refusal.

Not `go/packages` or `go list`: either would need to resolve the module graph
(`go mod download`), which is neither fast nor offline-safe as a release
precondition, and buys nothing here — the question is "did the declared shape
change", which a syntax-level read answers exactly as well as a fully
type-checked one for this purpose.

## Pin edges are declared, not counted

The nine `(file, module)` edges are listed in the script. The rejected
alternative — count pins at the current version, count again at the new one,
compare — fails open twice: a **stale** edge is counted in neither total, and a
**deleted** edge is absent from both, so the totals match while the release
ships a module that no longer pins its sibling. Naming each edge turns a
deletion into a failure and a legitimate dependency change into a one-line edit
reviewed alongside it. `test/scripts/release-alpha.test.sh` re-derives the edge
set from the tree and fails when the declaration drifts. `release-tag.sh`
reuses `PIN_EDGES` (and `TAG_NAMESPACES`, and the pure functions) by
`RELEASE_ALPHA_LIB=1`-sourcing `release-alpha.sh` rather than redeclaring any
of it — there is no second copy to drift out of step with the first.

## Bounds rather than guards

Both scripts refuse to start on a dirty tree or a detached `HEAD`. These are
**preconditions**, not race guards: they delete the "someone's unrelated edits
were swept into the release commit" class outright, and they make the `git
add` of the release files exact by construction. `release-tag.sh` additionally
refuses to run off any branch but the release branch, and refuses unless that
branch's `HEAD` is exactly the tip it just fetched — see "fetch-and-assert"
above.

## The rehearsal writes to a copy, not to the repository

`--dry-run` (on `release-alpha.sh` only — `release-tag.sh` has no dry run; its
every precondition is a read, and a refusal that read but wrote nothing needs
no rehearsal) exists to answer "what would this release do" without doing it,
so every step that writes is pointed at a `mktemp -d` copy of the fetched
tip's files. The diff is then a diff of the copy against that fetched-tip
snapshot, not against whatever the operator's own checkout happens to hold —
which, before a real cut's `git checkout -b`, may not match it at all.

The alternative — perform the step, show the result, undo it — was rejected
before the pin rewrite was written, and the changelog assembly proved why by
being the one step that did not follow the rule. Assembly deletes the entry
files it splices, so rehearsing it against the repository consumed the release
notes it was only supposed to preview, staged the deletions, and printed
"nothing was changed" (go-xkms#415, #416). An undo path is code that runs on
the failure path, where it is least tested; a copy has no failure path to get
wrong, which is also why there is no restore trap.

That places one constraint on anything the release calls: it must accept the
tree to operate on. `changelog-assemble.sh --root DIR` is that seam, and it is
the reason the option exists.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Keep one script that both prepares and publishes | go-xkms#419: the exact defect. No code path that ends in an immutable tag can also be the code path with no pull request in it. |
| Cut releases from a disposable, isolated checkout (go-xkms#211 "cut from a checkout") | Considered and declined; "fetch-and-assert" gets the load-bearing property (nothing is read from a stale local state) without changing where a release is written from. |
| Gate the growth check on `--bump` being passed | The incident it closes shipped with no `--bump` at all; gating on the flag misses exactly the case that motivated the gate. |
| `go/packages` or `go list` for the API diff | Needs a resolved module graph for a question a syntax-level read already answers, and a release precondition should not need `go mod download` to succeed. |
| Derive the version from `git describe` | The open question above. A glob such as `--match 'v*'` is not a version check, and it sees one namespace of three. |
| Compare pin *counts* before and after | Fails open on stale and deleted edges alike. |
| Discover pin edges by scanning `go.mod` | A removed reciprocal require then looks like a correct release rather than a defect. |
| `git tag -a` | Signs only when `tag.gpgSign` happens to be set, so agents got signed tags and humans unsigned ones. `-s` asks for it. |
| `git tag -v` to confirm signing | SSH-signed tags need an `allowedSignersFile` to verify; a correctly signed tag reports as unverifiable. The object is read instead. |
| `git push --tags` | Publishes every local tag, including leftovers from an abandoned attempt. |
| Non-atomic push | A partly published lockstep release cannot be withdrawn, only followed by another version. |
| Rehearse by doing and undoing | The undo runs on the failure path, where it is least tested. A scratch copy has no failure path; the changelog step's mutation of the real tree is what this row was written from. |
| Gate the changelog assembly out of a dry run entirely | Cheaper, but the rehearsal then hides the part of the release commit an operator most wants to read — and #361's failure class is entries landing under the wrong heading, which only a preview of the assembled section can catch. |
