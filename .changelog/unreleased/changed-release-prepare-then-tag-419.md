- **Cutting a release is now two steps, and only the second one publishes**
  (#419, #211, #421). `scripts/release-alpha.sh` used to commit the version
  bump, create all three lockstep tags, and push the commit *and* the tags to
  `main` atomically, in one run, with no pull request anywhere in that path —
  on 2026-09-06 two releases raced for the same base commit exactly because
  that path had no review gate to hold either one, and the unreviewed run
  published `v0.9.5-alpha`, a PATCH carrying nine new exported symbols with
  nothing to catch it. `make release-alpha` (`scripts/release-alpha.sh`) now
  fetches `--branch` (default `main`) from `--remote` (default `dev`) and
  reads `VERSION`, the reciprocal pins and `CHANGELOG.md` from that fetched
  tip — never from the operator's own checkout, which may be stale
  (go-xkms#211's "fetch-and-assert"; a fully isolated, disposable checkout was
  considered and declined). On a real cut it checks out a new branch
  `release/X.Y.Z-alpha` from the fetched tip, assembles the changelog, moves
  the pins, bumps `VERSION`, commits, and pushes **that branch only**; it
  prints the pull request URL and stops. Nothing is tagged and `main` is never
  written.

  A new `make release-tag VERSION=X.Y.Z-alpha` (`scripts/release-tag.sh`)
  publishes, run only after that pull request has been reviewed and merged. It
  fetches `--branch` again and refuses unless the local checkout's `HEAD` is
  byte-identical to the just-fetched tip, `VERSION` at that commit (read from
  the git object, not the working tree) is exactly `--version`, and a commit
  reachable from that tip carries the exact `chore(release): <version>`
  message `release-alpha.sh` produces (a squash merge's appended `(#<pr>)` is
  the one accepted variation) — then re-checks the reciprocal pins and the
  `CHANGELOG` heading against that resolved commit before creating and pushing
  the three annotated, signed tags atomically. `release-tag.sh` reuses
  `TAG_NAMESPACES`, `PIN_EDGES` and every pure function from
  `release-alpha.sh` by sourcing it with `RELEASE_ALPHA_LIB=1` rather than
  redeclaring any of it. `.github/workflows/release.yml`'s `push: tags: v*`
  trigger is unchanged and still fires exactly the same way; what changed is
  that nothing but `release-tag.sh` can ever create a tag, so a direct push to
  `main` can no longer produce one.

  Separately, `release-alpha.sh` now refuses an effective PATCH bump — derived
  from comparing the stated versions' MAJOR/MINOR, not from whether `--bump`
  was passed, since the incident that motivated this shipped with no `--bump`
  at all — that adds exported Go API to a published module since the previous
  release's tag. The comparison is `scripts/exportsurface`, a small
  dependency-free Go program (parses with `go/parser`, never resolves a
  module graph) that diffs the exported top-level declarations of every
  non-internal package under the root, `sdk/go` and `xkey` modules between two
  materialized trees — the previous tag via `git archive`, the fetched tip
  about to become the new release — and lists what was added.

  Files: `scripts/release-alpha.sh`, `scripts/release-tag.sh` (new),
  `scripts/exportsurface/main.go` (new), `Makefile`,
  `.github/workflows/release.yml`, `test/scripts/release-alpha.test.sh`,
  `test/scripts/release-tag.test.sh` (new), `docs/release-engineering/`.
  Verified by `make test-scripts`: the pure-function suite plus, end to end
  against throwaway fixture repositories with their own bare `dev` remotes —
  a dry run reads the network but writes nothing; prepare validates against
  what was just fetched even when the local checkout has never seen the
  remote's real state; a duplicate release branch is refused; the growth gate
  refuses an implied or explicit PATCH that grew the API and allows the same
  growth under MINOR; a real cut lands on a new branch, leaves `main` (local
  and remote) untouched, and refuses to prepare the same version twice; and
  `release-tag.sh`, using this repository's own agent signing key, refuses a
  stale `HEAD`, a branch mismatch, a `VERSION` mismatch, an unreachable
  release commit, an inconsistent pin set and a missing `CHANGELOG` heading in
  turn, then succeeds and pushes three verified, signed tags atomically.
