- **`release-alpha.sh --dry-run` no longer assembles the changelog against the
  real tree**: a rehearsal folded `.changelog/unreleased/*.md` into the real
  `CHANGELOG.md`, deleted every entry file it spliced, staged both, and then
  printed `release-alpha: nothing was changed` — so the command an operator
  runs *because* it is safe was the one that consumed the release notes, and
  the real cut that followed died on its own clean-tree precondition. The
  changelog assembly now runs where the pin rewrite always did: in a
  `mktemp -d` copy of `VERSION`, the four `go.mod` files, `CHANGELOG.md` and
  `.changelog/unreleased`, so a dry run leaves the working tree byte-identical
  and the index empty however it exits, while still previewing the assembled
  `## [X.Y.Z-alpha]` section in the diff and naming each entry a real cut would
  consume. `scripts/changelog-assemble.sh` grew the `--root DIR` option that
  makes this expressible — assembly is destructive, so a caller must be able to
  point it at a copy. The pin set is now validated before anything is written,
  so a tree that will be refused is refused with its entries intact. Relatedly,
  a run that dies at the tag-signing check now names the *release commit* as
  well as the tags in its cleanup hint (`git tag -d ... && git reset --hard
  <base>`): the commit is created before the tags are signed, so the tag-only
  hint left the operator standing on an unsigned `chore(release)` commit, to
  discover it at the push where `main` enforces signed commits. Verified by an
  end-to-end case in `test/scripts/release-alpha.test.sh` that asserts a
  before/after manifest of `.changelog/` and `CHANGELOG.md` is identical across
  a `--dry-run`, and that the run issues no git write subcommand at all. The
  irony is noted: the release-notes tooling ate the release notes, and this
  entry is one of the files a dry run would have deleted. Fixes #415, #416.
