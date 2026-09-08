- **`release.yml` survives a flaked matrix leg (#447).** The asset upload
  deleted an existing asset and re-uploaded it, which Gitea answers with
  404, so re-running a release after one leg flaked failed every leg that
  had already succeeded; `Create Master Checksums` then never ran and the
  tag, which cannot be re-cut, lost its checksums file for good. Uploads
  now go through `scripts/release-assets.sh`, which leaves an asset that is
  present with the same SHA-256 alone, replaces one whose digest differs
  and adds one that is absent. The checksums job runs whenever the release
  exists, verifies the release carries every asset the build matrix
  produces (failing on what is genuinely missing, not on how many runs it
  took), assembles `checksums.txt` from the per-asset `.sha256` files it
  downloads through the Gitea API, and uploads it the same idempotent way;
  the `gh` CLI it used before does not speak to Gitea, so that download had
  been silently empty on every release cut here. The announcement is gated
  on the verified release rather than on this run's matrix.
