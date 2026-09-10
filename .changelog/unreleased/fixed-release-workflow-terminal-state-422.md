- **The release workflow always reaches a terminal state.** A build leg
  that hung ran into the runner's three-hour default and left the run
  `in_progress` while the release page showed only the legs that had
  finished, with no master checksums. Every job now carries a
  `timeout-minutes` sized from the healthy runs (75 minutes for a binary
  leg, which builds arm64 under QEMU in 20–33), the matrix no longer
  cancels its other legs when one fails, and the checksums job is a bare
  `always()` gate that fails the run naming every expected asset the
  release lacks, so a partial release is a red run rather than a
  green-looking page.
