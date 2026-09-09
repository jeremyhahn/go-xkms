- **CI runs every xkey unit package.** The Nested Module Tests job ran 6 of
  the xkey module's package trees and compiled the rest, so 2,987 test
  functions in 41 packages -- truststore, tokenstore, luks, ca,
  secretservice, nssdb, pivcert, pkcs11mgr, sshstore, sshlocal, config,
  audit among them -- could not fail. The job's stated reason, that ten
  packages failed identically on main, was a missing `codec_json` build tag:
  with it, all 41 pass under `-race`. Forty of them now run on every PR in
  one step that also records each deliberate exclusion with its reason;
  `xkey/pkg/pkcs11`, 37% of the set's cost for 34 tests, runs nightly
  instead. Whole-package runs for `cmd/xkey/cmd` and `pkg/gui/services` are
  #332 and `sdk/go` is #333 (#147).
