- **`cmd/xkmsctl` no longer discards errors with `_ =`.** The ~870 ignored-error
  sites the package started with (measured by
  `grep -rnE "_ :?= |, _ :?= " cmd/xkmsctl --include='*.go' | grep -v _test.go`)
  are down to 13, every one of which is `pem.Decode`'s non-error `rest
  []byte` return, kept intentionally. Two new structural helpers remove the
  sites rather than papering over them: `flagReader` (`flags.go`) replaces
  `x, _ := cmd.Flags().GetX(name)` with `fr := newFlagReader(cmd)` /
  `x := fr.X(name)` / a single `fr.Err()` check per command, reporting a
  typed `*FlagReadError` (mistyped or misspelled flag) instead of silently
  returning a zero value; a matching `markFlagRequired` helper replaces
  `_ = cmd.MarkFlagRequired(name)`, recording a build-time `*InitError` in a
  package-level `initErrors` slice that `Execute` checks before dispatch and
  `TestInitErrors`-style coverage asserts is empty, rather than panicking in
  command-tree construction. `outputWriter` (`writer.go`) replaces
  `_, _ = fmt.Fprintf(w, ...)` with a small error-recording writer — modeled
  on `xkey/tools/skillgen`'s — whose `printf`/`println`/`print` are no-ops
  once a write has failed, checked once via `Err()` at the end of each
  command instead of after every line; `Printer` (`output.go`) now wraps one
  internally, and every `PrintX` method returns its recorded write error
  instead of an unconditional `nil`. Deferred best-effort `Close`/cleanup
  calls (`defer func() { _ = cl.Close() }()`, ~140 sites) now route through
  new `closeQuietly`/`closeFuncQuietly` helpers that log the failure at
  debug level instead of discarding it silently. A new `TestFlagBindings`
  (`flagbindings_test.go`) statically walks every `flagReader`-mediated read
  in the package and confirms the flag it names is registered, with a
  matching type, somewhere in the live `rootCmd` tree — the same check
  caught a stale test fixture (`bootstrap_run_test.go`'s hand-built command
  copy was missing `--p256-key`, previously masked by the discarded error it
  now replaces) during this change. No flag name, default, or output text
  changed. Files: `cmd/xkmsctl/flags.go`, `cmd/xkmsctl/writer.go`,
  `cmd/xkmsctl/output.go`, `cmd/xkmsctl/root.go`, and every other non-test
  `cmd/xkmsctl/*.go` file; tests: `cmd/xkmsctl/flags_test.go`,
  `cmd/xkmsctl/writer_test.go`, `cmd/xkmsctl/flagbindings_test.go` (go-xkms#702).
