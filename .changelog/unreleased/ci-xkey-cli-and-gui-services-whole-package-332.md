- **CI runs `cmd/xkey/cmd` and `pkg/gui/services` whole.** The two packages
  held 8,282 test functions, and the named-selector steps ran 27 of them: a
  renamed test was a red job, but a test added to either package arrived
  dark and stayed dark. Both now run as whole packages in the unprivileged
  xkey unit step, under `-tags ble` so the CLI's fail-closed fingerprint
  tests and the logins harness guard are included. The "pre-existing
  failures" that justified naming were CI running as root; as an
  unprivileged user both packages are green (1,761 and 6,521 tests). The
  one stale test found on the way, which pinned the pre-xhome behaviour of
  refusing a missing `~/.xkey`, now asserts the current contract: the home
  is created 0700 on first use, and an unwritable one fails with
  `ErrSharePolicySetFailed` carrying the permission error. `require-tests.sh`
  has no remaining caller and is removed (#332, #111).
