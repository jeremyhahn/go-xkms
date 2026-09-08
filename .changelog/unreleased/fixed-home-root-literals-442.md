- **`xkey backup` and `xkey device` address the xKey home through `xhome`
  (#442).** Two home-root literals survived #381's data-dir adoption because
  they are of a different shape: the default backup directory was
  `$HOME/.xkey/backups` and the shared devices file `$HOME/.xkey/devices.yaml`
  whatever `XKEY_HOME` or portable mode said, so a backup written under a
  configured home was not where the operator would look for it. Both now
  resolve through the same four-strategy chain as every other command, and a
  home that cannot be resolved is an error rather than a path under `$HOME`.
  `xhome.ResolveForUser(homeDir)` is new: the per-user strategy evaluated
  against a given home, which is how `sudo xkey device pair` keeps sharing
  the invoking user's devices file with their GUI session while `XKEY_HOME`
  and portable mode still take precedence. The `cmd` package's grep gate
  gains a home-root pattern (`TestNoAdHocHomeRootLiterals`) so the shape
  cannot regrow.
