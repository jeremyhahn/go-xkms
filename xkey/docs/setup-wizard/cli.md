# Setup Wizard — CLI

> **Status: NORMATIVE** · Feature: `setup-wizard` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

No CLI surface: the wizard is reachable only through the desktop GUI's Wails
bindings (see [api.md](api.md)). There is deliberately no `xkey setup` verb,
because the flow exists to show a human the generated SO PIN once and take
their acknowledgement; a non-interactive path would have nowhere to put that.

After setup, the PINs the wizard established are managed with the `xkey pin`
group, which resolves the same governing PIN backend the wizard selected
(software or TPM2 — see [../pin strategy](../setup-wizard/engineering.md#shared-governing-pin-strategy-go-xkms307)
and `xkey pin status`). Note that `xkey pin set-so` is the host PIN
service's SO PIN, not the FIDO2 authenticator's, which is a different
credential (go-xkms#233).

Before go-xkms#307 the wizard (running inside the GUI) could enroll the
user PIN on a TPM2 Platform SRK while `xkey pin` still hard-coded the
software store, so a PIN that verified through one answered "invalid" from
the other. `xkey pin` and the headless daemon now resolve through the same
`xkey/pkg/pinstrategy` record the wizard persists, and refuse — rather than
silently falling back to software — when that record names a backend they
cannot reach.

The SO PIN is never retrievable from the CLI: `xkey password list` and
`xkey password get` read the password store, and the wizard does not put the
SO PIN there.
