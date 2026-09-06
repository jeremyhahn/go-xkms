# Setup Wizard — CLI

> **Status: NORMATIVE** · Feature: `setup-wizard` · Module: `go-xkms/xkey` · Last verified: 2026-09-06

No CLI surface: the wizard is reachable only through the desktop GUI's Wails
bindings (see [api.md](api.md)). There is deliberately no `xkey setup` verb,
because the flow exists to show a human the generated SO PIN once and take
their acknowledgement; a non-interactive path would have nowhere to put that.

After setup, the PINs the wizard established are managed with the `xkey pin`
group, which drives the same qrdb PIN service. Note that `xkey pin set-so`
is that service's SO PIN, not the FIDO2 authenticator's, which is a
different credential (go-xkms#233).

The SO PIN is never retrievable from the CLI: `xkey password list` and
`xkey password get` read the password store, and the wizard does not put the
SO PIN there.
