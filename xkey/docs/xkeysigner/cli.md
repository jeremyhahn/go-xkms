# xkeysigner — CLI

> **Status: NORMATIVE** · Feature: `xkeysigner` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

No CLI surface: `pkg/xkeysigner` is a library consumed programmatically —
by the go-xkms SDK's `xkms.WithXKeyAuth` option
(`xkey/docs/xkeysigner/architecture.md`) — and by nothing under
`xkey/cmd/`. No `xkey` subcommand constructs a `xkeysigner.Signer` or sets
`XKEY_IPC_SOCKET` for this purpose; the only relevant CLI-adjacent fact is
that the GUI application must be running to answer the socket at all
(`architecture.md` "The daemon on the other end is the GUI app").
