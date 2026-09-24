# LUKS2 Encrypted Storage — API

> **Status: NORMATIVE** · Feature: `luks` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

No REST, gRPC, MCP, GUI or SDK surface. `xkey luks2` is reachable only
through the CLI (`cmd/xkey/cmd/{seal,unseal,lock,migrate,wipe,import_data}.go`).

There is no `pkg/gui/services` type for LUKS — the desktop GUI has no way to
seal, unseal, lock, migrate, wipe or import a LUKS container today, and
every operation requires root and an interactive-or-piped terminal for the
passphrase, which a Wails binding cannot supply without its own design. See
[architecture.md](architecture.md#what-this-feature-deliberately-does-not-do).

`xkey/pkg/luks` is an ordinary Go package other code in this module could
import directly, but nothing outside `cmd/xkey/cmd` does so today.
