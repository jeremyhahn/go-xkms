# OATH TOTP/HOTP — API

> **Status: NORMATIVE** · Feature: `oath` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

No network-transport surface. OATH credential management is reachable
through the CLI ([cli.md](cli.md)) and, for the desktop GUI, through direct
Go method calls on `pkg/gui/services.OATHService` over Wails bindings (see
[engineering.md](engineering.md) for the method list). Neither is served
over REST, gRPC, or any other transport, and neither requires an `xkmsd`
server.

One in-process consumer crosses a feature boundary without crossing a
transport: `pkg/gui/services.AutoFillService.GetTOTPForDomain`/`GetTOTPByID`
call `OATHService.GenerateTOTP` directly to fill a TOTP field during browser
autofill — see [autofill/api.md](../autofill/api.md). That path is still a
same-process Go method call, not a second network surface.

Phone-backed OATH sync (`xkey oath sync`/`push`/`pull`,
`cmd/xkey/cmd/device_oath_sync.go`) does cross a transport (BLE/USB to a
paired phone), but it is owned by the `device`/`phone` feature folders, not
this one.
