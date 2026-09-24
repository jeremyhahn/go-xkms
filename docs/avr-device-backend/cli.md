# AVR Device Backend — CLI

> **Status: NORMATIVE** · Feature: `avr-device-backend` · Repo: `go-xkms` · Last verified: 2026-09-23

No CLI surface. The backend is reachable only through the Go API: it is
constructed around a link the caller has already opened, and `xkmsctl` has no
verb that opens a serial port.

`xkmsctl backends list` will not show it either, for the same reason — the
backend is not registered by `pkg/server`'s `initializeBackends`, because there
is no daemon configuration yet that says which port a device is on. That
decision is open; see `api.md`.

The device's own vendor CLI, `agctl`, ships with `arduino-generic` and is the
tool for talking to a part directly.
