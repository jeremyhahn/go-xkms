# PKCS#11 Module/Token Manager — CLI

> **Status: NORMATIVE** · Feature: `pkcs11-manager` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

No CLI surface: `PKCS11Service` and the per-slot backend-registry
synchronization it performs are reachable only through the xkey GUI
(`xkey/pkg/gui`), which binds `PKCS11Service`'s methods to the Wails
frontend. See [api.md](api.md) for that surface.

`cmd/xkey/cmd/piv_pkcs11.go` (`-tags pkcs11`) is a separate, unrelated CLI
concern -- PIV certificate storage backed by a PKCS#11 token for the `xkey
piv` command group -- and does not go through `PKCS11Service` or the
registry synchronization this feature adds.
