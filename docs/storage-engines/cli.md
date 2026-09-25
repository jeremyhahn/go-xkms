# Storage Engines — CLI

> **Status: NORMATIVE** · Feature: `storage-engines` · Repo: `go-xkms` · Last verified: 2026-09-24

No CLI surface: `xkmsctl` has no `storage` command group and no flag that
opens or lists a storage engine's contents directly. Verified —
`cmd/xkmsctl/*.go` contains no file or command named for storage engine
selection or inspection. The engine is chosen once, by the server operator,
through `xkmsd`'s configuration (`storage.backend` / `XKMS_STORAGE_BACKEND`)
before the server starts; see engineering.md's Configuration section and
[`../xkmsd-configuration/cli.md`](../xkmsd-configuration/cli.md) for how
`xkmsd` resolves configuration generally.

Data stored through this layer is reached through the feature that owns it —
`xkmsctl key`, `xkmsctl cert`, `xkmsctl user`, and so on — never through a
storage-specific verb.
