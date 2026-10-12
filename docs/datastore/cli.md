# Datastore — CLI

> **Status: NORMATIVE** · Feature: `datastore` · Repo: `go-xkms` · Last verified: 2026-10-12

No CLI surface: `xkmsctl` has no `datastore` command group and no flag that
opens or lists the datastore's contents directly. Verified —
`cmd/xkmsctl/*.go` contains no file or command named for datastore
selection or inspection. The datastore is chosen once, by the server
operator, through `xkmsd`'s configuration (`datastore.engine` /
`datastore.mode` / `XKMS_DATASTORE_*`) before the server starts; see
engineering.md's Configuration section and
[`../xkmsd-configuration/cli.md`](../xkmsd-configuration/cli.md) for how
`xkmsd` resolves configuration generally.

Data stored through this layer is reached through the feature that owns it —
`xkmsctl key`, `xkmsctl cert`, `xkmsctl user`, and so on — never through a
storage-specific verb.

`xkmsctl admin` and `xkmsctl user` still declare a persistent
`--storage-path` flag (`cmd/xkmsctl/admin.go:729`, `cmd/xkmsctl/user.go:1125`).
`admin create` resolves it — flag, then `XKMS_STORAGE_PATH`, then
`/var/lib/xkms` (`cmd/xkmsctl/admin.go:747-754`) — and only echoes the result
in verbose output (`cmd/xkmsctl/admin.go:85`); it opens nothing. It does not
select or reach the datastore, and `xkmsd` reads no `XKMS_STORAGE_PATH`.
