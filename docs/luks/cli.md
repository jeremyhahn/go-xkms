# LUKS (root module) — CLI

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-30

**No `xkmsctl` surface.** Verified: no case-insensitive match for `luks`
anywhere under `cmd/xkmsctl` (excluding this package's own tests, which do
not exist there — the string does not appear at all).

`pkg/luks` itself has no CLI. As of go-xkms#917, `xkey/pkg/luks` is a thin
wrapper around this package's `sdk/go/luks` re-export (`Executor`/
`LibExecutor`) rather than a separate implementation, but the CLI surface
remains `xkey`'s: `xkey luks2 *` is the only command group that exercises
`pkg/luks`'s code. See
[`architecture.md`](architecture.md#neighboring-packages-named-luks-out-of-scope-here).
Its full command reference is
[`../../xkey/docs/luks/cli.md`](../../xkey/docs/luks/cli.md).

If `xkmsd` ever needs its own LUKS volume (e.g. encrypting its own storage
root), it would construct a `luks.Manager` with `luks.NewLibExecutor()`
directly through `sdk/go/luks` — no new production `Executor` would be
needed, since one now exists.
