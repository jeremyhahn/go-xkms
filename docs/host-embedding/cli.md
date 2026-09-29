# Host Embedding — CLI

> **Status: NORMATIVE** · Feature: `host-embedding` · Repo: `go-xkms` · Last verified: 2026-09-29

No CLI surface: host embedding is a composition seam configured in the
embedding host's Go code through the SDK options in [`api.md`](api.md). The
features it enables are driven by the same `xkmsctl` and `xkey` verbs as
against `xkmsd` — point `--server` at the host instead.
