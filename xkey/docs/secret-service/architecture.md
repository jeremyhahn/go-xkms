# Secret Service — Architecture

> **Status: NORMATIVE** · Feature: `secret-service` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## The problem

Linux desktop applications that need to store a password or token — browsers,
`git`, password managers, SSH tooling — talk to whatever implements the
freedesktop.org [Secret Service API](https://specifications.freedesktop.org/secret-service/)
on the session bus as `org.freedesktop.secrets`: usually GNOME Keyring or
KWallet. xkey already has an encrypted, barrier-backed password store
(`pkg/staticpw`, see [`../../../docs/password-vault/`](../../../docs/password-vault/));
this feature exposes that store over the same D-Bus contract, so
`secret-tool`, `git-credential-libsecret`, and browsers can use xkey as their
secret store without knowing xkey exists.

## Shape chosen: the store IS the object model, the barrier IS the lock

The Secret Service object model has four kinds of object: `Service`,
`Collection`, `Item`, `Session`, plus a one-shot `Prompt`. xkey does not
introduce a second storage layer to back them — it maps the model directly
onto `pkg/staticpw`:

| Secret Service object | go-xkms concept |
|---|---|
| `Collection` | A static-password **folder** (`StaticPassword.FolderPath`); `""` is the default/login collection |
| `Item` | A `StaticPassword` entry within a folder |
| Item attributes | `StaticPassword.Attributes` (generic `map[string]string`, added by this feature — see engineering.md), overlaid on legacy `service`/`username`/`url` derived from the existing fields |
| Locked state | `barrier.IsSealed()` — **one barrier, one lock**, for every collection and item at once |

There is exactly one lock because there is exactly one barrier per daemon
process (see [`../seal/architecture.md`](../seal/architecture.md)).
`Collection`/`Item` do not carry their own lock bit: locked-ness is always
read live from the barrier, never cached, so a `Lock`/`Unlock` call is
instantaneous and can never disagree with the store's own ability to decrypt.

**Rejected alternative: a per-collection lock.** The Secret Service API
allows a `Service.Unlock` call naming a subset of collections and unlocking
only those. xkey's barrier does not support partial unseal — the DEK either
exists in memory or it does not — so implementing per-collection locking
would mean layering a second, independent encryption key per folder on top
of the barrier. That is a materially bigger feature (key management, key
rotation, the question of where per-folder keys live while the barrier
itself is sealed) for a capability none of this feature's two verification
targets (`secret-tool`, `git-credential-libsecret`) exercise. `Lock`/`Unlock`
always act on the whole barrier regardless of which objects were named; see
engineering.md for the exact contract.

## Shape chosen: Prompt drives xkey's existing unseal, not a new one

`Service.Unlock` on a sealed barrier returns a `Prompt` object rather than
failing outright, matching the API. Resolving that prompt calls a
`secretservice.UnlockFunc` supplied by whoever wires the daemon — the CLI
verb resolves a password exactly the way `xkey barrier unseal` does
(`--barrier-password`, `--barrier-password-file`, `XKEY_BARRIER_PASSWORD`,
then an interactive terminal prompt), so this feature does not introduce a
second unseal code path. A GUI wiring (not shipped by this issue) would
supply a GUI dialog instead; the daemon itself does not know or care which.

## Rejected alternative: auto-unlock

The previous, incomplete revision of this package defaulted `AutoUnlock:
true` in its config and never wired it to anything. Auto-unlocking a secret
store the moment a process asks for it defeats the purpose of a barrier —
any session-bus client could read every secret, which is the vulnerability
go-xkms#723 was filed to close (see the Security section of
engineering.md). There is no auto-unlock option in the shipped
configuration.

## Storage: what changed in `pkg/staticpw`

Two small, additive changes to the shared password store, used only by this
feature today:

- `StaticPassword.Attributes map[string]string` — a generic attribute bag.
  Secret Service items carry arbitrary caller-defined attributes (`protocol`,
  `host`, `xdg:schema`, …); `pkg/staticpw`'s existing fields cover the
  password-manager UI's fixed set (name/username/url/notes) but not that.
  JSON round-trips it like every other field; DAO-backed stores (used by
  quicbaas, not by xkey) carry it through `PasswordEntity.Attributes` too, so
  no consumer silently drops it.
- `BackendStore.SetAlias` / `GetAlias` — a persisted alias name → folder-path
  mapping, using the same "marker key" technique the store already uses for
  empty folders (`CreateFolder`/`RemoveFolder`). Not part of the `Store`
  interface (see engineering.md "Capability interfaces"): only the canonical
  barrier-backed `BackendStore` implements it, so DAO/encrypted/scoped
  stores are not forced to carry alias bookkeeping they have no caller for.

## Component map

```
xkey/pkg/secretservice/
  service.go       Daemon + org.freedesktop.Secret.Service methods
  collection.go    Collection object (Delete/SearchItems/CreateItem + properties)
  item.go          Item object (Delete/GetSecret/SetSecret + properties)
  session.go       Session object (Close)
  prompt.go        Prompt object (Prompt/Dismiss/Completed) + unlock resolution
  mapping.go       D-Bus object path <-> folder/password-ID mapping
  crypto.go        dh-ietf1024-sha256-aes128-cbc-pkcs7 session transport crypto
  fips.go          FIPS 140 algorithm gate (see engineering.md)
  errors.go        Typed sentinel errors + Secret.Error D-Bus name mapping

xkey/cmd/xkey/cmd/secret_service.go   `xkey secret-service` daemon verb
```

Wiring direction: the CLI verb constructs a `*xkms.Barrier` and a
`xkms.StaticPasswordStore` on top of it (`xkms.NewBarrierBackend` +
`xkms.NewStaticPasswordStore`) — the same pattern `xkey barrier unseal`
already uses — and hands both to `secretservice.NewDaemon`. The package
itself never imports `os/exec`, terminal I/O, or GUI code: it stays testable
in-process (see the loopback-bus test harness in
`xkey/pkg/secretservice/service_dbus_test.go`) and reusable from a future GUI
toggle without change.

## Related documentation

- [`../seal/architecture.md`](../seal/architecture.md) — the barrier this
  feature locks and unlocks.
- [`../password/architecture.md`](../password/architecture.md) — the password-manager
  GUI/CLI surface over the same `pkg/staticpw` store (not yet converted to
  the five-file convention).
- [Secret Service API specification](https://specifications.freedesktop.org/secret-service/) —
  the upstream contract this package implements.
