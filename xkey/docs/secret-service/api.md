# Secret Service — API

> **Status: NORMATIVE** · Feature: `secret-service` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Transport: D-Bus only

This feature's API **is** the D-Bus surface — there is no REST, gRPC, QUIC,
MCP, or embedded-SDK equivalent, by design: the whole point is to speak the
protocol existing Secret Service clients (`secret-tool`,
`git-credential-libsecret`, browsers) already use. Well-known bus name:
`org.freedesktop.secrets`. Full protocol:
[Secret Service API specification](https://specifications.freedesktop.org/secret-service/).

## `org.freedesktop.Secret.Service` — object `/org/freedesktop/secrets`

| Method | Signature | Notes |
|---|---|---|
| `OpenSession` | `(s algorithm, v input) -> (v output, o result)` | `algorithm` is `plain` or `dh-ietf1024-sha256-aes128-cbc-pkcs7`; the latter is refused under FIPS enforcement (engineering.md) |
| `CreateCollection` | `(a{sv} properties, s alias) -> (o collection, o prompt)` | Persists a `pkg/staticpw` folder; refuses `IsLocked` while sealed |
| `SearchItems` | `(a{ss} attributes) -> (ao unlocked, ao locked)` | Searches every collection; `locked` is always empty — a sealed barrier fails the whole call with `IsLocked` instead of a partial answer (architecture.md) |
| `Unlock` | `(ao objects) -> (ao unlocked, o prompt)` | Immediate when already unsealed; otherwise returns a `Prompt` (engineering.md) |
| `Lock` | `(ao objects) -> (ao locked, o prompt)` | Always seals the whole barrier; `prompt` is always `/` |
| `GetSecrets` | `(ao items, o session) -> (a{o(oayays)} secrets)` | Refuses `IsLocked` while sealed |
| `ReadAlias` | `(s name) -> (o collection)` | Persisted alias, else the built-in default/login/`CollectionFolderMap` heuristics |
| `SetAlias` | `(s name, o collection)` | Persisted when the store supports it (engineering.md "Capability interfaces") |

Property: `Collections` (`ao`, read-only) — every folder as a collection
path; only the default collection while sealed.

Signals: `CollectionCreated(o)`, `CollectionDeleted(o)`, `CollectionChanged(o)`.

## `org.freedesktop.Secret.Collection` — one object per folder

| Method | Signature | Notes |
|---|---|---|
| `Delete` | `() -> (o prompt)` | Deletes every item directly in the folder plus the folder marker; `prompt` is always `/` (immediate); refuses `IsLocked` while sealed |
| `SearchItems` | `(a{ss} attributes) -> (ao results)` | Scoped to this folder only |
| `CreateItem` | `(a{sv} properties, (oayays) secret, b replace) -> (o item, o prompt)` | `properties["org.freedesktop.Secret.Item.Label"]` (required) and `["...Attributes"]` (optional `a{ss}`); refuses `IsLocked` while sealed |

Properties: `Items` (`ao`, read-only), `Label` (`s`, **read-only** — see
engineering.md "Known limitations"), `Locked` (`b`, read-only, live
`barrier.IsSealed()`), `Created`/`Modified` (`t`, read-only, derived).

## `org.freedesktop.Secret.Item` — one object per password entry

| Method | Signature | Notes |
|---|---|---|
| `Delete` | `() -> (o prompt)` | `prompt` always `/`; refuses on a read-only entry (TPM-policy-generated) or while sealed |
| `GetSecret` | `(o session) -> ((oayays) secret)` | Delegates to `Service.GetSecrets` for one item |
| `SetSecret` | `((oayays) secret)` | Refuses an empty value (`ErrSecretValueEmpty`) or while sealed |

Properties: `Locked` (`b`, read-only), `Attributes` (`a{ss}`, writable),
`Label` (`s`, writable — changes `Title` only, never `Name`/`FolderPath`,
so the item's D-Bus path never changes), `Type` (`s`, read-only,
`org.freedesktop.Secret.Generic`), `Created`/`Modified` (`t`, read-only).

## `org.freedesktop.Secret.Session`

| Method | Signature | Notes |
|---|---|---|
| `Close` | `()` | Ends the session; further `GetSecret(s)`/`SetSecret` calls against it fail `NoSuchObject` |

## `org.freedesktop.Secret.Prompt`

| Method | Signature | Notes |
|---|---|---|
| `Prompt` | `(s window_id)` | Resolves the pending operation (today: always an `Unlock`); `window_id` is accepted but unused (no GUI wiring ships with this issue) |
| `Dismiss` | `()` | Cancels without attempting the operation |

Signal: `Completed(b dismissed, v result)` — `result` is `ao` (the objects
that were unlocked) on success, empty on dismissal/failure.

## Error names

See engineering.md's "Errors" table:
`org.freedesktop.Secret.Error.IsLocked` and
`org.freedesktop.Secret.Error.NoSuchObject` are used where the spec
distinguishes them from a generic failure; everything else surfaces as
`org.freedesktop.DBus.Error.Failed`.
