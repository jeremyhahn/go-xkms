# Web console: SSH Key Import (lane suiq, row 1443)

## Gap

The server takes `POST /xkms/v1/ssh/keys/import` (ssh:write) and returns a
stored key's public line through `GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}/public`
(ssh:read), and the TS SDK has `ssh.importKey`, `ssh.getKey` and
`ssh.exportPublic`. No console view makes these calls: SshView lists,
generates and deletes keys; SSH Trust covers known hosts and authorized keys.

## The view

- `web/app/src/views/SshKeyImportView.svelte`, `PageHeader` "SSH Key Import".
- Import form: scope, owner, name, optional comment, PEM textarea, optional
  passphrase (type password). Import is disabled until scope, owner, name and
  PEM are set. The PEM and passphrase are base64-encoded (UTF-8 bytes, `btoa`)
  for the request, cleared after every attempt, and never shown in a toast,
  an error or the console.
- Result card: algorithm and fingerprint of the imported key.
- Lookup row: scope, owner, name and "Show public key", which calls
  `ssh.exportPublic` and shows the `authorized_keys` line in a monospace block.
- Errors in an `Alert`.

## Wiring (one added line per place, shared rule with suia-suio and suip)

- Route `#/ssh/import` -> `sshKeyImport` (router.svelte.ts: one line in the
  `RouteName` union, one in the path map).
- App.svelte: one import line, one dispatch line.
- nav.ts: one Security entry, capability `ssh`, requires ssh:write.

## Tests

`web/app/test/view3_ssh_key_import.test.ts`: validation, import (base64 PEM,
passphrase only when given, fields cleared), secret hygiene, public line,
errors. Committed before the view (ruling 286).

## Checks

sdk/ts build, svelte-auth and web/app `npm ci`, the new vitest file, the whole
web/app suite, svelte-check, vite build, `pkg/api/rest` -race, sdk/go build,
make lint.

## Out of scope

SshView, SshTrustView, key generation, signing, Go code, sdk/ts, SPEC.md.

## Results

Results to follow.
