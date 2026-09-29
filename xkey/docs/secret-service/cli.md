# Secret Service — CLI

> **Status: NORMATIVE** · Feature: `secret-service` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

Binary: `xkey`, verb `secret-service` (`xkey/cmd/xkey/cmd/secret_service.go`).
Requires an already-initialized barrier — run `xkey barrier init` first (see
[`../seal/cli.md`](../seal/cli.md)); this command never initializes one.

## `xkey secret-service`

Runs the daemon in the foreground until `SIGINT`/`SIGTERM`, then shuts down
cleanly (releases the D-Bus name, closes every session). There is no
separate `stop`/`status` pair: the daemon owns no shared state a second
process needs to inspect, the same shape as `xkey extension serve`.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--bus` | string | `session` | D-Bus bus to own `org.freedesktop.secrets` on: `session` or `system` |
| `--data-dir` | string | `~/.xkey/data` | Barrier storage directory (same resolution as `xkey barrier`) |
| `--strategy` | string | the strategy the barrier was initialized with | Barrier seal strategy override: `software`, `tpm2`, `pkcs11` |
| `--tpm-device` | string | `$TPM_DEVICE_PATH` or `/dev/tpmrm0` | TPM device path, with `--strategy tpm2` |
| `--tpm-simulator` | bool | `false` | Use the in-process TPM simulator (simulator builds only) |
| `--barrier-password-stdin` | bool | `false` | Read the barrier password from standard input; used both at startup and to resolve every later `Unlock` prompt |
| `--barrier-password-file` | string | — | Path to a file containing the barrier password |

Password resolution order (identical to `xkey barrier unseal`):
`--barrier-password-stdin`, then `--barrier-password-file`, then
`XKEY_BARRIER_PASSWORD`, then — only when a client's `Unlock` opens a
`Prompt` and the process has a controlling terminal — an interactive
`term.ReadPassword` prompt.

```
# Run on the session bus, unsealing interactively on first client Unlock
xkey secret-service

# Run with the barrier already unsealed at startup (piped password;
# XKEY_BARRIER_PASSWORD works the same way)
xkey secret-service --barrier-password-file /dev/stdin <<< "mypassword"

# Run on the system bus (requires a matching D-Bus policy file installed
# separately — this command does not install one)
xkey secret-service --bus system

# Point at a non-default barrier data directory
xkey secret-service --data-dir /secure/xkey
```

Startup output:

```
Secret Service daemon started
  Bus:    session
  Name:   org.freedesktop.secrets
  Sealed: false
```

`Sealed: true` at startup is not an error — no password was configured up
front, or it was wrong (a warning is logged, not fatal); every collection
then reports `Locked` until a client's `Unlock` round-trip succeeds.

## Verifying it is running

Any Secret Service client works, for example:

```
# GNOME/freedesktop secret-tool (see the integration test for the full
# store/lookup/clear round trip this exercises)
secret-tool store --label="My token" service myservice username me
secret-tool lookup service myservice username me

# git's libsecret credential helper
git config --global credential.helper libsecret
git push   # prompts once, then reuses the stored credential
```

Both require a session bus reachable at `$DBUS_SESSION_BUS_ADDRESS` — true
on any normal desktop session; use `dbus-run-session -- xkey secret-service`
to test under a private bus (see `make integration-test-secretservice`).
