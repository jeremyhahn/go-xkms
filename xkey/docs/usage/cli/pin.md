# CLI Reference: PIN Commands

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl pin`, the go-xkms server CLI (`cmd/xkmsctl/pin.go`); the normative reference is [`docs/pin-management/cli.md`](../../../../docs/pin-management/cli.md).

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl pin`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons. For the xkey command tree
> see [the xkey CLI reference](README.md).

The `pin` command group manages the Security Officer (SO) PIN and the user PIN
on an xkmsd server. The SO PIN authorizes privileged operations: setting the
user PIN and resetting the lockout counter. The user PIN authorizes day-to-day
operations. Every subcommand connects to the server named by the global
`--server` flag (`cmd/xkmsctl/pin.go:298`).

```
xkmsctl pin
├── so-set          # Set the SO PIN
├── so-change       # Change the SO PIN
├── so-verify       # Verify the SO PIN
├── user-set        # Set the user PIN (SO authorization)
├── user-change     # Change the user PIN
├── user-verify     # Verify the user PIN
├── lockout         # Show PIN lockout status
└── lockout-reset   # Reset the lockout counter (SO authorization)
```

## Supplying PINs

Every PIN flag resolves the same way (`cmd/xkmsctl/prompt.go:57`):

1. A value other than `-` is used as given. It is then visible in the process
   list.
2. `-` reads all of stdin, with the trailing newline trimmed.
3. An omitted flag prompts on stderr without echo when stdin is a terminal,
   and otherwise reads one line from stdin.

An empty PIN is refused (`cmd/xkmsctl/prompt.go:93`). Flags are defined at
`cmd/xkmsctl/pin.go:500` onward.

## Commands

### pin so-set

Sets the SO PIN. When an SO PIN is already set, `--current-pin` must match it.

| Flag | Description |
|------|-------------|
| `--current-pin` | Current SO PIN; required only when one is already set |
| `--new-pin` | New SO PIN |

```bash
xkmsctl pin so-set
```

### pin so-change

| Flag | Description |
|------|-------------|
| `--current-pin` | Current SO PIN |
| `--new-pin` | New SO PIN |

### pin so-verify and pin user-verify

Check a PIN. The only flag is `--pin`.

```bash
printf '%s' "$SO_PIN" | xkmsctl pin so-verify --pin -
xkmsctl pin user-verify
```

### pin user-set

Sets the user PIN under SO authorization.

| Flag | Description |
|------|-------------|
| `--so-pin` | SO PIN authorizing the operation |
| `--new-pin` | New user PIN |

```bash
xkmsctl pin user-set
```

### pin user-change

| Flag | Description |
|------|-------------|
| `--current-pin` | Current user PIN |
| `--new-pin` | New user PIN |

### pin lockout

Shows the failed attempts, the maximum attempts and whether the PIN is locked,
plus the lock expiry and the seconds until recovery when they apply
(`cmd/xkmsctl/pin.go:439`). Takes the global `-o json`.

```bash
xkmsctl pin lockout
```

```
PIN Lockout Status:
  Failed Attempts: 0
  Max Attempts:    <server limit>
  Locked:          false
```

### pin lockout-reset

Resets the lockout counter under SO authorization. The only flag is `--so-pin`.

```bash
xkmsctl pin lockout-reset
```

## Workflows

### Initial setup

```bash
xkmsctl pin so-set        # prompts for the new SO PIN
xkmsctl pin user-set      # prompts for the SO PIN, then the new user PIN
xkmsctl pin so-verify
xkmsctl pin user-verify
```

### Lockout recovery

```bash
xkmsctl pin lockout          # Locked: true, Recovery In: ...
xkmsctl pin lockout-reset    # or wait for the lockout to expire
```

The lockout policy (attempt limit, duration, backoff) is the server's; see
[PIN management engineering](../../../../docs/pin-management/engineering.md).

## `xkey --unified-pin` (out of scope for this page)

`--unified-pin` is an `xkey fido2` flag, not part of `xkmsctl pin`. It
propagates the xkey host PIN service's user PIN to the virtual FIDO2
authenticator's own CTAP2 PIN; see
[`../../virtual-authenticator/cli.md`](../../virtual-authenticator/cli.md).

## See Also

- [PIN management](../../../../docs/pin-management/user.md) — the normative feature folder
- [Configuration Reference](../../configuration/README.md)
