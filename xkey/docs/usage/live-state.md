# Live device state vs on-disk state

`xkey pin status`, `xkey barrier status`, `xkey password list` and
`xkey password status` report the state of a *device*, not of a directory.
Which of the two they read is the difference between a true and a false
answer, so they name their source in every invocation.

## The rule

| The command talks about | It asks |
|---|---|
| Live device state — PIN configuration, barrier seal state, the password store | The running daemon over its IPC socket |
| Files — `cert export`, `config path`, the on-disk trust store | The filesystem, unchanged |

A live-state command prefers the daemon, falls back to the on-disk data
directory when no daemon is running, and **labels which answered**:

```
$ xkey barrier status
Barrier Status:
  Initialized:      Yes
  State:            Unsealed
  Strategy:         tpm2
  Hardware-backed:  Yes

Source: daemon (/run/user/1000/xkey/xkey.sock)
```

```
$ xkey barrier status          # with no daemon running
Barrier Status: Not Initialized
  Data directory:  /home/u/.xkey

Run 'xkey barrier init' to initialize the barrier.

Source: data directory (/home/u/.xkey) — no daemon running
```

The label is not decoration. `State: Sealed` read from a cold data directory
and `State: Sealed` read from a live daemon are different facts: the first
only means "this process has not unsealed anything". Rendering them
identically is what made a configured, unsealed device report itself as
unconfigured and sealed.

`--json` carries the same information in the `source`, `source_location` and
`source_reason` fields.

## Flags

Every live-state command accepts:

| Flag | Meaning |
|---|---|
| `--socket` | The daemon's IPC socket. Defaults to the same auto-detected path `xkey fido2 status` uses: `$XDG_RUNTIME_DIR/xkey/xkey.sock`, else `/tmp/xkey-$UID/xkey.sock`. |
| `--source` | `auto` (default: daemon, then disk), `daemon` (fail if the daemon cannot answer), `disk` (read the data directory, ignoring any daemon). `xkey password status` also accepts `xkmsd`. |

`--source daemon` never falls back. An operator who asked the daemon and got
the data directory's answer instead is exactly the failure this design
removes, so the command fails and names the socket and the reason.

A daemon that is running but cannot answer — the foreground `xkey fido2`
daemon and the extension host do not own PIN or barrier state — is treated
as a fallback, labelled `daemon does not report this state`. A daemon that is
running and *fails* is not: the error is reported rather than replaced with a
stale on-disk answer.

## Where the password store lives

One story: the store belongs to whoever holds the barrier.

- A running daemon holds it. `password list` and `password status` both ask
  the daemon first.
- With no daemon, the store is the on-disk directory named by `--store`.
  Both commands read it, and both say so.
- A remote `xkmsd` server owns the *session* verbs — `password unlock`,
  `password lock`, `password access-mode` — and the access mode they
  configure. It is not where the local store lives, so it is consulted only
  when asked for: `xkey password status --source xkmsd`.

Before this, `password status` demanded `--xkmsd-url` while `password list`
needed none and silently returned empty. They now agree about reachability.

## What the socket will not do

The IPC socket is `srw-------`, owned by the user. **Filesystem permission is
its only authentication**, so every verb on it is reachable by any process
running as that user. The live-state verbs are therefore *descriptive only*:

- Reporting **that** a PIN is set is fine. There is no verb that returns a
  PIN value, and adding one would convert any local process into a
  credential-exfiltration path.
- `password list` over IPC returns metadata — name, title, username, URL,
  folder, timestamps — and never a password value. The wire type
  (`ipc.PasswordEntryInfo`) has no field that could carry one.
- `xkey password list --show-passwords` therefore requires `--source disk`,
  which reads the store directly and needs the barrier. The command says so
  rather than silently masking.
