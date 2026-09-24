# SSH

go-xkms provides a complete SSH key, host-key, and authorized-key subsystem
that generates keys on **any configured crypto backend** — software, TPM 2.0,
PKCS#11/HSM, cloud KMS, or a remote xkms server. For hardware backends the
private key never leaves the device; SSH signing is delegated to the backend.

## Architecture

| Layer | Location | Purpose |
|-------|----------|---------|
| Core | `pkg/ssh/{keys,known_hosts,authorized,session}` | Key lifecycle, host-key pinning, authorized_keys, outbound sessions |
| Backend bridge | `pkg/ssh/backend` | Generates/signs SSH keys on an `xkms` crypto backend via `types.KeyProvider` |
| SDK | `sdk/go/client/ssh` | Transport-agnostic `Client` (embedded, REST, gRPC, QUIC, MCP, unix) |
| REST/gRPC/QUIC/MCP/unix | `pkg/api/{rest,grpc,quic,mcp,unix}` | Server-side SSH endpoints over every protocol |
| CLI | `xkey ssh …`, `xkmsctl ssh …` | Multi-protocol command surface |
| GUI | xkey **SSH** page | Generate/list/export/delete with a backend selector |

### Backend-native keys

An SSH key is either:

- **Software** — an ed25519/RSA/ECDSA key whose OpenSSH PEM is sealed in a
  `secure.Secret` (the historical default), or
- **Backend-backed** — a key whose private half lives in a crypto backend
  (`Key.BackendID` / `Key.BackendKeyID` set, `Material == nil`). The public SSH
  key is derived from the backend public key; `Key.BackendSigner` resolves a
  `crypto.Signer` from the backend and wraps it with `ssh.NewSignerFromSigner`.

The stored envelope is versioned (`v2`); v1 software envelopes still load.
Backend-backed generation is enabled by passing a `BackendProvider`
(`sdk/go/client/ssh.NewBackendProvider`) to the embedded client, or by setting
`GenerateRequest.Backend`.

### Transport selection

`ssh.NewClientForServer(server, tlsCA, token)` dispatches by URL scheme:

| Scheme | Transport |
|--------|-----------|
| `http(s)://` | REST |
| `grpc(s)://` | gRPC (`grpcs` = TLS) |
| `unix://<path>` | gRPC over a Unix domain socket |
| `quic://` | HTTP/3 (dials the REST port -- there is no separate QUIC port) |
| `mcp(s)://` | MCP JSON-RPC (`mcps` = TLS) |

The server mounts SSH over every transport when an SSH client is wired
(`pkg/server` builds one embedded client with a backend provider over the
`XKMSService` and injects it into all transports).

### `SessionClient.Dial` — non-interactive outbound sessions, every transport

`Client.Session().Dial` (`Run` a command, get stdout/stderr/error back) is
distinct from `Client.Console` (an interactive PTY byte stream) and is
supported over **every** transport, including the network ones that refuse
Console: embedded, REST, QUIC, gRPC, unix, and MCP. The SSH connection to the
caller-chosen target host is always dialed directly from the calling
process (`golang.org/x/crypto/ssh`) — the xkms transport itself carries only
two RPCs, `Keys().Signer` (a forward-signing proxy; the private key never
leaves xkmsd) and `KnownHosts().Callback` (host-key verification against the
server's pins), neither of which needs a byte stream. That is why MCP's
request/response JSON-RPC framing, which cannot carry Console, has no
trouble with Dial. Host-key verification fails closed on every transport: an
unrecognized or mismatched host key is a typed error
(`*sdkssh.NotFoundError` / `*sdkssh.MismatchError` on every transport; see
Errors below) — there is no `InsecureIgnoreHostKey` path
anywhere in the SDK.

## Errors

A missing key, a re-pinned host or authorized entry, and a known_hosts
host-key mismatch (a MITM indicator) report the same class of failure on
every transport, driven by one shared table in
`sdk/go/client/ssh` (`classify`, consumed by `HTTPStatusForError`,
`GRPCCodeForError`, and `JSONRPCCodeForError`) so REST, gRPC, and MCP never
drift from each other:

| Store error | REST | gRPC | MCP (JSON-RPC) |
|---|---|---|---|
| `*pkgkeys.KeyNotFoundError`, `*pkgknownhosts.NotFoundError`, `*pkgauthorized.NotFoundError` | 404 | `NotFound` | -32001 |
| `*pkgknownhosts.DuplicateError`, `*pkgauthorized.DuplicateError` (Add called twice without a Remove) | 409 | `AlreadyExists` | -32005 |
| `*pkgknownhosts.MismatchError` (presented host key does not match the pin) | 409 | `FailedPrecondition` | -32006 |
| validation errors (`*InvalidScopeError`, `*InvalidAlgorithmError`, `*pkgkeys.InvalidKeySizeError`, …) | 400 | `InvalidArgument` | -32602 (Invalid params) |
| `*NotImplementedError` (a method the server does not serve) | 501 | `Unimplemented` | -32601 (Method not found) |
| `*BackendUnavailableError` (no `BackendProvider` wired for the requested backend) | — (falls to 500) | `FailedPrecondition` | — (falls to Internal) |
| anything else | 500 | `Internal` | -32603 (Internal error) |

REST and MCP report `DuplicateError` and `MismatchError` as the same status
(409 / -32005 and -32006 are still distinct on MCP, since JSON-RPC's
implementation-defined range has room to keep them apart even though HTTP's
409 does not). An unrecognized error is never echoed onto the gRPC status
message verbatim — only the table above's recognized classes carry their own
message; everything else answers a fixed `"ssh: internal error"` so a
storage-backend detail (a filesystem path, a driver error) never reaches an
RPC caller.

## CLI

```bash
# Local, on the admin-selected default backend (embedded store)
xkey ssh keys generate --name laptop --type ed25519

# On a specific local backend
xkey ssh keys generate --name laptop --type ecdsa-p256 --backend tpm2

# Against a remote xkmsd over any protocol
xkey ssh keys generate --server grpcs://host:9443 --tls-ca ca.crt --name k --backend tpm2
xkey ssh keys list   --server quic://host:8443   --tls-ca ca.crt
xkey ssh keys export --server unix:///run/xkms/xkms.sock --name k

# xkmsctl mirrors the surface for multi-protocol parity testing
xkmsctl --server mcp://host:8445 ssh keys list

# xkmsctl also covers key import and the pin / authorized-key stores
xkmsctl ssh keys import --file ~/.ssh/id_ed25519 --name laptop
xkmsctl ssh known-hosts add --host git.example.com --key "ssh-ed25519 AAAA..."
xkmsctl ssh known-hosts verify --host git.example.com --file host.pub
xkmsctl ssh authorized-keys add --name ci-runner --line "ssh-ed25519 AAAA..."
xkmsctl ssh authorized-keys emit --line "ssh-ed25519 AAAA..." --option no-pty
xkmsctl ssh authorized-keys verify --key "ssh-ed25519 AAAA..."

# Local system SSH integration (read-only, xkey only — see below)
xkey ssh local hosts                                    # ssh_config(5) Host aliases
xkey ssh local keys                                     # agent + ~/.ssh identities
xkey ssh connect --local --ssh-config-alias prod-bastion # plain passthrough `ssh`
```

`xkmsctl ssh` honors the global `--transport` / `--server` / `--tls-ca` flags.
Every subcommand except `authorized-keys emit` (a pure formatting helper) is
addressed by `--scope` / `--owner`. `keys import` reads an encrypted PEM's
passphrase without echo from the terminal, or from stdin when the CLI is not
attached to one; the plaintext is read straight into an enclaved buffer.
`known-hosts add`, `known-hosts verify`, and `authorized-keys verify` all take
the public key as an `authorized_keys`-format line via `--key`, or read it
from a file via `--file` — a pin can no longer be created from a fingerprint
alone (see the note under "Host-key pin storage" below).

## GUI

SSH keys are **backend-bound, first-class platform keys**. An SSH key is a
signing key (ed25519 / RSA / ECDSA) created on the chosen crypto backend
(`software` / `tpm2` / `pkcs11` / cloud / remote xkms) — for hardware backends
the private half never leaves the device. The backend key's CN is
`ssh-<scope>-<owner>-<name>` (surfaced as the SSH key's `backend_key_id`).

- **Keys page** — the unified, canonical key list. **Generate SSH Key** mints a
  backend-bound SSH key (one shared dialog, the single generation path). SSH keys
  appear in the list badged **SSH**; the raw backend signing key that backs them
  is de-duplicated away (matched on `backend` + `backend_key_id`) so each key
  shows once. SSH-row actions: copy public key, delete.
- **SSH application** — a connection manager with two tabs:
  - **Profiles** (default) — host profiles in a folder tree (host/port/user + the
    SSH key to use, shown with its backend badge) and a prominent **Connect**
    (embedded console or system terminal).
  - **Keys** — a filtered projection of the same SSH key store (backend-chip
    filtered), generating through the same shared dialog.

Both the Keys page and the SSH Keys tab share one SSH key service
(`pkg/ssh/keys` + `pkg/ssh/backend`), store, and generation dialog — there is no
parallel store or generator. Backend selection uses the `signing` capability.

## Testing

- Unit: `make test-ssh` (`pkg/ssh`), `go test -tags codec_json ./xkey/pkg/gui/services/ -run SSH`,
  SDK + gRPC service SSH tests. The embedded console is covered end-to-end by
  `pkg/ssh/console` (in-process echo-PTY server) and the WebSocket bridge
  (`NewWSHandler`), both exercised on the client side.
- Integration (devcontainer):
  - `make integration-test-api-ssh` — drives the **xkey** CLI against a
    dockerized xkmsd over embedded/REST/gRPC/QUIC/MCP/unix, running the common
    command set (generate → list → export → delete) and a backend-selection check.
  - `make integration-test-ssh-backends` — confirms SSH key
    **generate → derive public key → sign → verify** on **every backend**:
    software, TPM 2.0 (in-process simulator), PKCS#11 (SoftHSM2), and cloud KMS
    (AWS via Floci with real verifiable signatures; GCP + Azure via
    self-consistent in-memory-ECDSA mocks). ECDSA-P256 is the cross-cloud default;
    the suite also asserts ed25519 is correctly rejected on every cloud backend
    (no cloud KMS supports it). `make integration-test-ssh-backends-cloud-real`
    runs the same matrix against LIVE AWS/GCP/Azure (opt-in, credential-gated).
    Note: Azure Key Vault returns ECDSA signatures as IEEE-P1363 `r‖s`; the
    azurekv backend now normalizes these to ASN.1 DER so an Azure key works as a
    `crypto.Signer`/SSH key.
  - `cd xkey && make integration-test-ssh` — the xkey CLI SSH surface
    (`keys`/`host-keys`/`authorized-keys`) plus the **embedded console**
    (`ssh_console_test.go`): `xkey ssh console` over the embedded SDK against an
    in-process echo SSH server, covering the byte-stream round-trip (user@host and
    saved profile), MITM-safe host-key rejection (no trust-on-first-use), and the
    missing-key error path.
- GUI (Playwright): `xkey/frontend/tests/e2e/ssh.spec.ts` covers the SSH view,
  key dialogs, connections/profiles, and the **console mode** matrix (settings/
  profile/connect selectors, embedded-panel open/close, global-default resolution
  + persistence). Run it yourself:

  ```bash
  cd xkey/frontend
  npx playwright test ssh.spec.ts                       # Vite UI-only (auto-starts dev server on :5199)
  npx playwright test ssh.spec.ts -g "Console Mode"     # just the console-mode tests
  BASE_URL=http://localhost:34115 npx playwright test ssh.spec.ts  # live Wails backend (run `make dev-browser-e2e` first)
  ```

  The no-`BASE_URL` form above auto-starts the Vite dev server on `:5199` and is
  the simplest way to run locally. Wails-only specs `test.skip` themselves in
  Vite mode; the full live path runs in the devcontainer via
  `cd xkey && make playwright-test`.

## Connections & profiles

The xkey **SSH** application (under *Applications*) has two tabs:

- **Keys** — generate/list/export/delete keys on any backend (chip-filtered by
  backend, consistent with the rest of the app).
- **Connections** — saved **host profiles** in a folder hierarchy (mirroring the
  password manager) plus one-time connections.

### Choosing a key — the searchable key picker

The New Connection and Profile dialogs share one **searchable key dropdown**
(`SSHKeySelect.svelte`) listing every authentication option in two groups:

- **xKey keys** — keys from the unified SSH store, on any configured backend
  (software / tpm2 / pkcs11 / cloud / remote), labeled with algorithm and
  backend.
- **Local keys** — the operator's own identities: every key the system
  ssh-agent holds plus `~/.ssh` identity files (read-only discovery via
  `pkg/ssh/local`).

Type to filter by name, comment, fingerprint, path, backend, or algorithm —
built for machines with many keys. The first entry is always **No key
(agent / password auth)**.

The selection maps to `SSHConnectParams` / `Profile` fields: an xkey key sets
`key_name`; a local key sets `key_source: "local"` plus `local_identity` (an
identity file path, or `agent:<SHA256-fingerprint>` for an agent-held key);
"No key" leaves all of them empty.

- **System terminal** — a local key runs a passthrough `ssh` (`-i <path>` for
  a file identity; agent keys need no flag). **No key** also runs passthrough
  `ssh`, so the system agent or an interactive password prompt authenticates,
  exactly like typing `ssh user@host`.
- **Embedded console** — a local key resolves its signer via the system agent
  (required for hardware-backed `sk-` keys) or the identity file. **No key**
  offers every discovered local identity in order, OpenSSH-style
  (multi-signer public-key auth). Signer resolution happens at open time, so
  a bad key reference surfaces as a dialog error, not a dead console panel.

### Launching a connection

xkey serves the chosen key to the system `ssh` client over an **in-process SSH
agent** (`pkg/ssh/agent`), so hardware-backed keys authenticate without ever
exporting private material (`IdentitiesOnly=yes` advertises exactly the chosen
identity). The flow (`pkg/ssh/connect`):

1. start the agent on a temp socket serving the key's `gossh.Signer`;
2. seed a temp `known_hosts` from xkey's pins (matched hosts verify silently);
3. spawn the platform terminal running `ssh -o UserKnownHostsFile=<temp> ...`
   with `SSH_AUTH_SOCK` set — the native client shows the classic console
   first-contact prompt for unknown hosts;
4. sync newly-accepted host keys back into the pin store.

The GUI launches a terminal window; the CLI runs `ssh` inline in the current
terminal.

### Agent-only sessions — signing with no host

Step 1 above is useful on its own: plenty of tools speak the ssh-agent protocol
without ever dialing a host (`git commit -S` under `gpg.format=ssh`,
`ssh-keygen -Y sign`, `age`), and `xkmsssh.StartAgent` serves an xkms-held key
over an ephemeral socket with no connection target. `pkg/ssh/connect` is a
consumer of that session, adding the host semantics described above.

**That capability is documented in [`../ssh-agent-sessions/`](../ssh-agent-sessions/),
which is NORMATIVE for it — this file is not.** Start with
[`user.md`](../ssh-agent-sessions/user.md) for the worked git-signing example,
[`architecture.md`](../ssh-agent-sessions/architecture.md) for why it is
hostless, and [`engineering.md`](../ssh-agent-sessions/engineering.md) for the
lifetime contract and invariants.

### Console mode: system terminal vs embedded

A connection opens either in the **system terminal** (the OS terminal, via the
SSH agent — see above) or in an **embedded in-app console** (an xterm.js terminal
inside the UI). The mode is chosen per connection, saved on the profile
(`Profile.ConsoleMode`), and falls back to a global default (Settings → SSH →
*Default console mode*).

### Embedded console tabs (multiple sessions)

The embedded console panel manages **multiple simultaneous sessions as
tabs**, like a system terminal. Each embedded connection (one-time, profile,
or ssh_config host) opens its own tab; the tab strip shows the target
(`user@host`), a live/ended status dot, a per-tab close, and a `+` button
that opens the New Connection dialog. Inactive tabs stay mounted — their
WebSocket and SSH session keep running in the background, scrollback intact.

- Each session is an independent one-time ticket on the loopback console
  server; the backend (`SSHConsoleService`) serves any number concurrently.
  Abandoned tickets (issued but never connected) are purged after 2 minutes.
- When a session ends (remote exit, network drop), the tab dims and a
  **Reconnect** action re-opens the same target in place — a fresh ticket
  from the tab's remembered origin (params, profile, or alias). The host is
  already pinned, so reconnects are prompt-free.
- The panel's close button closes every session; closing the last tab
  hides the panel.

#### Persistent sessions (opt-in)

Sessions are **memory-only by default**: they live while the SSH view is
open and vanish on navigation, reload, or restart. A session specifically
started with **Persistent session** enabled (a checkbox in the New
Connection dialog for embedded mode, or the *Persistent console session*
profile option / `xkey ssh profile add --persist-session`) is additionally
recorded in the shared SSH store (`pkg/ssh/sessions`, barrier-routed —
title + reconnect origin only, never key material or connection state).
Persisted tabs are restored **disconnected** the next time the SSH view
loads — after navigation, a reload, or a full app restart — with Reconnect
one click away; nothing ever auto-dials SSH at startup. Closing a persisted
tab (or the whole panel) deletes its record. CLI parity:
`xkey ssh sessions list|rm`.

### Embedded console — a client-side capability

The embedded console is an xkms library capability (`pkg/ssh/console`) that runs
**in the client's own process**. The SSH session is established by whoever holds
the terminal — xkey's CLI and desktop app — never by xkmsd.

| Transport | Mechanism |
|-----------|-----------|
| embedded | in-process PTY (`OpenConsole` / `Client.Console`) |
| gRPC, unix, REST, QUIC, MCP | unsupported (`ConsoleUnsupportedError`) |

xkmsd serves **no** console endpoint. It is a key vault, a CA, and a network
appliance for storing and serving keys; terminating SSH there would let any
authenticated caller make the appliance dial an arbitrary host and proxy an
interactive shell through it — server-side request forgery, a network pivot,
and remote code execution against the target, from the one host that must offer
none of them. A remotely stored key still drives a local session: the client
resolves a `Signer` through `Keys().Signer`, which sends each authentication
challenge to the server to be signed, so the private key never leaves the
vault. Add xkms as an xkey backend and `xkey ssh console` works against it.

The console reuses the same key signer (software **or** hardware-backed) and
host-key verification — for hardware keys the private key never leaves the
device. `pkg/ssh/console.Open` requests a PTY, wires stdin/stdout pipes, and
exposes `Resize(rows, cols)`; `Console.Read`/`Write` are the terminal stream.

#### Shutdown: `CloseWrite` (half) vs `Close` (full)

`Console` separates the two shutdowns the way `net.TCPConn` does, and every
transport's `ConsoleSession` implements both:

| Call | Effect |
|------|--------|
| `CloseWrite()` | **Half close.** Sends an SSH channel EOF so the remote command's stdin reports EOF (what `xkey ssh console host < script` needs); the session stays readable so trailing output still arrives. Idempotent; later `Write`s return `*WriteClosedError`. |
| `Close()` | **Full teardown.** Closes the session (and, for a `Dial`ed console, the connection), releasing any `Read`/`Write` in flight. Idempotent; every later operation returns `*ClosedError`. |

`Close` never sends the EOF and never blocks on a write: closing the stdin pipe
reaches `ssh.(*channel).CloseWrite()`, which mutates the channel's EOF flag
without synchronizing against an in-flight `WriteExtended` — a GUI "disconnect"
racing the keystroke pump was a real data race, and serializing `Write` behind
the same lock as `Close` would have turned it into a hang whenever the remote
stopped reading.

`Read`, `Write`, `Resize` and `Close` are safe to call concurrently.
`CloseWrite` must be sequenced after the caller's final `Write` — it is the
"no more input" signal, so by definition no write is outstanding.

Transport specifics: over the WebSocket bridge, the end of the client's input
stream triggers `CloseWrite` before the deferred `Close`.

**Wire protocol** (WebSocket): binary frames carry terminal bytes (stdin one
way, stdout the other); text frames are JSON control —
`{"type":"resize","rows":R,"cols":C}` (client→server) and
`{"type":"error"|"exit",...}` (server→client).

**Frontend client**: the framework-agnostic `SSHConsoleClient` on the
**`@go-xkms/sdk/ssh-console`** subpath wraps xterm.js + this protocol; xkey
(Svelte) and other web UIs wrap it in their own component. It lives on a subpath
rather than the package root so consumers that only talk to the REST API do not
pull xterm into their bundle. The bridge it connects to is the xkey desktop
app's token-gated loopback WebSocket — the only place this protocol is served.

```bash
# CLI: interactive console in the current terminal (in-process, SDK Console)
xkey ssh console prod-web
xkey ssh console deploy@web1 --key laptop
```

### Host-key trust (TOFU)

The embedded console's WebSocket protocol includes a host-key confirmation
round trip, gated by `ConsoleTarget.HostKeyPolicy` (`sdk/go/client/ssh`):

| Policy | Behavior |
|--------|----------|
| `""` / `"yes"` (strict) | No prompt — the dial fails immediately on an unpinned host. |
| `"ask"` | Server sends a `"confirm"` frame and blocks (default 60s, override with `WithConsoleHostKeyConfirmTimeout`) for the client's accept/reject reply. The embedded console renders an interactive Accept/Reject prompt. |
| `"accept-new"` | Server auto-accepts and sends an informational `"notify"` frame — no round trip, never blocks. |

At the SDK level an empty policy is strict; xkey's console service defaults
to **`"ask"`** (matching the system-terminal path and the Settings page) so
a fresh install's first connection raises the fingerprint prompt instead of
hard-failing against an empty pin store. The Settings → SSH policies are
persisted and re-applied at app startup.

A **changed** (mismatched, already-pinned) host key always fails the dial,
regardless of policy.

**Wire frames** (WebSocket TEXT, JSON):

```jsonc
// server → client
{"type":"hostkey","host":"web1:22","key_type":"ssh-ed25519","fingerprint":"SHA256:...","known":false,"mode":"confirm"}
// client → server — only for "confirm" mode
{"type":"hostkey-response","accept":true}
```

`ConsoleTarget.KnownHostsExtraFiles` / `KnownHostsSkipStore` extend the same
store policy below to the embedded console, so Settings → SSH governs both
console modes identically.

### Host-key store policy (Settings → SSH)

- **Barrier** (default) — pins live only in xkey's encrypted store.
- **System** — uses `~/.ssh/known_hosts`.
- **Both** — seeds from and mirrors accepted keys to both.

This policy applies to both the system-terminal path (`--known-hosts-policy`)
and the embedded console (`ConsoleTarget.KnownHostsExtraFiles` /
`KnownHostsSkipStore`, above).

Host pins carry the full host public key (`known_hosts` envelope v2) so they
can be emitted as OpenSSH `known_hosts` lines and matched byte-for-byte rather
than by fingerprint alone. **BREAKING:** a pin created before envelope v2
(fingerprint-only, v1) is no longer trusted — `Get` and `Verify` fail closed
with a typed error naming the host that must be re-pinned, and `List` skips
it rather than aborting the scan.

### Profiles

`pkg/ssh/profile` stores `Profile{Name, FolderPath, Host, Port, User,
KeyScope/KeyOwner/KeyName, Options, Notes}` in a barrier-routed backend under
`ssh/profiles/` (folder model identical to `pkg/staticpw`). A profile references
a key — never key material.

```bash
xkey ssh profile add --name prod-web --folder work/prod --host web1 --port 2222 --user deploy --key laptop
xkey ssh profile list --folder work
xkey ssh connect prod-web                 # saved profile
xkey ssh connect deploy@web1 --key laptop # one-time
xkey ssh connect prod-web --known-hosts-policy both

# A local-passthrough profile (authenticates via ssh_config/ssh-agent, not an xkey key)
xkey ssh profile add --name bastion --host bastion.example.com --key-source local
xkey ssh profile add --name bastion2 --ssh-config-alias prod-bastion # implies --key-source local

# Pin one specific local key (mirrors the GUI key picker's Local group)
xkey ssh connect deploy@web1 --identity ~/.ssh/id_ed25519       # file identity → ssh -i
xkey ssh connect deploy@web1 --identity agent:SHA256:pNYoqv...  # agent-held key (e.g. sk-)
xkey ssh profile add --name web1 --host web1 --user deploy --identity ~/.ssh/id_ed25519

# No key at all → plain passthrough ssh (system agent / password prompt)
xkey ssh connect deploy@web1
```

## Local system SSH integration

`pkg/ssh/local` (re-exported via `sdk/go/client/ssh`) gives xkey a **read-only**
view of the operator's existing OpenSSH setup — hosts and keys already
configured outside xkey never need to be migrated in, and xkey never writes
`~/.ssh/config` or `/etc/ssh/ssh_config`.

| Function | Purpose |
|----------|---------|
| `LoadLocalSSHConfig(paths...)` | Parses `~/.ssh/config` + `/etc/ssh/ssh_config`: `Host` aliases, `HostName`/`User`/`Port`/`IdentityFile`/`IdentityAgent`, `Include`, and `%h`/`%d`/`%r`/`%p` tokens. A missing file is treated as an empty config. |
| `DefaultLocalSSHConfigPaths()` | The standard OpenSSH client config paths, in priority order. |
| `DiscoverLocalIdentities(host, homeDir)` | ssh_config `IdentityFile` entries first, then the default identity set (`id_rsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`) under `homeDir/.ssh`, deduplicated by path. |
| `ResolveLocalSigner(ctx, identity, authSockPath)` | Signs via the system agent (`$SSH_AUTH_SOCK`) first — required for FIDO2 `sk-` keys — falling back to parsing an unencrypted identity file. An encrypted file with no matching agent key returns `*PassphraseRequiredError`. |
| `DialLocalAgent(sockPath)` | Connects to the system agent and returns its advertised signers. |

- **GUI** — SSH → **Keys** has an xkey/Local source toggle: a read-only list of
  agent + file keys. **Connections** shows a read-only "From ~/.ssh/config"
  section with **Connect**.
- **CLI** — `xkey ssh local hosts` / `xkey ssh local keys` list what's
  discovered. `xkey ssh connect --local [--ssh-config-alias <alias>]` execs a
  plain passthrough `ssh` — no in-process agent, no `known_hosts` override, so
  the native client honors local config, `ProxyJump`, and everything else it
  already does. Profiles persist this via `--key-source local` +
  `--ssh-config-alias`.

## Backend filter consistency

A single `BackendSelector` (filter chips) and `BackendBadge` are used app-wide;
per-backend colors/icons/labels come from `frontend/src/lib/utils/backends.ts`.
The SSH page, Keys, Seal, and Certificates were migrated off ad-hoc badges/the
old dropdown onto these shared primitives.

## Security notes

- ed25519 and ECDSA are the safe defaults across all backends. RSA over SSH uses
  `rsa-sha2-256/512`; a backend's `crypto.Signer` must honor the hashed-digest
  scheme — gate RSA on backend capability where a backend cannot.
- Host-key trust defaults to MITM-safe (no trust-on-first-use): a pin must
  exist before dial. The embedded console can opt into interactive or
  auto-accept first-contact handling (see [Host-key trust
  (TOFU)](#host-key-trust-tofu)) — a changed key still always fails, regardless
  of policy. Encrypted PEM import over remote transports is not supported (no
  passphrase channel); use the embedded transport or import unencrypted.
