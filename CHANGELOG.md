# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0-alpha] - 2026-08-14

### Changed — BREAKING: network serving is the unified API server; legacy transport stacks removed (Phase 4 complete)
- **The legacy "MCP" line-framed JSON-RPC-over-TCP plane is replaced by the real Model Context Protocol.** The server side is qrdb's Streamable HTTP MCP endpoint (`https://host:mcp_port/mcp`); every xkms JSON-RPC method is an MCP tool (`xkms_<method>` with dots as underscores, one optional `params_json` string argument carrying the params object verbatim). `pkg/api/mcp` retains only the dispatch core (`NewServer` + `InvokeMethod` + the tenant/authorization gates) backing the module's tools; the TCP/UDS listener, wire framing, and the `xkms.subscribe` notification plane are deleted. The MCP client transport (`pkg/api/transport/mcp`) now speaks real MCP (mcp-go Streamable HTTP with mTLS) — its ~120 typed methods and their payloads are unchanged.
- **Enabling any network protocol (`rest`, `grpc`, `quic`, `mcp`) now requires `storage.backend: qrdb` and `tls.enabled: true`** (enforced by config validation): the embedded qrdb node's multi-protocol server takes xkmsd's ports and serves the capability plane through the registered `ServiceModule`. The legacy per-transport network listeners are deleted (`pkg/api/quic` removed wholesale; the in-process gRPC/MCP/REST network listeners in `pkg/server` removed). Local IPC is exempt: the Unix socket still serves in-process for non-qrdb storage, and the desktop loopback engine still serves its injected listener. **QUIC is now HTTP/3 on the REST port** (advertised via `Alt-Svc`); the QUIC client transport dials the REST port. TLS material is operator `cert_file`/`key_file` when configured, otherwise a persisted node-local bootstrap certificate serves from first boot and is replaced in-place by the CA-issued certificate once the CA composes. The embedded web UI registers on the unified server (public prefix routes, lazy SPA binding). The QUIC client's stale legacy dialect was migrated to the shared `/api/v1` forms — including 12 previously broken routes (8 PIV paths missing the `/api` prefix, 4 TCG-CA paths on a removed route family).

### Added
- **Unified API server — full module surface (Phase 3 waves 2+3) + cutover switch (Phase 4)**: The xkms `ServiceModule` now carries all three unified-server surfaces. *HTTP*: the REST surface is table-driven — new `pkg/api/rest/routes.go` (`RouteSpec`/`Routes()`) is the single source for both the legacy chi router and `Module.RegisterHTTP`, which registers every route through qrdb's permission-recording registrar (public → `HandlePublic`, authenticated-session → `identity:gated`, permission routes → `resource:action`), late-binding handlers via `pkg/server.ModuleRESTServer()` (503 while composing, 501 for absent subsystems) with legacy group middleware reapplied per route (`rest.BindRoute`). *MCP*: every xkms JSON-RPC method (including the frost namespace) registers as a real mcp-go tool (`xkms_*`, `params_json` parity argument) dispatched through the new connectionless `mcp.Server.InvokeMethod`, which runs the same tenant + authorization gates as the wire path. *Cutover*: new `server.unified_api` config hands the embedded qrdb node's server xkmsd's REST/gRPC/Unix/MCP ports and stands the corresponding legacy listeners down (QUIC/Noise stay legacy pending a qrdb `RegisterQUIC` hook); the composition-time `XKMSService` publish is now mutex-synchronized. At go-qrdb `v0.3.0-alpha`, module MCP tools remain fail-closed under qrdb auth middleware until qrdb exports a module tool-permission registry hook.

### Changed — BREAKING: cluster/auth-factor proxy planes replaced by the qrdb SDK (unified API server Phase 2)
- **xkmsd no longer ships its own cluster/rebalance proxy surface.** The hand-authored cluster plane (`pkg/xkms/servicer_cluster.go` mutation surface, `pkg/api/rest/handlers_cluster.go`, `pkg/api/grpc/service_cluster.go`, the `Cluster*` proto RPCs, `pkg/auth/permissions_cluster.go`, and the per-transport cluster handler/tests) is deleted; xkmsd hosts go-qrdb's own control plane on the embedded node (`pkg/server/qrdb_control_plane.go`) and `xkmsctl cluster|rebalance|factors` drive the `qrdbsdk.Client` directly. The internal `ClusterLeaderEndpoint` + NotLeader redirect behavior is retained. Wire consumers of the removed `Cluster*` KeystoreService RPCs must move to the qrdb control-plane surface.

### Added
- **Unified API server seam — go-xkms as a qrdb `ServiceModule` (Phase 3 wave 1)**: New `pkg/apimodule.Module` registers the wholesale `KeystoreService` gRPC surface (lazy service binding; `Unavailable` until composition completes) into the embedded qrdb node's multi-protocol server under the module name `xkms`, wired via `qrdbsdk.WithModule` in `pkg/server/qrdb_node.go`. Per-RPC authorization rides `option (qrdb.v1.permission)` annotations on all 143 RPCs (locked by `authz_proto_option_test.go`; unannotated ⇒ default-deny). The stack convention is one module per provider project, named after the project; the module is re-exported through `sdk/go` (`NewServiceModule`, `ServiceModule`, `ServiceModuleName`) so downstream hosts (go-quicbaas, go-trusted-platform) register it without importing `go-xkms/pkg`. Registration is additive: the legacy transport stacks keep serving until the Phase 4 cutover.

### Changed
- **go.work machinery fully removed (dependency-resolution cutover completion)**: Deleted `scripts/gen-gowork.sh`, `.devcontainer/scripts/ensure-gowork.sh`, every sibling bind-mount/`additional_contexts` block, and every `GOWORK=/tmp/go.work` reference across the Makefile, devcontainer, root `Dockerfile`, and all integration Dockerfiles/compose files. Container builds now resolve first-party modules from Gitea tags: runtime lanes get the `GOPRIVATE` + `insteadOf` environment (token from the gitignored `.devcontainer/.env`), image-build-time fetches use an optional `gomodauth` BuildKit secret (staged by `make stage-gomodauth`; never a layer, never build context). First-party pins bumped and exercised workspace-free: go-qrdb `v0.3.0-alpha` (root + `sdk/go`), go-codec `v1.4.0`, go-quicraft `v0.3.1-alpha` — in the root, `sdk/go`, and `xkey` modules.

### Changed
- **Typed-error migration (~6,050 sites)**: Replaced ad-hoc `fmt.Errorf` construction across the entire repository with the house typed-error pattern -- the new `pkg/errs` package (`Message`, `Wrapped`, `Detail`, `Affix`, `Joined`, all `errors.Is`/`errors.As`-transparent via `Unwrap`) plus per-package sentinel and typed errors. Breakdown: xkey 1,573 sites, cmd/ + sdk 785, pkg/ 3,689, with the remainder in tests, integration suites, and examples. Rendered messages are preserved byte-for-byte; wrapped causes keep participating in `errors.Is`/`errors.As` chains.
- **Health/validation adoption onto the qrdb SDK**: xkms now consumes the go-qrdb SDK health-check and configuration-validation surfaces instead of carrying local copies; roughly 2,950 LOC of dead parallel implementation was deleted.
- **SSH SDK TLS dedup**: The SSH client transports now share a single TLS configuration builder in `sdk/go/transport/tls.go`, removing the per-transport duplicated TLS setup.
- **Raft mTLS onto the qrdb SDK boundary**: Inter-node Raft mTLS provisioning now flows through the go-qrdb SDK `WithRaftMTLS` option instead of a local wiring path, keeping the locked SDK boundary intact.
- **Stale go-trusted-ca header sweep**: Rewrote the stale `go-trusted-ca` license/attribution headers left from the CA merge across 652 files to the canonical go-xkms header.
- **Floci replaces LocalStack for AWS KMS emulation**: The `awskms` integration suite and the shared `docker-compose.emulators.yml` now use `floci/floci` (MIT-licensed, ~24ms startup, successor to the sunset LocalStack Community Edition) instead of `localstack/localstack`. Floci is a drop-in on port 4566; the full asymmetric matrix (ECC P-256/P-384/P-521, RSA 2048/3072/4096, RSASSA-PSS, sign/verify/GetPublicKey) was validated against the emulator. `LOCALSTACK_ENDPOINT` is replaced by `FLOCI_ENDPOINT` (`AWS_ENDPOINT_URL` remains the primary override). The Azure Key Vault emulator and HashiCorp Vault services are unchanged — floci-az implements Key Vault secrets only (no `/keys` crypto operations), so it cannot replace the Azure emulator.

### Added
- **Local system SSH integration (xkey as a GUI over your local SSH setup)**: New `pkg/ssh/local` (re-exported via `sdk/go/client/ssh`) parses `~/.ssh/config` + `/etc/ssh/ssh_config` read-only (Host/HostName/User/Port/IdentityFile/IdentityAgent, Include, `%h/%d/%r/%p` tokens), discovers default `~/.ssh` identities (`id_rsa` … `id_ed25519_sk`), and signs through the system SSH agent (`$SSH_AUTH_SOCK`) — the only signing path for FIDO2 `sk-` keys — falling back to parsing unencrypted identity files. xkey's SSH view gains a read-only **Local** key source (agent + file keys) and a **"From ~/.ssh/config"** connections section; connecting to a config host honors the selected console mode (embedded console with agent signing, or system-terminal **passthrough** that runs plain `ssh <alias>` with zero overrides so native ProxyJump/IdentityFile/known_hosts semantics apply). CLI parity: `xkey ssh local hosts|keys`, `xkey ssh connect --local [--ssh-config-alias]`, profile `--key-source`/`--ssh-config-alias`.
- **Embedded SSH console trust-on-first-use (TOFU)**: The WebSocket console protocol gained a host-key confirmation round trip (`{"type":"hostkey",...,"mode":"confirm"|"notify"}` / `{"type":"hostkey-response","accept":bool}`). Host-key policy (`yes`/`ask`/`accept-new`) and known-hosts policy (barrier store / `~/.ssh/known_hosts` / both) now apply to the embedded console exactly as to the system terminal: `ask` shows an in-console Accept/Reject fingerprint prompt (60s server timeout), `accept-new` auto-pins with an informational notice, and a **changed** host key always hard-fails regardless of policy. Implemented via `known_hosts.CallbackWithConfirm` + new `ConsoleTarget.HostKeyPolicy`/`KnownHostsExtraFiles`/`KnownHostsSkipStore` in the SDK; TypeScript SDK `SSHConsoleClient.onHostKey` is fail-closed (no handler ⇒ reject).
- **Searchable SSH key picker (any backend + local keys) in xkey's connect/profile dialogs**: The New Connection and Profile dialogs replace the managed-keys-only `<select>` with one type-to-search combobox (`SSHKeySelect.svelte`) listing **xKey keys** (unified SSH store, any backend, labeled with algorithm + backend) and **Local keys** (every system ssh-agent key plus `~/.ssh` identity files), filtered by name/comment/fingerprint/path/backend — built for machines with many keys. A local selection persists as `key_source: "local"` + a new `local_identity` field (`Profile.LocalIdentity`): an identity file path, or `agent:<SHA256-fingerprint>` for an agent-held key (e.g. FIDO2 `sk-`). System-terminal connects pass a file identity as `ssh -i`; embedded-console connects resolve the pinned signer via the agent/identity file. The shared resolver is `sdk/go/client/ssh.ResolveLocalSigners` (`LocalKeySelector{Identity|Alias|Host}`), consumed identically by the GUI console service and the CLI; multi-signer public-key auth (`session`/`console`/`ConsoleTarget.Signers`, `OpenConsoleWithSigners`) offers every candidate in order, OpenSSH-style. CLI parity: `xkey ssh connect|console --identity <path|agent:fp>` (implies `--local`), `xkey ssh console --local`, profile `--identity`.

- **Opt-in persistent console sessions**: Embedded-console sessions are memory-only by default; a session specifically started with **Persistent session** enabled (New Connection checkbox, the *Persistent console session* profile option, or `xkey ssh profile add --persist-session`) is recorded in the shared barrier-routed SSH store (`pkg/ssh/sessions`, re-exported as `sdk/go/client/ssh.ConsoleSessionStore`) — title + reconnect origin only, never key material or live connection state. Persisted tabs are restored disconnected (Reconnect one click away, never auto-dialing at startup) whenever the SSH view loads: after navigation, a webview reload, or a full app restart; closing a persisted tab deletes its record. CLI parity: `xkey ssh sessions list|rm`. Coverage: store CRUD unit tests, console-service session tests, CLI integration tests proving GUI↔CLI store compatibility, Vite Playwright specs for the opt-in surfaces (default OFF), and live Playwright E2E proving a persisted session survives a reload and reconnects while a default session leaves no record.
- **Tabbed multi-session embedded SSH console**: The embedded console panel now manages multiple simultaneous sessions as tabs, like a system terminal. Every embedded connection (one-time, profile, or ssh_config host) opens its own tab with a `user@host` title, live/ended status dot, and per-tab close; a `+` in the tab strip opens the New Connection dialog. Inactive tabs stay mounted so their WebSocket/SSH sessions keep running with scrollback intact; an ended session's tab offers an in-place **Reconnect** (a fresh one-time ticket minted from the tab's remembered origin — reconnects to a pinned host are prompt-free). Backend hygiene: the console service purges abandoned (issued-but-never-connected) tickets after 2 minutes. Coverage: service-level concurrent-session WS test (`TestSSHConsoleE2E_ConcurrentSessions`) + ticket-TTL test, a concurrent two-process CLI integration test (`TestSSHConsoleConcurrentSessions`), Vite Playwright specs for the tab mechanics, and live Playwright E2E driving two real SSH sessions across tab switches plus the reconnect flow.

### Fixed
- **`ssh/console` Close returned io.EOF on peer-first teardown**: `Console.Close` closes stdin before closing the SSH session; when the remote command exits on that EOF first, `x/crypto/ssh` reports the already-closed channel as `io.EOF`. Close now treats that as a clean close (the session is terminated either way) instead of surfacing a spurious error.
- **Embedded SSH console dead on first contact (strict host-key default + unapplied Settings)**: `SSHConsoleService`'s built-in host-key policy was strict (`"yes"`) while the Settings page *displayed* "ask" without ever applying or persisting it — the value only reached the backend when the dropdown was touched, and reset on every restart. On a fresh install (empty pin store) every first-contact embedded connection therefore hard-failed before the TOFU prompt could appear, while the system terminal worked (its service already defaulted to "ask"). The console service default is now `"ask"` (invalid values also reset to it), and the host-key checking + known-hosts policies are persisted (`localStorage`) and re-applied to both SSH services at app startup, so the backend always enforces what Settings shows. Coverage that proves the console *works* end-to-end: service-level WS tests (`TestSSHConsoleE2E_*` — first-contact prompt/accept/reject, strict-policy regression, no-key agent flow), CLI integration tests (`TestSSHConsoleLocalIdentityFile`, `TestSSHConsoleNoKeyAgentFallback`, updated no-key semantics), and a live Playwright E2E (`SSH Embedded Console — live E2E`) that drives the real GUI against a real SSH server (`xkey/test/e2esupport/sshechod`): key picker → TOFU accept → live terminal echo → pinned reconnect, plus a reject path.
- **SSH connections without a key failed instead of using agent/password auth**: With an empty key store (or "No key" selected) the system-terminal connect tried to resolve a nameless xkey-managed key and failed before any terminal opened, and the embedded console opened a dead panel whose signer failure surfaced only as an opaque WebSocket 403. A key-less connection now behaves like typing `ssh user@host`: the system terminal runs a plain passthrough `ssh` (system agent or interactive password prompt), and the embedded console offers every local agent/identity signer, OpenSSH-style. Embedded-console signer resolution moved from the WebSocket upgrade to `OpenConsole` time, so a bad key reference (missing managed key, unknown agent fingerprint, passphrase-protected identity) surfaces as a real error notification in the dialog instead of a dead console panel; `openConsole`/`connectOneTime` failures now report the underlying reason. Same fallback in the CLI: `xkey ssh connect|console` without `--key` uses local identities instead of erroring.
- **xkey SSH store: wrong location, no encryption, GUI/CLI split**: The GUI opened its SSH store at a CWD-relative `"ssh"` path (ignoring the data directory) and never routed it through the barrier; the CLI used a separate hardcoded `~/.xkey-store/ssh`. Both now share one store via `xkey/pkg/sshstore` — barrier-routed (encrypted at rest, with one-shot migration of legacy plaintext stores to `*.pre-barrier.bak`) when the barrier is active, otherwise an engine store at `<data-dir>/ssh`. SSH wiring moved from `NewApp` into `initializeDataDir` so it no longer races the barrier unseal. First-contact embedded console connections no longer hard-fail with `pin not found` (see TOFU above).
- **Duplicate xterm.js in the xkey bundle**: `sdk/ts` (imported as source) pinned xterm v5 while the frontend shipped v6, so two Terminal implementations could bundle; unified on `@xterm/xterm@^6` + `@xterm/addon-fit@^0.11` with Vite `resolve.alias`/`dedupe` guaranteeing a single copy.
- **Unix gRPC socket server Stop/Start shutdown race**: If `Shutdown` ran while `startUnix` was still inside `unix.GRPCServer.Start` (before the gRPC server was assigned), `Stop` found a nil server, did nothing, and the subsequent `Serve` blocked forever — hanging daemon shutdown until the 30s force-stop and leaking the serving goroutine. `Stop` now records a stopped flag that `Start` checks under the same lock before serving, releasing the listener and socket as a clean shutdown. Regression test: `TestGRPCServer_StopBeforeStart`.

- **Real GCP Cloud KMS emulator lane (floci-gcp)**: The `gcpkms` integration suite now runs `TestGCPKMSEmulator` against `floci/floci-gcp` over genuine gRPC — real, locally verified RSASSA-PKCS1 and ECDSA P-256 signatures, symmetric AES-256-GCM round-trips, and key lifecycle — replacing mock-only coverage for those algorithms. Algorithms floci-gcp does not implement (EC P-384, RSA-PSS) remain covered by the mock and opt-in real-cloud suites. The GCP KMS backend gains an `Insecure` config option (requires a custom `Endpoint`; plaintext unauthenticated gRPC for local emulators only), also exposed as the `insecure` backend-registration key.
- **Pluggable cluster CA key custody (`ca_key_strategy`) — any node can issue**: A new `ClusterCAKeyStrategy` seam (`pkg/trust/clusterca`, re-exported via `sdk/go/clusterca`) decides where the cluster CA signing key lives and which nodes issue node certificates, so every product (xkmsd, quicbaasd) behaves identically from a one-line config choice. `barrier` (default) bootstraps the key node-local, then promotes it into the qrdb-routed replicated barrier-encrypted datastore — every node loads it (each decrypting with its own barrier), so **any node can issue**, not just the first. `hsm` keeps the key inside a shared PKCS#11 HSM that every node signs through by reference (key material never leaves the HSM; FIPS-grade). `tpm-kek` wraps the replicated CA key under a KEK derived from a cluster seed that the bootstrap node seals to its local TPM and delivers to each joining node via **TPM credential activation** (`MakeCredentialWithExternalEK`/`ActivateCredential`) during attested enrollment — hardware-rooted without a shared HSM. Seed delivery is intentionally decoupled from enroll-01 via a neutral `NodeSecretProvider` seam, an optional `EnrollmentSecretStrategy` interface (type-asserted, so `barrier`/`hsm` are unaffected), and a reusable post-enrollment `SecretDeliveryService` fetch — all re-exported through `sdk/go/clusterca`. All three strategies are wired live in both xkmsd and quicbaasd: the shared TPM (from the seal strategy) supplies the credential activator, the delivery endpoint is mounted on each node's server, and a joining node fetches + activates its wrapped seed after enrollment. A `tpm_simulator` integration test validates the real credential-activation round-trip. `tpm-kek` requires every node to have a TPM and fails closed otherwise. See `docs/cluster/README.md`.
- **Touch-free ACME-attested Raft cluster enrollment**: A new `cluster.raft_enrollment.acme` mode provisions inter-node Raft mTLS with the runtime TrustedCA as the single cluster trust anchor. The first node pre-stages the CA hierarchy, issues its own transport leaf, and caches the full CA certificate set (adopted on later boots so `Load` finds every intermediate without forking a second root); joining nodes prove TPM residency via enroll-01 to an existing node's ACME directory (no shared CA private key distributed). Node certificates carry their SPIFFE identity (`spiffe://<trust-domain>/node/<raft-address>`) as a URI SAN, and transport issuance routes through a dedicated cluster intermediate (`cluster_ca_cn`) — root signs intermediates only (FedRAMP/PCI posture). The shared provisioning toolkit (`pkg/trust/clusterca`, re-exported via `sdk/go/clusterca`) — including `NewNodeLocalBackends` for pre-node cluster CA key protection — is consumed identically by every product in the stack. enroll-01 (attestation-gated self-enrollment) and endorse-01 (EAB-admin-gated admission) remain distinct admission models. See `docs/cluster/README.md`.
- **Cluster CA key protection at rest**: The node-local cluster CA signing keystore (which must exist before the replicated datastore, so it lives outside the barrier) is protected via the canonical seal strategies through `cluster.raft_enrollment.ca_key_protection` (`""` auto → TPM/HSM → passphrase → refuse; `tpm2`/`pkcs11`; `passphrase`; or `none`). Auto mode never silently falls back to plaintext, and `config.ComplianceGaps` refuses a plaintext (`none`) cluster CA key unless the daemon is started with `--insecure`.
- **Node-barrier data-plane encryption (encrypted-at-rest key stores)**: On an embedded qrdb deployment (`storage.backend: qrdb`) with the barrier enabled and an auto-unseal credential (a boot passphrase or a TPM/HSM seal strategy), xkms now uses the qrdb node's own barrier, which `encfs`-encrypts the entire PebbleDB data plane — so the crypto backends' key stores (TLS, ACME, and general keys) are encrypted at rest, closing a plaintext-on-disk gap. This mirrors go-quicbaas so both products drive the identical shared seal mechanism (`pkg/server/node_seal.go`, `qrdb_node.go`). Falls back to xkms's own barrier for non-qrdb storage or when no auto-unseal credential is present.
- **Unified seal provisioning (config / CLI / env)**: `barrier.strategy`/`barrier.passphrase` config, `XKMS_SEAL_STRATEGY`/`XKMS_SEAL_PASSPHRASE` env vars, and the `xkmsd --seal-passphrase` flag (precedence CLI > env > config) provide the boot-time auto-unseal secret. TPM/hardware strategies auto-unseal from the device with no boot secret; the TPM open is shared with the general TPM2 backend (single device open).
- **Canonical hardware-seal autodetect (SDK)**: `sdk/go.BuildBestSealStrategy` / `ProbeSealStrategies` (`pkg/seal/autodetect.go`) are the single stack-wide implementation of the non-provisioning, single-open TPM probe; go-quicbaas's `seal_autodetect.go` now delegates to it (removing a duplicate).
- **Secure-by-default gap for un-unsealable barriers**: `config.ComplianceGaps` now flags a `qrdb` + barrier deployment that cannot auto-unseal (a passphrase strategy with no boot secret), so the daemon refuses to start it (leaving backend keys plaintext) unless `--insecure` is set. The canonical seal vocabulary (`awskms`/`gcpkms`/`azurekv`/`passphrase`) is now accepted across xkms credential-seal validation and go-trusted-platform's barrier config, with backward-compatible aliases.
- **Embedded SDK tenant-scope enable-encryption**: The qrdb SDK now exposes `node.WithTenantIsolation()` and `node.EnableEncryption(ctx, scope, opts)` for standalone and clustered nodes; embedded nodes now have full daemon parity for per-tenant encryption migration via the shared `pkg/server.BuildTenantInfra` composer.
- **Credential-free enable-encryption sources**: Tenants starting with `StrategySystemBarrier` (system-managed auto-unseal) or `StrategyNone` can now transparently migrate to keyed strategies (passphrase / shamir / hardware) without supplying unlock credentials; truly-shared-barrier tenants are rejected via `ErrSharedBarrierImmutable`.
- **qrdb SDK re-exports for entitlement errors**: `go-qrdb/sdk/go` now re-exports `ErrSharedBarrierImmutable`, `EntitlementError`, migration error sentinels, and the `EncryptionMigrator` interface for downstream integration.
- **Standalone DKEK Package**: New `pkg/dkek/` package provides backend-agnostic Device Key Encryption Key support using Shamir's Secret Sharing. Works with any storage backend, no longer tied to PKCS#11.
- **SymmetricKeyProvider parity**: All symmetric-capable backends (AWS KMS, GCP KMS, Azure KV, Vault, PKCS#11, TPM2, Software, Symmetric) now implement `SymmetricKeyProviderWithTracking` with `GetTracker()` for AEAD safety tracking.
- **TPM2 Backend SymmetricKeyProvider**: The TPM2 backend (`pkg/backend/tpm2/`) now implements `SymmetricKeyProvider` interface, exposing `GenerateSymmetricKey()`, `GetSymmetricKey()`, and `SymmetricEncrypter()` through the Backend layer.
- **XKMSServicer unit tests**: Comprehensive test suite for `pkg/xkms/` servicer (368+ tests, 80.5% coverage) covering keys, crypto, certificates, sealing, barrier, PIN, user, platform store, shares, custodian, policy, and password operations.
- **GUI CustodianService**: New `xkey/pkg/gui/services/custodian_service.go` wrapping the SDK CustodianGroupService for Wails frontend with event emission, input validation, and 30 unit tests.
- **GUI TenantService**: New `xkey/pkg/gui/services/tenant_service.go` wrapping the SDK TenantService for Wails frontend with event emission, barrier init/unseal support, and 29 unit tests.
- **Custodian/Tenant events**: New event types for custodian group lifecycle (created, deleted, member added/removed, shares distributed) and tenant lifecycle (created, deleted, barrier initialized/unsealed).

### Removed
- **YubiKey Backend**: Removed `pkg/backend/yubikey/` -- YubiKey PIV devices are now supported through the generic PKCS#11 backend with `libykcs11`. This eliminates redundant code and provides stronger cryptographic operations via native PKCS#11 AES-GCM instead of envelope encryption.
- **SmartCard-HSM Backend**: Removed `pkg/backend/smartcardhsm/` -- SmartCard-HSM devices are supported through the generic PKCS#11 backend. The DKEK (Device Key Encryption Key) functionality has been moved to the standalone `pkg/dkek/` package.
- **Secret Sharing Duplication**: Removed `pkg/crypto/secretsharing/` -- consolidated on `pkg/threshold/shamir/` as the single Shamir's Secret Sharing implementation.

### Migration Guide
- **YubiKey users**: Replace `backend: yubikey` configuration with `backend: pkcs11` and set `library: /usr/lib/libykcs11.so` (or appropriate path for your OS). All PIV slot operations work identically through the PKCS#11 interface.
- **SmartCard-HSM users**: Replace `backend: smartcardhsm` with `backend: pkcs11`. For DKEK functionality, use the `pkg/dkek` package directly or the `xkmsctl dkek` CLI commands which now work with any backend.

## [0.2.3-alpha] - 2026-01-15

### Added
- Go SDK (`sdk/go/`) with multi-protocol client support (REST, gRPC, QUIC, MCP, Unix)
- Virtual FIDO2 key binary (`cmd/xkey`) with Linux UHID support
- Linux UHID interface package (`pkg/uhid`) for virtual USB HID device emulation
- Native FIDO2 authenticator (`pkg/fido2/authenticator/`) with CTAP2 protocol support
- Virtual FIDO2 device factory and native enumerator in `pkg/fido2/`
- Integration tests for SDK, UHID, and xkey packages
- WebAuthn mock authenticator for integration testing
- CLI documentation (`docs/usage/cli/`) for all commands
- FIDO2 documentation (`docs/fido2/`)

### Changed
- Renamed `cmd/cli` to `cmd/xkmsctl` (CLI binary)
- Renamed `cmd/server` to `cmd/xkmsd` (daemon binary)
- Moved `pkg/cli/` to `cmd/xkmsctl/` (CLI is now a standalone command)
- Moved `pkg/client/` to `sdk/go/` (clients are now part of SDK)
- Moved gRPC proto files to `pkg/api/grpc/proto/`
- Updated all Dockerfiles to use `golang:bookworm` with `GOTOOLCHAIN=auto`
- Updated Go version to 1.25.6
- Improved devcontainer with UHID permissions for virtual FIDO2 testing
- Enhanced QUIC, MCP, and gRPC handlers with sealing operations
- Refactored TPM2 package to remove simulator build constraints

### Fixed
- Race conditions in gRPC server port field using atomic operations
- Race conditions in server instance field access with proper mutex locking
- FROST handler parameter validation across all API protocols
- UHID integration test permissions in devcontainer

## [0.2.2-alpha] - 2025-12-24

### Added
- **Unified Symmetric Backend**: New `pkg/backend/symmetric/` consolidating AES and ChaCha20-Poly1305
  - Single backend supporting AES-128-GCM, AES-192-GCM, AES-256-GCM
  - ChaCha20-Poly1305 and XChaCha20-Poly1305 support
  - Password-protected key storage with Argon2 key derivation
  - AEAD nonce tracking and bytes limit enforcement
  - Import/export functionality for key portability
- **Algorithm Type System**: New `pkg/types/algorithms.go` with comprehensive type definitions
  - `KeyAlgorithmString` for asymmetric key algorithm identifiers (RSA, ECDSA, Ed25519)
  - `EllipticCurve` constants (P224, P256, P384, P521, Curve25519)
  - `HashName` constants matching Go crypto standards
  - `SignatureAlgorithmName` for signature algorithm identifiers
  - `AEADAlgorithm` and `KeyWrapAlgorithm` for encryption operations
  - `CLIKeyType` for CLI key type parsing
  - Parsing and validation functions for all algorithm types
- **FROST Protocol Stubs**: Infrastructure for future FROST threshold signature support
  - Handler stubs for REST, gRPC, QUIC, Unix, and MCP protocols
  - Backend factory stubs for FROST initialization
  - CLI command stubs for FROST operations

### Changed
- **Test Coverage Improvements**: Increased coverage across 7 packages to 90%+ target
  - `pkg/types`: 66.6% → 97.0% (+30.4%)
  - `pkg/xkms`: 86.8% → 90.6% (+3.8%)
  - `pkg/backend/symmetric`: 88.4% → 90.0% (+1.6%)
  - `pkg/client`: 86.3% → 90.1% (+3.8%)
  - `pkg/crypto/ecies`: 89.6% (all reachable code covered)
  - `pkg/backup`: 89.7% → 91.0% (+1.3%)
  - `pkg/webauthn/http`: 87.9% (improved edge case coverage)
- **Consolidated AESAttributes**: Removed deprecated `AESAttributes` type, using `KeyAttributes` with `SymmetricAlgorithm` field
- **TPM2 Symmetric Tests**: Updated tests for symmetric key generation and encryption validation
- **Cloud Backend Tests**: Cleaned up symmetric encryption tests for AWS KMS, Azure Key Vault, GCP KMS, and Vault backends

### Removed
- **pkg/backend/aes/**: Deprecated AES-only backend (functionality moved to `pkg/backend/symmetric/`)
  - `aes.go`, `aes_test.go`, `aes_bench_test.go`
  - `aes_importexport_test.go`, `aes_tracking_test.go`
  - `errors.go`
- **test/integration/backend/aes_integration_test.go**: Replaced by symmetric backend integration tests

### Fixed
- **Code Formatting**: Fixed gofmt issues in test files blocking CI
- **Linting Errors**: Resolved staticcheck and ineffassign warnings
- **Build Errors**: Fixed undefined `AESAttributes` references after consolidation

## [0.2.1-alpha] - 2025-12-21

### Added
- **TPM2 ProdCaData**: New `ProdCaData` structure for carrying TPM attestation data (Quote, Signature, Nonce, PCRs) from client to server during IDevID enrollment
  - Enables server-side storage of client attestation state upon successful enrollment
  - Binary serialization with `PackProdCaData`/`UnpackProdCaData` functions
  - Conversion to/from `Quote` structure for TPM operations

### Changed
- **Unified Key ID Format**: Consolidated key ID parsing to 4-part format `backend:type:algo:keyname` with optional segments
  - Shorthand `my-key` now supported (equivalent to `:::my-key`)
  - All segments except keyname are optional
  - Refactored `ParseKeyID`, `ParseKeyIDToAttributes`, and validation to use unified format
- **XKMS Service API**: Refactored service functions to use unified key ID format
  - Added `BackendFor(attrs)` helper for backend resolution based on StoreType
  - Added `ParseCertificateID()` using unified format
  - Renamed `getKeystoreForKey` to `getKeystoreForKID` with proper 4-part parsing
  - `Signer()`, `Decrypter()`, `Key()` now use `BackendFor()` for backend resolution
- **TPM2 Provisioning**: Simplified golden measurement and platform policy handling
  - Removed deprecated file integrity monitoring code (use IMA via PCR 10 instead)
  - `Install()` now uses config's `EK.HierarchyAuth` for already-provisioned TPMs
  - Improved logging with INFO level for provisioning operations
  - `GoldenMeasurements()` returns empty if no PCRs configured (skip platform policy)
- **Client Config**: Changed default Unix socket path to `xkms-data/xkms.sock`, removed `APIKey` field (use JWT via FIDO2 flow)
- **Validation**: Updated `ValidateKeyReference()` to enforce 4-part key ID format

### Fixed
- **AWS KMS Lock Contention**: Fixed test timeout by implementing double-checked locking in `Backend.initClient()`
- **Azure Key Vault Lock Contention**: Applied same double-checked locking fix for consistency
- **CI Go Version**: Updated `Dockerfile.ci` from Go 1.24.4 to 1.25.5
- **TPM Test Config**: Added missing `GoldenPCRs` to `TestTPMOperations` config

## [0.2.0-alpha] - 2025-12-13

### Added
- **Key Versioning API**: Full key version lifecycle management across all client interfaces
  - `ListKeyVersions` - List all versions of a key with status and metadata
  - `EnableKeyVersion` / `DisableKeyVersion` - Enable or disable specific key versions
  - `EnableAllKeyVersions` / `DisableAllKeyVersions` - Bulk version state management
  - gRPC, REST, QUIC, and Unix socket client support
  - Proto definitions in `pkg/api/grpc/proto/xkmsv1/xkms.proto`
- **JWT Authentication Adapter**: `pkg/auth/jwt.go` for token-based authentication
  - Configurable issuer, audience, and signing key validation
  - Support for RS256, ES256, and EdDSA signing algorithms
- **Adaptive Authentication**: `pkg/auth/adaptive.go` for multi-method auth
  - Automatic fallback between authentication methods (mTLS → JWT → API Key)
  - Configurable authentication chain with priority ordering
- **WebAuthn JWT Generator**: `pkg/webauthn/jwt_generator.go` for token generation after FIDO2 authentication
- **CLI Certificate Commands**: `internal/cli/cert.go` for certificate management operations
- **TPM2 Backend Integration**: Server-side TPM2 backend factory and operations
  - `internal/server/backend_factory_tpm2.go` - TPM2 backend initialization
  - `internal/server/backend_tpm2.go` - TPM2 server operations
- **YubiKey Sealer Interface**: Hardware-backed data sealing for YubiKey PIV
  - `pkg/backend/yubikey/yubikey_sealer.go` - Envelope encryption sealing
  - RSA-OAEP key wrapping for DEK protection
  - AES-256-GCM authenticated encryption
- **YubiKey Symmetric Encryption**: AES-GCM envelope encryption using PIV keys
  - `pkg/backend/yubikey/yubikey_symmetric.go` - Full symmetric backend
  - DEK wrapping with RSA-OAEP, ECIES (P-256/P-384), and X25519
  - Ed25519 to X25519 key conversion for key agreement
- **Configurable Hardware-Backed RNG**: Support for TPM2 and PKCS#11 hardware random number generators
  - `pkg/crypto/rand/` Resolver interface now implements `io.Reader` for crypto/rand compatibility
  - New `RNGConfig` in server configuration for RNG source selection
  - Modes: `auto` (default), `software`, `tpm2`, `pkcs11`
  - Fallback mode support when primary RNG fails
  - Environment variable overrides: `XKMS_RNG_MODE`, `XKMS_RNG_FALLBACK`, `XKMS_RNG_TPM2_*`, `XKMS_RNG_PKCS11_*`
- **Unix Socket Client Package**: `pkg/client/` for Go applications to communicate with xkms server
- **CLI Configuration Tests**: `internal/cli/config_test.go` with comprehensive config validation
- **Extended CLI Integration Tests**: Multi-protocol and complete lifecycle tests
- **User Documentation**: `docs/usage/user.md` for end-user documentation
- **Daemon Configuration**: Complete daemon operation support for `xkmsd`
  - Configuration file support (`--config`, `XKMS_CONFIG`)
  - Signal handling: SIGTERM/SIGINT for graceful shutdown, SIGHUP for config reload
  - PID file management with automatic creation and cleanup
  - Runtime configuration reload without restart
  - Unix socket protocol selection (gRPC or HTTP)
  - systemd service file with security hardening
  - Installation script and comprehensive documentation in `configs/`
- **Comprehensive Test Suites**: New test files for sealer and symmetric operations
  - `pkg/backend/yubikey/yubikey_sealer_test.go` (14 test functions)
  - `pkg/backend/yubikey/yubikey_symmetric_test.go` (20 tests)
- **Deployment Documentation**: systemd and OpenRC service files for production deployments
  - `deploy/systemd/` - systemd service unit, sysusers, and tmpfiles configurations
  - `deploy/openrc/` - OpenRC init script and configuration for Alpine Linux
  - `deploy/README.md` - Comprehensive deployment guide with installation steps
- **Enhanced README**: Expanded quick start guide with FIDO2 admin setup
  - Server Quick Start section with first-time setup instructions
  - Complete CLI examples for key, certificate, and admin management
  - XKMS Service API overview with all service functions documented
  - Multi-backend configuration examples
- **Admin CLI Commands**: `internal/cli/admin.go` for administrator management
  - Create, list, delete admin users
  - Role assignment and permissions management
- **FIDO2 CLI Commands**: `internal/cli/fido2.go` for passwordless authentication setup
  - Register and manage FIDO2 credentials
  - Authenticate using hardware security keys
- **RBAC Middleware**: `internal/rest/rbac_middleware.go` for role-based access control
  - Permission-based route protection
  - Role hierarchy support
- **User Management API**: `internal/rest/user_handlers.go` for user operations
  - REST endpoints for user CRUD operations
  - Integration with RBAC system
- **Unix Socket HTTP Server**: `internal/unix/` for local IPC
  - HTTP server over Unix domain sockets
  - Handlers for all xkms operations

### Changed
- **Test Coverage Improvements**: Increased coverage across multiple packages
  - `pkg/versioning`: 76.1% → 93.9%
  - `pkg/client`: 79.1% → 86.1%
  - `internal/config`: 83.1% → 96.0%
  - Testable code (excluding hardware) now at 93.4% average coverage
- Extended environment variable configuration support for RNG, rate limiting, and logging
- **API Naming**: Renamed `XKMSFacade` to `XKMSService` for clarity
  - `FacadeConfig` → `ServiceConfig`
  - `facade.go` → `service.go`
  - Updated all documentation, tests, and code references
- **Documentation**: Updated terminology from "facade" to "service" throughout
- **Typed Errors**: Replaced all `fmt.Errorf` with typed errors in PIV backends
  - YubiKey: 37 typed error variables, ~139 replacements
  - Enables proper `errors.Is()` and `errors.As()` error handling
- Extended `Resolver` interface with `Read(p []byte) (n int, err error)` method for `io.Reader` compatibility
- Hardware RNG (TPM2/PKCS#11) can now be used as drop-in replacement for `crypto/rand.Reader`
- Updated example configurations with RNG settings documentation
- **Documentation Cleanup**: Streamlined architecture documentation
  - `docs/architecture/unified-keyid-jwk-integration.md` reduced from 1,580 to 245 lines
  - Removed all legacy/migration content, kept only current API documentation
- **CI/CD**: Added FIPS 140-2/3 compliant builds to CI and release workflows
  - BoringCrypto-enabled binaries for environments requiring FIPS certification

### Fixed
- **Makefile**: Fixed `bc` dependency error in coverage calculation (replaced with pure shell/awk)
- **Ed25519 to X25519 Conversion**: Fixed SHA256 → SHA512 for RFC 7748 compliance in YubiKey symmetric
- **TestMCPStreamingNotifications**: Fixed flaky integration test for async MCP notifications
- **PlatformPassword Race Condition**: Fixed concurrent cache access in `pkg/tpm2/password.go`
  - Multiple goroutines calling `Bytes()` could bypass cache and trigger excessive TPM unseal operations
  - Implemented double-checked locking pattern to ensure only one goroutine performs unseal when cache is empty
  - `TestPlatformPassword_CacheConcurrency` now passes with race detector enabled
- Improved error handling and logging for ignored HTTP write errors
- Integration test stability improvements across all backends
- **Configuration**: Server socket path now defaults to `/var/run/xkms/xkms.sock` to match client defaults
- **Configuration**: Added `xkmsd-dev.yaml` for development/testing with `/tmp` paths
- **Configuration**: Added `xkms-client.yaml` example client configuration
- **Scripts**: Moved test scripts from `scripts/` to `test/scripts/`

### Removed
- **API Key Authentication**: Removed `pkg/auth/apikey.go` (replaced by JWT adapter)
- **Logo**: Removed `logo.svg` from repository root
- `test/integration/encoding/README_FIX.md` - Development-only fix notes
- `pkg/metrics/implementation-summary.md` - Development-only implementation notes

### Known Limitations (Alpha)
- **TPM2 Server Integration**: The `pkg/tpm2` library is fully functional for direct Go usage, but server-side integration (REST/gRPC/CLI/MCP) is not yet complete. Use `pkg/tpm2` directly for TPM2 operations.
- **Vault Import/Export**: HashiCorp Vault Transit backend does not support key import/export operations
- **PKCS#11 Attestation**: Some attestation methods are not yet implemented

## [0.1.9-alpha] - 2025-12-07

### Added
- **WebAuthn/FIDO2 Server Support**: Complete server-side passwordless authentication
  - `pkg/webauthn/` - Core WebAuthn service with user, session, and credential management
  - `pkg/webauthn/http/` - HTTP handlers for REST API integration
  - Registration flow: begin/finish ceremonies with session management
  - Authentication flow: discoverable credentials and user-specific login
  - Pluggable store interfaces for UserStore, SessionStore, CredentialStore
  - Memory-based stores for development and testing
  - Full test coverage with testify mocks
- **WebAuthn REST API Endpoints**:
  - `GET /api/v1/webauthn/registration/status` - Check registration status
  - `POST /api/v1/webauthn/registration/begin` - Start registration ceremony
  - `POST /api/v1/webauthn/registration/finish` - Complete registration
  - `POST /api/v1/webauthn/login/begin` - Start authentication ceremony
  - `POST /api/v1/webauthn/login/finish` - Complete authentication
- **Shared Mock Infrastructure**: `pkg/xkms/mocks/mock_keystore.go` for unit testing
- **WebAuthn Integration Tests**: Docker-based tests in `test/integration/api/`
- **WebAuthn Documentation**: `docs/usage/webauthn.md`
- **Unified Rate Limiting**: Consistent rate limiting across all public APIs
  - Integrated rate limiting into REST server via middleware
  - Added gRPC unary and stream server interceptors for rate limiting
  - QUIC/HTTP3 server rate limiting via HTTP middleware
  - MCP JSON-RPC server connection-level rate limiting
  - New configuration options: `burst`, `cleanup_interval_sec`, `max_idle_sec`
  - Environment variable overrides: `KEYSTORE_RATELIMIT_ENABLED`, `KEYSTORE_RATELIMIT_REQUESTS_PER_MIN`, `KEYSTORE_RATELIMIT_BURST`

### Changed
- Refactored REST server tests to use shared mock infrastructure
- Improved test organization with centralized mocks
- Extended `RateLimitConfig` with additional options for burst and cleanup intervals

## [0.1.8-alpha] - 2025-12-06

### Changed
- **Storage Independence**: Removed go-objstore dependency, go-xkms now has its own storage implementations
  - Local `pkg/storage/memory.go` provides in-memory storage backend
  - Local `pkg/storage/file/` provides file-based storage backend
  - Storage interface remains compatible with go-objstore for higher-level app integration
- **Docker Cleanup**: Removed all GOPRIVATE workarounds from integration test Dockerfiles
  - Cleaned up main Dockerfile (removed sed/GOPRIVATE/GOPROXY hacks)
  - All integration tests now use standard Go module proxy

### Removed
- `pkg/storage/objstore_adapter.go` - go-objstore adapter (no longer needed)
- `pkg/tpm2/store/objstore_*.go` - All go-objstore adapters for TPM store
- `pkg/tpm2/store/factory.go` - go-objstore factory (replaced with local implementations)
- `pkg/tpm2/store/testing.go` - go-objstore test helpers
- GOPRIVATE environment variables from all Dockerfiles

### Dependencies
- Removed go-objstore dependency entirely (go-xkms is now self-contained for storage)

## [0.1.7-alpha] - 2025-12-05

### Added
- **Unified Sealer Interface**: Backend-agnostic sealing abstraction across all backends
  - `pkg/tpm2/sealer.go` - TPM2 sealer with PCR policy support
  - `pkg/backend/pkcs8/sealer.go` - Software sealer using HKDF + AES-256-GCM
  - `pkg/backend/pkcs11/sealer.go` - HSM hardware-backed AES-GCM sealing
  - `pkg/backend/awskms/sealer.go` - AWS KMS cloud-managed encryption
  - `pkg/backend/azurekv/sealer.go` - Azure Key Vault symmetric key sealing
  - `pkg/backend/gcpkms/sealer.go` - GCP KMS cloud-managed encryption
  - `pkg/backend/vault/sealer.go` - HashiCorp Vault Transit engine encryption
- **JWT SigningMethodSigner**: Hardware-backed JWT signing via `crypto.Signer` interface
  - Supports RS256/384/512, PS256/384/512, ES256/384/512, EdDSA
  - `SignWithSigner()` and `SignWithSignerAndKID()` convenience methods
- **Certificate Display Functions**: `pkg/certstore/types.go` with OID parsing, key usage display
- **Composite Sealing**: `pkg/xkms/composite_seal.go` for multi-backend seal operations
- **TPM2 Enhancements**: Certificate conversion, type re-exports, store abstraction
- **Logging Package**: Structured logging infrastructure (`pkg/logging/`)
- **Architecture Documentation**: Storage interfaces and BlobStorer refactoring guides

### Changed
- Extended `pkg/types/types.go` with Password, SealData, and Sealer interfaces
- Refactored internal TPM store with cleaner interfaces and helpers
- Improved overall test coverage from 85.8% to 91.2%

### Fixed
- Test coverage gaps across multiple packages:
  - `pkg/certstore`: 46.1% → 90.2%
  - `pkg/encoding/jwt`: 59.5% → 94.3%
  - `pkg/types`: 62.0% → 96.1%
  - `pkg/backend/threshold`: 72.5% → 81.7%
  - `pkg/storage/file`: 86.8% → 92.3%

## [0.1.6-alpha] - 2025-11-22

### Added
- Unified service pattern for simplified multi-backend management
- Backend factory pattern with auto-detection and configuration
- Comprehensive test coverage for service and factory (40+ test cases)
- Input validation for all API endpoints to prevent injection attacks
- Path traversal protection in file storage backend

### Changed
- Simplified API: `server.Initialize()` instead of `server.InitializeService()`
- Refactored xkms initialization with auto-backend detection
- Updated documentation and examples to reflect simplified API
- Improved code coverage from 72.8% to 92.5% in xkms package

### Security
- Centralized validation at service layer protects ALL public APIs (REST, gRPC, QUIC, CLI, MCP)
- All user inputs validated before reaching any backend or storage layer
- Created shared `pkg/validation` package for consistent validation across codebase
- Service layer validates all keyIDs, backend names, and key references
- Defense in depth: Storage layer also validates (though service should prevent bad input)
- Rejects special characters, null bytes, and directory traversal attempts
- Backend names: whitelist pattern `[a-z0-9\-]+` only (max 64 chars)
- KeyIDs: whitelist pattern `[a-zA-Z0-9_\-\.]+` only (max 255 chars)
- Key references support "backend:key-id" format with validation of both parts
- File storage protected against path traversal attacks
- Log injection prevention via sanitization of all logged user input

### Fixed
- Test coverage gaps in service and backend factory code
- Documentation examples now demonstrate clean, simple API usage
- Potential path traversal vulnerability in file storage operations

## [0.1.5-alpha] - 2025-11-19

### Changed
- Replaced minimal TPM2 implementation with full production-grade TPM support
- Complete TPM 2.0 integration with hierarchies, policies, and provisioning
- Enhanced TPM attestation and cryptographic operations
- Updated all security-critical dependencies to latest versions
  - golang.org/x/crypto: v0.42.0 → v0.45.0
  - google.golang.org/grpc: v1.76.0 → v1.77.0
  - AWS SDK v2, Prometheus, OpenTelemetry, TPM libraries
- Updated golangci-lint to v2.6.2 with action v7 for Go 1.25 compatibility
- Fixed TPM2 backend API compatibility with new config structure
- Removed redundant release tarballs (direct binary downloads only)

### Fixed
- Fixed TPM2 integration test build tags to properly include `tpm2` tag requirement
- Fixed TPM2 event log parsing to use absolute paths
- Resolved all 51 linting errors preventing CI builds (17 errcheck, 34 staticcheck)
  - Added proper error handling for unchecked error returns
  - Fixed JSON marshaling of function types (SessionCloser)
  - Resolved duplicate package imports and syntax errors
  - Suppressed false positive style warnings for embedded field accessors

## [0.1.4-alpha] - 2025-11-18

### Changed
- Internal refactoring and optimizations

## [0.1.3-alpha] - 2025-11-18

### Changed
- Refactored KeyAttributes to common library for better code reuse
- Improved type organization and reduced import cycles

## [0.1.2-alpha] - 2025-11-18

### Added
- Threshold cryptography package with Shamir Secret Sharing
- Split and combine secrets with configurable threshold

## [0.1.1-alpha] - 2025-11-17

### Added
- Quantum-safe signing support (post-quantum cryptography)
- Key encapsulation mechanisms (KEM) for quantum resistance

## [0.1.0-alpha] - 2025-01-15

### Overview

Initial alpha release of go-xkms - a production-ready cryptographic key and certificate management library for Go with 10 backends, 5 client interfaces, and dual licensing (AGPL-3.0 + Commercial).

### Added

#### Core Features
- Unified KeyStore interface for consistent key and certificate operations across all backends
- CompositeKeyStore pattern combining backend storage with certificate management
- Thread-safe concurrent operations with proper synchronization primitives
- Pluggable architecture for easy backend and storage extension

#### Key Management
- **Asymmetric Keys**: RSA (2048/3072/4096), ECDSA (P-256/P-384/P-521), Ed25519
- **Symmetric Keys**: AES-GCM (128/192/256-bit) with AEAD support
- **Operations**: Generate, store, retrieve, rotate, delete, import/export, wrap/unwrap
- **Standards**: Implements Go's `crypto.Signer` and `crypto.Decrypter` interfaces
- **Protection**: Password-protected PKCS#8 key storage with secure key derivation

#### Cryptographic Backends (10 Production-Ready)
1. **PKCS#8**: File-based asymmetric key storage
2. **AES**: File-based symmetric encryption backend
3. **Software**: Pure Go implementation for testing
4. **PKCS#11**: Hardware Security Module (HSM) integration
5. **SmartCard-HSM**: CardContact SmartCard-HSM with DKEK support
6. **TPM2**: Trusted Platform Module 2.0 with hierarchies and policies
7. **YubiKey**: YubiKey PIV (Smart Card) support
8. **AWS KMS**: Amazon Key Management Service integration
9. **GCP KMS**: Google Cloud Key Management Service integration
10. **HashiCorp Vault**: Vault Transit Engine integration

All backends support symmetric encryption (AES-GCM) and AEAD operations.

#### Certificate Management
- **CRUD Operations**: Store, retrieve, delete, list X.509 certificates
- **Certificate Chains**: Full chain management, building, and validation
- **CRL Support**: Certificate Revocation List management and checking
- **Validation**: Certificate verification with configurable `x509.VerifyOptions`
- **Hardware Storage**: Native PKCS#11 HSM and TPM2 NV RAM certificate storage
- **Hybrid Mode**: Automatic failover between hardware and external storage
- **Capacity Monitoring**: Certificate storage capacity management

#### Client Interfaces (100% API Coverage)
- **REST API**: HTTP/HTTPS web services with Fiber framework
- **gRPC**: High-performance RPC with Protocol Buffers
- **QUIC**: HTTP/3 over QUIC for ultra-low latency
- **CLI**: Full-featured command-line interface with Cobra
- **MCP**: Model Context Protocol (JSON-RPC) for AI integration

All interfaces expose the complete KeyStore API (17/17 methods).

#### Cryptographic Operations
- **Signing**: RSASSA-PSS, RSASSA-PKCS1-v1_5, ECDSA-SHA2, Ed25519
- **Verification**: Multi-algorithm signature verification
- **Asymmetric Encryption**: RSA-OAEP, RSA-PKCS1v15
- **Symmetric Encryption**: AES-128/192/256-GCM with nonce and tag management
- **AEAD**: Authenticated Encryption with Additional Data support
- **Hash Functions**: SHA-256, SHA-384, SHA-512, SHA3

#### Encoding & Interoperability
- **JWK**: JSON Web Key encoding/decoding (RSA, ECDSA, Ed25519, symmetric)
- **JWT**: JSON Web Token generation and validation (RS256, RS384, RS512, ES256, ES384, ES512, EdDSA)
- **JWE**: JSON Web Encryption with key wrapping (RSA-OAEP, AES-GCM)
- **PKCS#8**: Private/public key encoding with password protection
- **PEM**: PEM format encoding/decoding
- **Cross-Library Testing**: Verified interoperability with jose-go, go-jose, jwt-go

#### Security & Access Control
- **Authentication**: mTLS, API Key, NoOp (configurable per interface)
- **Authorization**: RBAC (Role-Based Access Control) integration
- **Audit Logging**: Comprehensive audit trail with structured logging
- **Policy Engine**: Configurable security policies
- **Metrics**: Prometheus-compatible metrics export
- **Correlation IDs**: Request tracing across all interfaces

#### Storage Abstraction
- **File Storage**: Production file-based storage with atomic operations
- **Memory Storage**: In-memory storage for testing
- **Filesystem Interface**: Custom FS implementation support (similar to io/fs)
- **Atomic Operations**: Safe concurrent file operations

#### Testing & Quality
- **Unit Tests**: 93.3% average code coverage across 25+ packages
- **Integration Tests**: 151 passing tests across all 10 backends
- **Benchmark Tests**: Performance benchmarks for critical operations
- **Docker Integration**: Complete Docker Compose test environments
- **Security Scanning**: gosec integration for vulnerability detection
- **Linting**: golangci-lint with comprehensive rulesets

#### Build System
- **Makefile**: 50+ targets for building, testing, and deployment
- **Version Injection**: Automatic version embedding in binaries via ldflags
- **Build Tags**: Conditional compilation for optional backends
- **Binary Builds**: CLI and 5 server binaries with proper versioning
- **Shared Library**: CGO-based libxkms.so with version numbering
- **Cross-Platform**: Linux and macOS support (Windows experimental)
- **CI/CD Ready**: GitLab CI configuration included

#### Documentation
- Getting Started guide with step-by-step instructions
- Backend-specific configuration guides (10 backends)
- Certificate Management best practices
- Symmetric Encryption guide
- API Parity documentation (REST/gRPC/QUIC/CLI/MCP)
- Build System documentation
- 15+ working examples covering all features

#### Licensing
- **Dual Licensed**: AGPL-3.0 (open source) + Commercial License
- **Copyright**: Jeremy Hahn & Automate The Things, LLC
- **Source Headers**: All 502 Go files updated with dual-license notice
- **Commercial Options**: Available from Automate The Things, LLC
- **SPDX Compliant**: Proper license identifiers throughout

### Changed
- Updated from Apache 2.0 to dual licensing model (AGPL-3.0 + Commercial)
- Reorganized documentation structure to match standard patterns
- Consolidated type definitions into pkg/types to prevent import cycles
- Enhanced error handling with typed errors and proper error wrapping

### Fixed
- Import/export functionality across all backends
- Symmetric encryption support in cloud KMS backends (AWS, GCP, Azure)
- Test coverage gaps in backend implementations
- Race conditions in concurrent operations
- Memory leaks in long-running server processes

### Security
- All source code scanned with gosec
- No high-severity vulnerabilities
- Secure random number generation for all cryptographic operations
- Protection against timing attacks in key operations
- Safe handling of sensitive data with proper zeroing

### Known Limitations (Alpha Release)
- API may change before v1.0.0 (backward compatibility maintained where possible)
- Some cloud KMS operations require active network connectivity
- TPM2 integration requires hardware TPM or software simulator (swtpm)
- YubiKey support requires physical device
- Windows support is experimental and not fully tested
- Azure Key Vault backend requires valid Azure credentials

### Performance
- Key generation: <100ms for RSA-2048, <50ms for ECDSA-P256, <10ms for Ed25519
- Signing: <10ms for RSA, <5ms for ECDSA, <1ms for Ed25519
- Symmetric encryption: <1ms for AES-256-GCM (1KB payload)
- Certificate operations: <5ms for storage/retrieval

### Contributors
- Jeremy Hahn (@jeremyhahn)

### Links
- Repository: https://github.com/jeremyhahn/go-xkms
- Documentation: https://github.com/jeremyhahn/go-xkms/tree/master/docs
- Commercial Licensing: licensing@automatethethings.com
- AGPL-3.0 License: https://www.gnu.org/licenses/agpl-3.0.html

[0.2.3-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.3-alpha
[0.2.2-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.2-alpha
[0.2.1-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.1-alpha
[0.2.0-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.0-alpha
[0.1.9-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.9-alpha
[0.1.8-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.8-alpha
[0.1.7-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.7-alpha
[0.1.6-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.6-alpha
[0.1.5-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.5-alpha
[0.1.4-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.4-alpha
[0.1.3-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.3-alpha
[0.1.2-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.2-alpha
[0.1.1-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.1-alpha
[0.1.0-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.0-alpha

---

## Merged from go-trusted-ca (2026-04-16)

The go-trusted-ca repository was merged into go-xkms. All ACME-related
functionality now lives under `pkg/acme/`. The following sections are
imported from go-trusted-ca's CHANGELOG for historical reference.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### API Documentation
- **Swagger UI** at `/docs` for interactive API exploration
- **ACME API OpenAPI spec** (`/openapi/acme-api.yaml`) - Full RFC 8555 documentation
- **Admin API OpenAPI spec** (`/openapi/admin-api.yaml`) - Administrative endpoints
- Spec switching via query parameter (`?spec=admin-api`)

#### Monitoring & Observability
- **Grafana Dashboard** (`deploy/grafana/dashboard.json`)
  - SLO tracking (99.9% availability, 99% challenge success)
  - Error budget tracking
  - Request latency heatmaps (p50, p95, p99)
  - Certificate issuance metrics
  - Challenge validation rates by type
  - System resource monitoring (CPU, memory, goroutines, GC)

#### Multi-Arch Docker Builds
- GitHub Actions workflow for automated multi-arch builds
- Support for `linux/amd64` and `linux/arm64`
- Trivy security scanning on every build
- SBOM (Software Bill of Materials) generation
- Build provenance attestation

---

## [0.1.0-alpha] - 2026-01-02

### Added

#### ACME Server (RFC 8555 Compliant)
- Full RFC 8555 ACME protocol implementation
- Directory endpoint with capability discovery
- Account management (create, update, deactivate, key rollover)
- Order workflow with authorization and challenge validation
- Certificate issuance and revocation
- Nonce management and replay protection

#### Challenge Types
- **HTTP-01**: Standard domain validation via HTTP token
- **DNS-01**: Domain validation via DNS TXT records
- **device-attest-01**: TPM 2.0 device attestation per draft-acme-device-attest
- **enroll-01**: TCG-compliant IDevID enrollment for TPM-equipped devices
- **endorse-01**: Endorsement Key certificate provisioning

#### Multi-Tenancy
- Tenant isolation with dedicated CAs
- Per-tenant key management via go-xkms KMS
- RBAC role-based access control
- RBAC policies with CEL expressions

#### Admin API
- RESTful management interface
- Tenant lifecycle management
- Policy and role administration
- CA status and health monitoring

#### Storage Backends
- All go-xkms backends supported:
  - Local filesystem (PKCS#8)
  - TPM 2.0 hardware protection
  - PKCS#11 HSM integration
  - AWS KMS
  - GCP Cloud KMS
  - Azure Key Vault
  - HashiCorp Vault
- Certificate storage via go-objstore

#### Security
- JWT-based authentication
- TLS 1.3 support
- Rate limiting with RFC 8555 compliance
- Proxy header support (X-Forwarded-For, X-Real-IP)

#### Deployment
- Single-node embedded mode
- Raft-based clustering via QRDB
- Docker container support
- Prometheus metrics endpoint

#### Developer Experience
- Comprehensive test coverage (90%+ on core packages)
- Integration test suite with Docker
- Example configurations and quickstart guide

### Dependencies
- go-xkms v0.2.2-alpha
- go-objstore v0.1.4-alpha
- go-qrdb (local development)

### Known Limitations
- TCG-CSR-IDEVID parsing partially implemented
- Client package coverage at 74.8% (TPM functions require integration tests)

---

[0.1.0-alpha]: https://github.com/jeremyhahn/go-trusted-ca/releases/tag/v0.1.0-alpha
