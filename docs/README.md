# go-xkms Documentation

Comprehensive documentation for the go-xkms cryptographic key management library.

## Overview

go-xkms is a unified cryptographic key management library for Go that provides a consistent interface across multiple storage backends, from software-based file storage to hardware security modules and cloud key management services.

## Feature documentation

Each feature below has a folder holding five documents — `architecture.md`,
`engineering.md`, `cli.md`, `api.md`, `user.md`. Together they are the
feature's requirements: read the folder before reading the code, and change
the folder in the same commit that changes the behavior.

| Feature | What it covers |
|---------|----------------|
| [acme-issuance](acme-issuance/) | ACME RFC 8555 server and client, ARI, DNS-01/HTTP-01, TPM enrollment |
| [attestation-evidence](attestation-evidence/) | RFC 9334 evidence-level primitives: TPM2_Quote, AK and EK certificate chains, strict TCG crypto-agile event-log parsing and replay, TPM2_Certify and IAK/IDevID re-exports, and signed reference values (CoRIM), all in `sdk/go/evidence` |
| [attestation-verifier](attestation-verifier/) | The generic, backend-agnostic `pkg/attestation` API — chain/signature verification (`Verifier`) and per-format key-binding invariants (`VerifyInvariants`) — that gates CSR issuance on hardware provenance for any format, TPM2/PIV/Android included |
| [attested-peer](attested-peer/) | Is the other end of a connection a currently attested system? The quote→verdict primitive, IDevID/IAK credential validation, TLS channel binding, and the verifier, evidence cache and collector behind go-qrdb's attested-caller gate |
| [audit-log](audit-log/) | Tamper-evident audit records and their signing chain |
| [auth-factors](auth-factors/) | Factor composition, adapters, and the identity/key-domain split |
| [avr-device-backend](avr-device-backend/) | An AVR device with a secure-element identity as an xkms key provider and DICE attester, over the arduino-generic wire protocol; its UEID, and device-attest-01 enrolment (simulator only: the device cannot sign a CSR) |
| [backend-credentials](backend-credentials/) | Backend secrets (PKCS#11 User PIN, cloud KMS and Vault secrets) under `credentials.seal_strategy`: the `pkg/server/credentials` service, `credential://` resolution at startup, and the `xkmsctl credential` / `/api/v1/credentials` / MCP `credentials.*` surface |
| [certificate-authority](certificate-authority/) | `TrustedCA` — cross-signed root pool, AIA import, DANE TLSA publishing |
| [clustering](clustering/) | Embedding a go-qrdb clustered node behind the `raft` build tag: Raft config mapping, inter-node mTLS provisioning, not-leader redirects, the `xkmsctl cluster`/`rebalance` control plane, the read-only REST cluster status/membership surface for the web console, and cluster CA key custody |
| [crypto-backends](crypto-backends/) | The `Backend` contract, every software, hardware and cloud implementation, and the `WITH_*` toggles that compile each one in |
| [datastore](datastore/) | The single global, qrdb-backed datastore every xkms subsystem stores through: the `storage.Backend` interface, `datastore.engine` (memory/file/pebble) and `datastore.mode` (standalone/remote) configuration, and why there is no per-subsystem storage choice left |
| [dice-device-identity](dice-device-identity/) | DICE-based device identity with a hardware root of trust: the TCG DICE certificate extensions and UCCS claims (the UEID in either placement), their verification, and the `dice-idevid` issuance profile |
| [escrow](escrow/) | External key escrow (KMIP + xkms federation): the agent factory, daemon config, and service layer — reachable today only through the embedded Go SDK, pending an RBAC vocabulary decision for the network transports |
| [fido2-ctap2](fido2-ctap2/) | The canonical FIDO2 CTAP2 implementation |
| [frost-threshold-signing](frost-threshold-signing/) | RFC 9591 FROST threshold signing (`-tags frost`) — trusted-dealer keygen, the explicit round API, and why the CLI's local path and the REST/gRPC/MCP network surface are independent |
| [host-embedding](host-embedding/) | Mounting the `xkms` ServiceModule in a qrdb-embedding host: the host supplies dependencies (qrdb client, barrier registry, PIN backend, sealer, CA config, PCR reader), `pkg/compose` builds the Password Manager, SSH, CA, platform store, credential and policy stores through the same path as `xkmsd`, and the barrier routes stay the host's unless it opts in |
| [init-ceremony](init-ceremony/) | `xkmsd init` — the single-administrator bootstrap: CA artifacts, the node's first boot and the administrator's login factors |
| [key-management](key-management/) | Key lifecycle, key providers, symmetric and asymmetric operations |
| [luks](luks/) | The single LUKS implementation in the stack: FIPS-aware volume lifecycle (`Manager`/`Executor`, `LibExecutor` on `go-luks2`) and TPM 2.0 passphrase sealing (`TPMSealer`, configurable Platform-SRK/Shared-SRK parent). `xkey` consumes it through `sdk/go/luks`; its desktop-specific glue is documented separately in `xkey/docs/luks/` |
| [multi-tenancy](multi-tenancy/) | Per-tenant isolation, tenant barriers, tenant-scoped keys |
| [observability](observability/) | Prometheus instrumentation — operation counters/histograms, backend health, keys/certs totals, connection tracking |
| [oidc-credentials](oidc-credentials/) | Server-side OIDC credentials: named OAuth/OIDC logins on the tenant barrier, tenant-shared or personal, kept fresh by a leader-elected scheduler; rotating refresh tokens under a per-credential lock with compare-and-swap; device-flow and import logins; `GetAccessToken` by reference and the codex `chatgptAuthTokens` projection — alongside xkey's unchanged local OIDC on the shared `pkg/oidc` core |
| [password-vault](password-vault/) | Stored password credentials and their access modes |
| [pin-management](pin-management/) | The PIN service and its TPM 2.0 backend |
| [piv-smartcard](piv-smartcard/) | PIV slot operations as a factor and as a CLI/SDK verb |
| [pkcs11-backend](pkcs11-backend/) | `pkg/backend/pkcs11` — xkms as a PKCS#11 *client* consuming an HSM/token (`-tags pkcs11`), distinct from the provider module below |
| [pkcs11-provider-module](pkcs11-provider-module/) | The `pkcs11-module` cgo provider and its slot/token lifecycle |
| [platform-secrets](platform-secrets/) | Platform secret storage and resolution |
| [rbac](rbac/) | The `auth.Authorizer` seam over qrdb's identity plane: the xkms permission vocabulary, transport enforcement, and the built-in role model |
| [post-quantum](post-quantum/) | ML-KEM / ML-DSA key generation and use — the stdlib vs. CIRCL split, FIPS behavior, and the SLH-DSA/HSS/XMSS mechanisms the PKCS#11 module advertises but does not implement |
| [release-engineering](release-engineering/) | Cutting an -alpha release in two steps — `make release-alpha` prepares a pull request, `make release-tag` tags it once merged — the lockstep tag namespaces, the reciprocal `go.mod` pin edges, the exported-API growth gate |
| [sealing-and-barrier](sealing-and-barrier/) | Hardware and cloud seal strategies contributed to the qrdb barrier, and the pre-barrier store holding the TPM-sealed PKCS#11 PIN |
| [sign-server](sign-server/) | Embeddable, node-local, sign-only xkms server (`pkg/signserver`, `sdk/go/signserver`): an exclusive SO_PEERCRED unix socket a remote-mode PKCS#11 module signs through, with only named keys exposed, and CGO-free key provisioning under the CKA_LABEL/CKA_ID the module exposes |
| [signing](signing/) | The embedded SDK's `Sign`/`Verify` — persisted per-blob checksums (`SignOptions.BlobCN`, `VerifyOpts.IntegrityCheck`) shared by every backend |
| [ssh-agent-sessions](ssh-agent-sessions/) | Serving an xkms-held key over an ephemeral SSH agent socket with no connection target — git commit signing, `ssh-keygen -Y sign` |
| [ssh-keys](ssh-keys/) | SSH keys (software or backend-backed), host-key pins, and authorized_keys entries — key lifecycle, `pkg/ssh/keys`/`known_hosts`/`authorized`, and the REST/gRPC/MCP/CLI surface over them |
| [ssh-sessions](ssh-sessions/) | Opening an outbound SSH connection: the interactive console (embedded-only), non-interactive `Run`/upload sessions (every SDK transport, by composing the `ssh-keys` sign/known-hosts endpoints), launching the system `ssh` client, connection profiles, session history, and local `ssh_config`/agent discovery — `pkg/ssh/{console,connect,session,sessions,profile,local}` |
| [symmetric-aead](symmetric-aead/) | AES-GCM / ChaCha20-Poly1305 / AES-CBC / AES-ECB, the AEAD safety tracker, GCM nonce modes under FIPS |
| [tpm-policies](tpm-policies/) | Named, TPM-authorized policies (PolicyAuthorize + NV-counter revocation) shared by many keys and sealed objects, the key/policy registry, and per-tenant TPM modes (`none` / `shared` / `vtpm`) |
| [tpm2](tpm2/) | EK/SRK lifecycle, IDevID/LDevID, PCR policy, attestation, sealed objects |
| [trust-bootstrap](trust-bootstrap/) | The DANE / Noise / SPKI / Direct / Auto mode-dispatch library |
| [user-onboarding](user-onboarding/) | Administrator-issued account-activation invitations, redeemed through the WebAuthn/PIV ceremonies to enroll the first credential (go-xkms#1294 part B) |
| [web-console](web-console/) | The Svelte SPA console served by `xkmsd` at `/ui/` and by the `xkms-console` Wails desktop shell (remote and standalone loopback modes) — distinct from the xkey GUI |
| [webauthn](webauthn/) | The canonical WebAuthn relying party |
| [xkmsd-configuration](xkmsd-configuration/) | How the daemon resolves its configuration: defaults, file, `XKMS_*` environment, flags, and the listeners that consume the result |

xkey has its own feature folders under [xkey/docs/](../xkey/docs/).

Two files are worth reading before the rest, because the other folders
cross-reference them instead of repeating them:

- [`key-management/api.md`](key-management/api.md) §"How the six transports are
  shaped" — the transport model every other `api.md` assumes, plus the
  as-shipped port-conflict table.
- [`key-management/cli.md`](key-management/cli.md) §"Global flags" — the
  `xkmsctl` flags every command group inherits.

Everything below this section predates the feature-folder convention. It is
**unconverted debt, not a precedent** — a new feature gets a five-file folder
regardless of what the rest of this tree looks like.

## Migration record

Migration is per-repo and **feature by feature**; this is the record the
convention requires, so the next reader resumes from a list instead of
re-auditing the tree.

While conversion is in progress, **a feature folder is NORMATIVE for its
feature.** A legacy path listed as superseded is retained only for detail not
yet absorbed and is **non-normative** — where the two disagree, the feature
folder wins.

Do not add a count here. Derive it:

```bash
ls -d docs/*/ xkey/docs/*/ | while read d; do
    ok=1
    for f in architecture engineering cli api user; do
        [ -f "$d$f.md" ] || ok=0
    done
    [ $ok -eq 1 ] && echo "$d"
done
```

Test for **all five files**, not just `architecture.md`. Several legacy folders
— `docs/acme/`, `xkey/docs/ble/`, `xkey/docs/gui/` —
already contain a file called `architecture.md`, so the shorter form overcounts
by three and reports unconverted folders as converted.

### Legacy paths superseded by a feature folder

| Feature folder | Legacy paths it supersedes |
|---|---|
| [key-management](key-management/) | `architecture/unified-keyid-jwk-integration.md` — **absorbed and deleted** (go-xkms#1433): the key ID format and validation rules moved to [`key-management/engineering.md`](key-management/engineering.md) §"Key ID format"; its JWK xKMS helpers (`FromxKMS`, `LoadKeyFromxKMS`, …), JWT examples and YAML config do not exist and were dropped. `key-agreement.md` |
| [crypto-backends](crypto-backends/) | `backends/` (README, software, pkcs8, tpm2, pkcs11, nitrokey-hsm, awskms, gcpkms, azurekv, vault) — **absorbed and deleted** (go-xkms#1433). Each claim was re-verified against `pkg/backend/*`, `pkg/config` and `pkg/xkms/register_*.go`. Per-backend config keys, credential resolution and generated algorithms moved to [`crypto-backends/engineering.md`](crypto-backends/engineering.md#per-backend-configuration); TPM 2.0 and PKCS#11 detail was already in [`tpm2/`](tpm2/) and [`pkcs11-backend/`](pkcs11-backend/). Dropped as unsupported by the code: Vault AppRole/Kubernetes/certificate auth, AWS/Azure generation beyond RSA-2048/P-256, software RSA 6144/8192, a persistent AEAD tracker, and pricing, IAM, compliance and latency prose; `architecture/security-levels.md` — **absorbed and deleted** (go-xkms#1433): the `SecurityLevel` ordering and per-backend levels moved to [`crypto-backends/engineering.md`](crypto-backends/engineering.md); its FIPS-level claims, UI prose and sort examples were dropped; `configuration/build-system.md` — **absorbed and deleted** (go-xkms#1433): the object-store toggles, the codec seed in `BUILD_TAGS`, `make show-backends` and the xkey Makefile's toggle set moved to [`crypto-backends/engineering.md`](crypto-backends/engineering.md#build-toggles) |
| [frost-threshold-signing](frost-threshold-signing/) | `frost/` — **absorbed and deleted** (go-xkms#1433): every claim was re-verified against `pkg/keyprovider/frost`; the true ones moved into the feature folder (the security checklist became the procedure in [`frost-threshold-signing/user.md`](frost-threshold-signing/user.md) §"Operating a FROST group securely"), and the fictional `xkms frost` CLI, per-backend Go config, env vars and compliance prose were dropped |
| [tpm2](tpm2/) | `configuration/tpm2-session-encryption.md` — **absorbed and deleted** (go-xkms#1147): it documented the removed `EncryptSession` switch and an encrypted-versus-unencrypted comparison that no longer exists; session encryption is unconditional and documented in [`tpm2/engineering.md`](tpm2/engineering.md) §"Bus protection", its capture tests under §"Test strategy" |
| [attestation-verifier](attestation-verifier/) | `attestation/README.md` — **absorbed and deleted** |
| [pkcs11-provider-module](pkcs11-provider-module/) | `pkcs11/module/`, `pkcs11/manager.md` — **absorbed and deleted** (go-xkms#1433); `module/security.md` became `user.md` "Hardening". `references/pkcs11-v3.0-to-v3.2-changes.md` is kept as the spec delta and linked from [`engineering.md`](pkcs11-provider-module/engineering.md#interfaces-and-v32-status) |
| [pkcs11-backend](pkcs11-backend/) | `pkcs11/backend/` (architecture.md, configuration.md, operations.md, runbook.md, security.md, README.md) — **absorbed and deleted** (go-xkms#1433); also corrects that folder's config.Pin/SOPIN description (now `*types.SecretValue`, credential-resolved) and its AttestKey "placeholder" claim (now fully implemented) |
| [certificate-authority](certificate-authority/) | `ca/` (`ca/api-reference.md`, `ca/architecture.md`, `ca/certificate-types.md`, `ca/configuration.md`, `ca/multi-keystore.md`, `ca/protocol-parity.md`, `ca/README.md`) — **absorbed and deleted** (go-xkms#1433): the canonical `Issuer` seam, built-in profiles, the FIDO2 attestation profile, multi-keystore routing, TCG naming and defaults, CA-backed server TLS and the `SignCSR` attestation gate are in [`certificate-authority/engineering.md`](certificate-authority/engineering.md); claims the code no longer supports (a `quantum_safe` build tag, fixed root/intermediate path lengths, the pre-qrdb object-store layout, constructor signatures without `ctx`) were dropped. Also `ca-multi-keystore-design.md`; `architecture/hardware-certificate-storage.md` — **absorbed and deleted** (go-xkms#1433): storage modes, hybrid fallback, per-ID records and the TPM2 NV layout moved to [`certificate-authority/engineering.md`](certificate-authority/engineering.md#hardware-certificate-storage--pkgstoragehardware); its FNV-1a index hash, TPM2 `CreateCertificateStorage`, `HybridStorageInfo`, NV retry loop and performance tables do not match the code and were dropped |
| [trust-bootstrap](trust-bootstrap/) | `trust/`, `bootstrap/`, `configuration/bootstrap.md` — **absorbed and deleted** (go-xkms#1433): the `pkg/trust/resolver` surface, the bootstrap sub-configs and TOFU pin store, the `protocols.noise` listener gate and env overrides are in [`trust-bootstrap/engineering.md`](trust-bootstrap/engineering.md), and the `bootstrap auto --config` resolution in [`trust-bootstrap/cli.md`](trust-bootstrap/cli.md); the client-side `bootstrap.*` YAML, the DANE/SPKI server examples, the first-boot SPKI-pin file and the cross-repo consumer history have no code and were dropped. `ca/bootstrap.md`, `ca/bootstrap-integration.md`, `ca/dane.md` — **absorbed and deleted** (go-xkms#1433): the `pkg/trust/dane` publisher hook and the `bootstrap.noise` listener limits are in [`trust-bootstrap/engineering.md`](trust-bootstrap/engineering.md); their pre-truststrap SDK (`Bootstrapper`, `CABundleRequest`, `pkg/ca/dane`) and error names no longer exist and were dropped |
| [acme-issuance](acme-issuance/) | **absorbed and deleted** (go-xkms#942): `acme/configuration.md`, `acme/quickstart.md`, `acme/implementation-plan.md`, `acme/cli/cactl.md`, `acme/cli/trusted-acme-server.md`, `acme/cli/trusted-acme-client.md`, `acme/cli/README.md`, `acme/deployment/README.md`, `acme/deployment/bare-metal.md`, `acme/deployment/docker.md`, `acme/deployment/monitoring.md`, `acme/deployment/troubleshooting.md` — all pre-merge go-trusted-ca documentation for a `trusted-acme-server`/`cactl` binary pair and `TRUSTEDCA_*`/`CACTL_*` env prefixes that never existed in this repository. **Absorbed and deleted** (go-xkms#1433), the rest of the tree except `acme/gui/`: `acme/README.md` (its JWS algorithm list is now in `api.md`), `acme/admin/` (all five files: the `/admin` routes, query parameters and the library server's gRPC/MCP/Unix authorization moved to `api.md`; its JWT auth, policy engine and routes, response envelope, error-code table, rate-limit headers and config keys were not in the code and were dropped), `acme/api/grpc.md` (described RPCs `api/proto/admin.proto` does not define; dropped), `acme/protocols/` (corrected into `api.md` §"Transport adapters": xkmsd serves the admin plane only as REST; gRPC, QUIC, MCP and Unix exist only on the library `MultiProtocolServer`), `acme/sdk/README.md` (SDK `NewClient` transports in `engineering.md`), `acme/auth/README.md` (`pkg/acme/auth` in `engineering.md`), `acme/audit/README.md` (to [`audit-log/`](audit-log/api.md#acme-audit-trail)), `acme/deployment/operations.md`, `acme/deployment/security.md`, `acme/docker.md` (stale operator checklists naming config keys, images and procedures the code does not have; dropped), `acme/examples/multi-account.yaml` (did not decode against `service.Config`; dropped), and `acme/specs/` (moved to [`references/`](references/README.md), `RFC_8555_COMPLIANCE.md` rewritten as a section-to-code map). **Absorbed and deleted** (go-xkms#1433), each claim re-verified against the code: `acme/architecture.md`, `acme/client.md`, `acme/challenges.md`, `acme/challenge-resolver.md`, `acme/api-reference.md`, `acme/dns-01-providers.md`, `acme/dns-01/` (README and the azure, clouddns, cloudflare and route53 provider pages) — client library, resolver, DNS-01 providers and the client service's `challenge.dns01` keys, http-01 responder, enroll-01 endpoints and finalize bundle in `engineering.md` and `api.md` — and the ACME tenant CA hierarchy and admin tenant routes from `acme/multi-tenancy.md`. Claims the code does not support were dropped. |
| [webauthn](webauthn/) | `webauthn/README.md`, `webauthn/client.md` — **absorbed and deleted** |
| [fido2-ctap2](fido2-ctap2/) | `fido2/README.md`, `fido2/authenticator/architecture.md` — **absorbed and deleted** (go-xkms#1433): the hmac-secret derivation moved to [`fido2-ctap2/engineering.md`](fido2-ctap2/engineering.md); its Quick Start constructors and the `PINCoordinator` / PIN-subscriber design do not exist and were dropped |
| [piv-smartcard](piv-smartcard/) | `piv/README.md`, `piv/certificate-storage-architecture.md`, `piv/tpm2-nv-storage.md` — **absorbed and deleted** (go-xkms#1433): output formats, CA profiles, key-generator resolution, the storage interface, TPM2 NV mapping and the PKCS#11 CKA_ID mapping moved to [`piv-smartcard/engineering.md`](piv-smartcard/engineering.md) and [`api.md`](piv-smartcard/api.md); the pre-implementation storage design (fixed NV indices, file layout, metrics) and the unverified xkey CLI examples were dropped, and the feature folder's own `GetNVIndex` claims were corrected |
| [auth-factors](auth-factors/) | `auth/factors.md`, `auth/layering.md` — **absorbed and deleted** (go-xkms#1433): the `auth factor` / `auth login` CLI and the SDK login plane moved to [`auth-factors/cli.md`](auth-factors/cli.md) and [`api.md`](auth-factors/api.md); the layering split is in [`rbac/`](rbac/), [`init-ceremony/`](init-ceremony/) and [`certificate-authority/`](certificate-authority/); the obsolete qrdb registry sample and wrong CLI flags were dropped; `configuration/auth.md` (client-side mTLS flags and PKCS#11 client certificates) — **absorbed and deleted** (go-xkms#1433); see the [xkmsd-configuration](xkmsd-configuration/) row |
| [pin-management](pin-management/) | `pin/` — **absorbed and deleted** (go-xkms#1433): the `PlatformAuthProvider` contract and the TPM2 backend's PIN-length, auth-failure, lockout-error and FIDO2-hash behaviour moved to [`pin-management/engineering.md`](pin-management/engineering.md); its software backend, `HashConfig`, `PINRecord`, PIN service and sentinel list are go-qrdb's and were dropped; `architecture/pin-architecture.md` — **absorbed and deleted** (go-xkms#1433): its `PINCoordinator`/`pkg/pin` design has no code and was dropped; the real `UnifiedPIN` FIDO2 link is noted in [`pin-management/architecture.md`](pin-management/architecture.md); `seal/pin.md` — **absorbed and deleted** (go-xkms#1433): its Platform SRK enrollment, auth-readiness and dictionary-attack facts moved to [`pin-management/engineering.md`](pin-management/engineering.md); its software backend, hashing and `pkg/pin` API were go-qrdb's or no longer exist |
| [sealing-and-barrier](sealing-and-barrier/) | `seal/README.md`, `seal/api.md`, `seal/pcr-policies.md` — **absorbed and deleted** (go-xkms#1433): the `PlatformSealer` contract moved to [`sealing-and-barrier/engineering.md`](sealing-and-barrier/engineering.md); the barrier internals, Shamir, recovery and the `/api/v1/barrier/*` routes are go-qrdb's, and named PCR policies are [`tpm-policies/`](tpm-policies/). `seal/barrier.md` — **absorbed and deleted** (go-xkms#707): its layered LUKS+barrier architecture, the `pkg/storage/luks.Backend` gate, and barrier auto-unseal content are now covered by [`../xkey/docs/luks/architecture.md`](../xkey/docs/luks/architecture.md) §"The gate: `pkg/storage/luks.Backend`", [`../xkey/docs/seal/`](../xkey/docs/seal/) (policy-based barrier auto-unseal), [`../xkey/docs/setup-wizard/`](../xkey/docs/setup-wizard/) (the GUI's separate LUKS-volume TPM auto-unseal, `BarrierAutoUnsealBlobID`), and [`../xkey/docs/password/`](../xkey/docs/password/) (static-password-behind-the-barrier layering) — re-verified against all four for this pass; `architecture/barrier-integration.md` — **absorbed and deleted** (go-xkms#1433): `BarrierConfig` and the strategy constructors moved to [`sealing-and-barrier/engineering.md`](sealing-and-barrier/engineering.md); the epoch/storage barrier internals and the barrier servicer table are go-quicraft's and go-qrdb's, and its claim that an omitted `PreferenceOrder` falls back to a default was false; `sealed-storage/` — **absorbed and deleted** (go-xkms#1433): the `pkg/storage/sealed` decorator moved to [`sealing-and-barrier/engineering.md`](sealing-and-barrier/engineering.md); its passthrough `Scan`, eight-sealer table and constructor examples did not match the code and were dropped |
| [init-ceremony](init-ceremony/) | `init/ceremony.md`, `init/roles.md`, `init/threshold.md`, `init/README.md`, `auth/bootstrap.md` — **deleted**; the M-of-N officer ceremony they described was removed (go-qrdb holder/quorum model) |
| [backend-credentials](backend-credentials/) | `init/credentials.md` — **absorbed and deleted** (go-xkms#1450). It had been filed as cross-cutting, but it documents one feature. Its per-strategy `credentials.<strategy>.*` config blocks, `CredentialSealer` interface, `Enter User PIN:` prompt and `storage.backend: qrdb` precondition never matched the code, and it presented `pkcs11`, `vault` and `passphrase` as working when `xkmsd` refuses all three at startup |
| [multi-tenancy](multi-tenancy/) | `architecture/multi-tenant.md` — **absorbed and deleted** (go-xkms#1433): the `pkg/api/tenantgate` decision and its per-transport mapping moved to [`multi-tenancy/engineering.md`](multi-tenancy/engineering.md); its `staticpw` tenant DAO factory, `BuildTenantInfra`, `BarrierRegistryAccessor` and OU-based tenant extraction do not exist and were dropped; `seal/tenant-barriers.md` — **absorbed and deleted** (go-xkms#1433): its default volume-pool path moved to [`multi-tenancy/engineering.md`](multi-tenancy/engineering.md); its `BarrierRegistry`/`TenantBarrier` tables are go-qrdb's, and `TenantBarrierConfig` is read by nothing; `acme/multi-tenancy.md` — **absorbed and deleted** (go-xkms#1433): its ACME tenant CA hierarchy and admin routes went to [`acme-issuance/`](acme-issuance/engineering.md#acme-tenant-ca-hierarchy) |
| [escrow](escrow/) | `escrow/README.md` — **absorbed and deleted** |
| [password-vault](password-vault/) | `staticpw/README.md`, `staticpw/teams.md` — **absorbed and deleted** (go-xkms#1433): key layout, entry IDs, `ScopedStore` routing, the generator, `ExpiryChecker` and the team store's member semantics moved to [`password-vault/engineering.md`](password-vault/engineering.md). Its tenant-level unlock API, `TeamScopedStore`, per-tenant DAO factory, `/v1/teams` routes and team RBAC no longer exist, and its "ID is the lowercase path" claim was wrong; all were dropped |
| [platform-secrets](platform-secrets/) | `platform-store/README.md` — **absorbed and deleted** (go-xkms#1433): the `platform-store/` key prefix, well-known secret names, lock granularity and constructor/name errors moved to [`platform-secrets/engineering.md`](platform-secrets/engineering.md); its example and links to pages that do not exist were dropped |
| [post-quantum](post-quantum/) | `architecture/post-quantum-cryptography.md` — **absorbed and deleted** (go-xkms#1433): every true claim was already in the folder; its performance figures, nonce-tracking flow, "ML-KEM-512 unsupported" and hybrid-signature claims were false or unverified and were dropped; `backends/quantum.md` — **absorbed and deleted** (go-xkms#1433): ML-DSA/ML-KEM, the AEAD tracker and the configuration it described were already in the feature folder; its key and signature size tables and performance figures are not in the code and were dropped |
| [symmetric-aead](symmetric-aead/) | `architecture/symmetric-encryption.md`, `configuration/aead-auto-selection.md`, `configuration/symmetric-encryption.md`, `configuration/aead-bytes-tracking.md` — absorbed and deleted (go-xkms#1433); `crypto/kdf.md` stays as the cross-cutting KDF reference |
| [audit-log](audit-log/) | `acme/audit/README.md` — **absorbed and deleted** (go-xkms#1433): the `acme.audit` config and `GET /admin/audit` are in [`audit-log/engineering.md`](audit-log/engineering.md#acme-audit-trail) and [`audit-log/api.md`](audit-log/api.md#acme-audit-trail) |
| [luks](luks/) | — |
| [signing](signing/) | `verification/` — **absorbed and deleted** (its `ChecksumProvider` was never wired to a live verifier; superseded by `types.ChecksumProvider`) |
| [ssh-agent-sessions](ssh-agent-sessions/) | — (new surface; supersedes nothing) |
| [ssh-keys](ssh-keys/), [ssh-sessions](ssh-sessions/) | `ssh/README.md` — **absorbed and deleted** (go-xkms#1433), together with [ssh-agent-sessions](ssh-agent-sessions/) and [`../xkey/docs/ssh/`](../xkey/docs/ssh/): the cross-transport error table moved to [`ssh-keys/engineering.md`](ssh-keys/engineering.md), and the console wire protocol and host-key policy to [`ssh-sessions/engineering.md`](ssh-sessions/engineering.md); its MCP `wire.Code` column and GUI badge notes were not re-verified and were dropped |
| [user-onboarding](user-onboarding/) | — (new surface; supersedes nothing) |
| [host-embedding](host-embedding/) | `architecture/server-architecture.md` §"Unified API Server" — **absorbed and deleted** (go-xkms#1433): module registration on each transport, unified-server TLS and the composition roots moved to [`host-embedding/engineering.md`](host-embedding/engineering.md); its service-layer types (`KeyManager`, `BackendRegistry`), per-transport servers and route/RPC listings no longer exist and were dropped. `architecture/correlation-ids.md` — **absorbed and deleted** (go-xkms#1433): ID generation and middleware placement moved there; its context-logging adapter, log field name and benchmark figures were dropped |
| [xkmsd-configuration](xkmsd-configuration/) | `architecture/server-architecture.md` §"Configuration Management" — **absorbed and deleted** (go-xkms#1433): the network-serving requirement moved to [`xkmsd-configuration/engineering.md`](xkmsd-configuration/engineering.md); its YAML example and `XKMS_REST_ADDRESS`-style names never existed; `configuration/auth.md` — **absorbed and deleted** (go-xkms#1433): `auth.type`, `tls.client_auth` and the client-CA pool are in [`xkmsd-configuration/engineering.md`](xkmsd-configuration/engineering.md#authentication-and-client-certificate-settings), the storeless mTLS identity and admin cert binding in [rbac](rbac/), client flags in [auth-factors](auth-factors/); its adaptive authenticator, OIDC `auth.type`, `watch_cert_files` reload and certificate workflow (`xkmsctl key create`, `cert create --is-ca`, …) do not exist and were dropped |
| [clustering](clustering/) | `cluster/` (`cluster/README.md`, `cluster/ca-key-custody.md`) — **absorbed and deleted**. The legacy `README.md`'s `/api/v1/cluster/*` REST routes and `admin:add_member`/`admin:remove_member` permissions described a proxy plane that was since deleted; `ca-key-custody.md` is retained as a companion deep-dive, now [`clustering/ca-key-custody.md`](clustering/ca-key-custody.md), linked from [`clustering/architecture.md`](clustering/architecture.md). A separate `docs/cluster/` five-file folder landed briefly (go-xkms#847, the read-only REST cluster status/membership surface for the web console) and duplicated this one; it was merged into `clustering/` in the same pass rather than kept as two folders for one feature. |
| [rbac](rbac/) | `architecture/rbac.md` — **absorbed and deleted** (go-xkms#1433): every true claim was already in the folder; its `storage.backend: "qrdb"` precondition, `ssh:use` permission and audit-chain claim no longer match the code and were dropped; `configuration/auth.md` (storeless mTLS identity, public methods, admin cert binding) — **absorbed and deleted** (go-xkms#1433); see the [xkmsd-configuration](xkmsd-configuration/) row |
| [datastore](datastore/) | `storage/README.md` — **absorbed and deleted** (go-xkms#1433): `pkg/storage.OpenEngine`'s engine kinds and errors moved to [`datastore/engineering.md`](datastore/engineering.md), and xkmsctl's `--storage-path`/`XKMS_STORAGE_PATH` to [`datastore/cli.md`](datastore/cli.md). Its `storage:` config block, `~/.xkms/data` default, performance table and provider build tags match no code and were dropped; its `objstore` backend is not reachable through `xkmsd`'s own datastore. Also supersedes this repo's own now-deleted `storage-engines/` folder (go-xkms#1345): the old per-subsystem `storage.backend` (file/pebble/memory as private, unreplicated alternatives to `qrdb`) was replaced by one global, always-qrdb-backed `datastore.engine`/`datastore.mode`. `architecture/storage.md`, `architecture/dao-integration.md`, `architecture/dao-storage.md`, `architecture/objstore-integration.md` — **absorbed and deleted** (go-xkms#1433): guarded writes, the KV adapter and the entity layer moved to [`datastore/engineering.md`](datastore/engineering.md); their store lists, `UnitOfWork`, `TenantDAOFactory`, `storage.backend` config, old `Scan` signature, performance table and S3/Azure/GCS examples do not match the code and were dropped |
| [web-console](web-console/) | `web/` (`README.md`, `parity.md`, `running.md`, `screens.md`, `testing.md`) — **absorbed and deleted** (go-xkms#1433), each claim re-verified against the code: the `ui:`/`cors:`/`auth.piv_login:`/`auth.session:` keys went to [`web-console/user.md`](web-console/user.md), the per-entry RBAC/capability gates and signed-out routes to [`web-console/api.md`](web-console/api.md), the Playwright tier internals and the native-`<dialog>` modal to [`web-console/engineering.md`](web-console/engineering.md). Dropped: the Barrier & Seal, Audit, Custodians, Shares and Init Ceremony screens, the `#/policies` route and `ssh:use` gate, the barrier/audit live spec and the `/health` readiness wait — none exist in `web/app` or `test/integration/web` |

Several of these need a note rather than a row:

- **`architecture/pin-architecture.md`** and **`fido2/authenticator/architecture.md`**,
  both absorbed and deleted (go-xkms#1433), described a `PINCoordinator` and a
  `pkg/pin` package. **Neither exists in this repository.**
  [`pin-management/architecture.md`](pin-management/architecture.md) documents
  what does — `pkg/pinselect` and `pkg/pintpm2` — and says so explicitly.
- **`acme/cli/cactl.md`** documented a binary that was never in this
  repository and whose project has been retired; it, and the rest of
  `acme/cli/`, were deleted by go-xkms#942 — see
  [`acme-issuance/cli.md`](acme-issuance/cli.md).
- **What remains of `acme/`.** Everything except three things was absorbed
  and deleted by go-xkms#942 and go-xkms#1433 (see the table above):
  - `acme/gui/` is still legacy: the dual-mode admin+client SPA,
    `pkg/acme/gui/{admin,client,guard,webui}`. go-xkms#942 corrected its
    `cactl`/`trusted-acme-server`/`TRUSTEDCA_*` references in place. The
    admin web UI xkmsd actually serves is a separate implementation,
    `pkg/acme/web/packages/admin` at `/admin-ui` (`cmd/xkmsd/admin.go:54`);
    reconciling the two is unresolved.
  - `acme/ROADMAP.md` is kept on purpose (see "Roadmaps stay out" below).
  - `acme/boulder-comparison-enhancements.md` is kept on purpose as a
    reference ([`acme-issuance/architecture.md`](acme-issuance/architecture.md)
    cites it directly).
- **`ca/dane.md`, `ca/bootstrap.md` and `ca/bootstrap-integration.md` —
  absorbed and deleted** (go-xkms#1433). Generic DNSSEC and TLSA background
  that made no claim about this code was not carried over; the record fields
  go-xkms uses are in
  [`trust-bootstrap/engineering.md`](trust-bootstrap/engineering.md)
  §"Exported surface — `pkg/trust/dane`". Their "Using the Go API" and "API
  Reference" sections (`pkg/ca/dane`, `Bootstrapper`, `CABundleRequest`,
  `CABundleResponse`) described a package and SDK shape that no longer exist.
- **`cli/barrier.md` — deleted**: `xkmsctl barrier` was removed (go-qrdb owns the barrier surface).
- **`cli/trust-platform.md` — absorbed and deleted** (this pass). It split
  three ways, across two modules: the `xkey browser launch` section (NSS
  `cert9.db` via `xkey/pkg/nssdb`, Firefox `policies.json` overlay) is
  covered by
  [`../xkey/docs/browser-trust-injection/`](../xkey/docs/browser-trust-injection/)
  (`cli.md`'s `xkey browser launch` section, `user.md`'s `~/.pki/nssdb` and
  shared-mode-Firefox notes); the `xkey trust bootstrap` walkthrough by
  [`trust-bootstrap/`](trust-bootstrap/); and the `xkey trust fetch <url>
  --spki-pin`/`xkey trust import-platform <host:port> --spki-pin`
  walkthrough, the "Security model" three-path table, the "out-of-band"
  SPKI-pin sourcing guidance, and the WebAuthn-login handoff, by
  [`../xkey/docs/platform-trust/`](../xkey/docs/platform-trust/) — `cli.md`
  now documents `fetch`/`import-platform` (defined in the separate file
  `xkey/cmd/xkey/cmd/trust_fetch.go`, verified against
  `trust_fetch_test.go`'s flag-name assertions) alongside the rest of the
  `trust` group, `user.md` carries the out-of-band sourcing guidance and a
  pointer to `headless-webauthn/user.md` for the login handoff, and
  `architecture.md`/`api.md` correct the endpoint the legacy file got wrong
  — it was `GET /api/v1/ca/bundle`; both verbs actually hit the public,
  unauthenticated `GET /v1/ca/bootstrap` via a separate `pkg/trust/fetcher`
  package, not `pkg/trust/bootstrap`'s dispatch chain.
- **`attestation/README.md` — absorbed and deleted** (this pass). The
  "PKCS#11 HSM attestation" gap an earlier version of this note described was
  already closed by
  [`pkcs11-backend/architecture.md`](pkcs11-backend/architecture.md)
  §"Attestation: fully implemented, corrects a stale claim"
  (`AttestKey`, `pkg/backend/pkcs11/attestation.go:296`), and `tpm2/`
  documents TPM 2.0 attestation from the TPM side. The piece that remained —
  the **generic, backend-agnostic** `pkg/attestation` API
  (`attestation.Verifier`/`NewVerifier`,
  `VerifyOptions`/`DefaultVerifyOptions`/`InsecureVerifyOptions`,
  `VerifyInvariants`/`Evidence`, and the `pkg/config.AttestationConfig` +
  `pkg/xkms.SetAttestationVerifiers` wiring that gates CSR issuance on it) —
  is now [`attestation-verifier/`](attestation-verifier/), which also covers
  a second production call site the legacy file never mentioned:
  `pkg/ca/tcg.go`'s TCG-CSR-IDEVID enrollment path calls the same
  `VerifyInvariants` directly, for the TPM2 format. The legacy file's own Go
  code samples were additionally stale and are **not** reproduced in the new
  folder: `tpm2.NewTPM2KeyStore` and `types.AttestingBackend` do not exist
  anywhere in the tree; the real generation method is
  `(*Backend).AttestKey(ctx, attrs, nonce)` on both `pkg/backend/tpm2` and
  `pkg/backend/pkcs11`, behind the real interface `types.AttestingKeyProvider`
  (`pkg/types/types.go:1805`), already documented in
  [`key-management/`](key-management/).
- **`crypto/kdf.md` is not superseded** by `key-management/`, which
  mentions the KDF algorithm names as CLI flag values and error types but
  not the approved-hash-per-algorithm table, the SP 800-108 fixed-input and
  counter-placement construction, parameter-applicability enforcement, the
  wire-to-KDF-parameter mapping, or the SP 800-108/HKDF breaking-change
  migration note — all verified still current against `pkg/crypto/kdf` and
  `pkg/types/kdf.go`.

### Still owed a feature folder

**Nothing, as of go-xkms#707 (2026-09-24).** The 2026-10-11 docs audit found
shipped features without a folder after all, and those are being converted
one issue at a time. Each one is added to the table below as it lands. Every area this
section used to list has since been converted; the table below is kept as
a record of where each one landed, not as an open queue. Before adding a
new row here, re-run the derivation loop at the top of this file and
check the top "Feature documentation" table first — several rows below
were stale (already converted, sometimes in a different repository
module) by the time they were re-verified for this pass.

| Area (formerly listed as owed) | Now converted at |
|---|---|
| Post-quantum | [`post-quantum/`](post-quantum/) |
| Symmetric encryption / AEAD | [`symmetric-aead/`](symmetric-aead/) |
| FROST threshold signatures | [`frost-threshold-signing/`](frost-threshold-signing/) (full absorption — the legacy `frost/` folder was re-verified against source and deleted, go-xkms#1433) |
| SSH key management | [`ssh-keys/`](ssh-keys/), [`ssh-agent-sessions/`](ssh-agent-sessions/), and [`ssh-sessions/`](ssh-sessions/) together — see the note below |
| PKCS#11 **backend** (consuming a token) | [`pkcs11-backend/`](pkcs11-backend/) |
| Web console | [`web-console/`](web-console/) |
| Clustering | [`clustering/`](clustering/) |
| RBAC | [`rbac/`](rbac/) |
| Browser trust injection | [`../xkey/docs/browser-trust-injection/`](../xkey/docs/browser-trust-injection/) — converted, but in the xkey module; see the note below |
| LUKS | [`luks/`](luks/) |
| Datastore | [`datastore/`](datastore/) |
| Backend credentials (found missing by the 2026-10-11 audit, go-xkms#1450) | [`backend-credentials/`](backend-credentials/) |

- **SSH** — [`ssh-keys/`](ssh-keys/) is NORMATIVE for SSH keys,
  known-hosts, and authorized-keys (plus the backend bridge and the
  shared key-ID layout). [`ssh-agent-sessions/`](ssh-agent-sessions/) is
  NORMATIVE for hostless agent-only signing sessions.
  [`ssh-sessions/`](ssh-sessions/) (go-xkms#707) is NORMATIVE for
  interactive console sessions, the `xkey` connection-profile manager,
  session history, and local `ssh_config`/agent discovery
  (`pkg/ssh/{console,connect,session,sessions,profile,local}`). Between the
  three, every subpackage of `pkg/ssh` has a NORMATIVE home, so the legacy
  `ssh/README.md` was absorbed into them and deleted (go-xkms#1433).

Browser trust injection is converted, but the code and its folder live in the
xkey module, not here — see
[`../xkey/docs/browser-trust-injection/`](../xkey/docs/browser-trust-injection/)
and the superseded-path row in `xkey/docs/README.md`. That folder also
covers `xkey browser launch`'s NSS `cert9.db` and Firefox `policies.json`
mechanics — one of the three pieces `cli/trust-platform.md` (deleted this
pass) split into; see the "absorbed and deleted" note above (§"Legacy paths
superseded") for the other two. The legacy `browser/README.md` in *this*
tree was absorbed into that folder and deleted (go-xkms#1433).

### Cross-cutting, and never getting a folder

[`architecture/`](architecture/), [`configuration/`](configuration/),
[`deployment/`](deployment/), [`development/`](development/),
[`testing/`](testing/), [`fips/`](fips/),
[`crypto/weak-hashes.md`](crypto/weak-hashes.md) — cross-cutting design,
build, operational and contributor documentation, not features.

**Roadmaps stay out of feature folders.** Feature folders document what *is*.
`ROADMAP.md`, `ROADMAP-bootstrap.md`, `tpm-refactor-roadmap.md`,
`cli-gui-parity.md`, `acme/ROADMAP.md` and `pkcs11/ROADMAP.md` are future work
and stay where they are.

**Operator checklists.** `pkcs11/module/security.md` became
[`pkcs11-provider-module/user.md`](pkcs11-provider-module/user.md#hardening)
§"Hardening" (go-xkms#1433). The ACME checklists (`acme/deployment/security.md`,
`acme/deployment/operations.md`, `acme/admin/configuration.md`) were
re-verified by go-xkms#1433; they named config keys, images and procedures the
code does not have, and were deleted rather than absorbed.

## Documentation Structure

### [Architecture](architecture/)
Core architectural concepts, design patterns, and technical specifications:
- [Overview](architecture/overview.md) - System architecture and design philosophy
- [API Specifications](architecture/api-specifications.md) - API design and interface contracts
- [RBAC](rbac/architecture.md) - Role-based access control

### [Backends](crypto-backends/)
The `Backend` contract, the capability matrix and each backend's configuration:
- **All backends**: [Crypto Backends](crypto-backends/) (software, PKCS#8, cloud KMS, Vault — [per-backend configuration](crypto-backends/engineering.md#per-backend-configuration))
- **Hardware**: [TPM 2.0](tpm2/), [PKCS#11](pkcs11-backend/) (including Nitrokey HSM)
- **Quantum**: [Post-Quantum Cryptography](post-quantum/)

### [Configuration](configuration/)
Configuration guides for various components:
- [Build toggles](crypto-backends/engineering.md#build-toggles) - Build tags and compilation options
- [TPM2 Session Encryption](tpm2/engineering.md#bus-protection) - TPM session security

### [Trust Bootstrap](trust-bootstrap/)
Converted to the five-file feature layout — see [Feature documentation](#feature-documentation) below.
- [Engineering](trust-bootstrap/engineering.md) - `pkg/trust/bootstrap` modes and `Fetch`, the `pkg/trust/resolver` scope chain, the Noise bootstrap listener's configuration

### [Init](init-ceremony/)
First-boot server initialization ceremony. Backend credential seal strategies
are now [backend-credentials](backend-credentials/).

### [Auth factors](auth-factors/)
Converted to the five-file feature layout — see [Feature documentation](#feature-documentation) below.
- [Architecture](auth-factors/architecture.md) - Identity (qrdb) vs key-domain (xkms) split, factor registration

### [WebAuthn](webauthn/)
Converted to the five-file feature layout — see [Feature documentation](#feature-documentation) below.
- [Architecture](webauthn/architecture.md) - Canonical RP implementation consumed by every binary in the stack via the QuicBaaS SDK re-export
- [Engineering](webauthn/engineering.md) - Exported surface, ceremony invariants, the headless client used by `xkmsctl` and tests

### [PIN](pin-management/)
- [Engineering](pin-management/engineering.md) - backend selection (`pkg/pinselect`), the TPM2 backend (`pkg/pintpm2`) and the Platform SRK

### [Sealing and Barrier](sealing-and-barrier/)
- [Architecture](sealing-and-barrier/architecture.md) - qrdb owns the barrier and StrategyRegistry; xkms owns every hardware/cloud strategy

### [Usage](../xkey/docs/usage/)
CLI usage guides and tutorials have moved to [xkey/docs/usage/](../xkey/docs/usage/README.md).

### [xKey Application](../xkey/docs/)
xKey is the desktop GUI and CLI application built on go-xkms. All xKey documentation (setup wizard, auto-unseal, FIDO2 daemon, enterprise mode, password management, etc.) lives in [xkey/docs/](../xkey/docs/README.md).

### [Testing](testing/)
Testing documentation and best practices:
- [Integration Tests](testing/integration-tests.md) - End-to-end testing guide
- [Docker Testing](testing/docker-testing.md) - Isolated test environments

### [Deployment](deployment/)
Deployment guides and production configurations:
- [Docker Deployment](deployment/docker.md) - Complete Docker deployment guide
- [Docker Quick Start](deployment/docker-quickstart.md) - 5-minute Docker setup

### Sealed storage and credentials
Encrypted-at-rest storage and credential management:
- [Sealed value decorator](sealing-and-barrier/engineering.md) - `pkg/storage/sealed`, transparent value encryption via `types.Sealer`
- [Platform Secrets](platform-secrets/architecture.md) - Named-secret store over a sealed backend
- [Password Vault](password-vault/architecture.md) - Password manager with per-user vaults and tenant sharing

### [FIPS 140](fips/)
FIPS compliance and algorithm selection:
- [FIPS Strategy](fips/README.md) - crypto/fips140.Enabled mode detection, build provenance, KDF selection, and PasswordHasher

### [Development](development/)
Development and contributor documentation:
- [Encoding Interop Status](development/encoding-interop-status.md) - JWK/JWT/JWE test implementation status

## Quick Start

The simplest way to get started is with `AutoInitialize`, which discovers all compiled-in backends and sets them up automatically:

```go
import (
    "crypto/elliptic"
    "crypto/x509"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    // See what backends are compiled in
    fmt.Println("Available backends:", xkms.SupportedBackends())

    // Auto-initialize all compiled-in backends with defaults
    if err := xkms.AutoInitialize(nil); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Generate a key using the service API
    key, err := xkms.GenerateKey(&types.KeyAttributes{
        CN:           "my-signing-key",
        StoreType:    types.BackendType("software"),
        KeyAlgorithm: x509.ECDSA,
        ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Sign data
    sig, err := xkms.Sign("software:::my-signing-key", []byte("hello"), nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %x\n", sig)
}
```

For client/server deployments, use the Go SDK:

```go
import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

client, _ := xkms.NewFromURL("https://localhost:8443")
defer client.Close()
client.Connect(ctx)

resp, _ := client.GenerateKey(ctx, &xkms.GenerateKeyRequest{
    KeyID:   "my-key",
    Backend: "software",
    KeyType: "EC",
    Curve:   "P-256",
})
```

See the [Getting Started](../xkey/docs/usage/getting-started.md) guide for all initialization patterns.

## Key Features

- **Unified Interface**: Single API across all backends
- **Auto-Discovery**: Registry auto-discovers compiled-in backends at startup
- **Multiple Backends**: Support for file, HSM, TPM, and cloud storage
- **Key Types**: RSA, ECDSA, Ed25519, AES
- **Standards Compliant**: PKCS#8, PKCS#11, TPM 2.0, JWK, JWT
- **Certificate Management**: X.509 certificate lifecycle management
- **High Performance**: Lock-free algorithms, optimized for low latency
- **Type Safe**: No pointer magic or unsafe operations
- **Well Tested**: 90%+ code coverage with meaningful tests

## Examples

See the `examples/` directory for complete working examples:

- `examples/basic/` - Basic key operations
- `examples/certificates/` - Certificate management
- `examples/signing/` - Digital signatures
- `examples/symmetric-encryption/` - Symmetric encryption
- `examples/tls/` - TLS client and server
- `examples/advanced/` - Advanced patterns

## Building

```bash
# Build with all backends
make build

# Build with specific backends
go build -tags="pkcs11 tpm2" ./...

# Run tests
make test

# Run integration tests
make integration-test
```

## Contributing

There is no `CONTRIBUTING.md` yet. The contribution guidelines currently live in
the [Contributing section of the root README](../README.md#contributing), and the
coding, testing, and documentation rules agents and contributors must follow are
in [CLAUDE.md](../CLAUDE.md).

## License

Copyright (c) 2025 Jeremy Hahn. Licensed under the AGPL-3.0 License.
