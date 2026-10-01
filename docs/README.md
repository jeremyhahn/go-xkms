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
| [attestation-verifier](attestation-verifier/) | The generic, backend-agnostic `pkg/attestation` API — chain/signature verification (`Verifier`) and per-format key-binding invariants (`VerifyInvariants`) — that gates CSR issuance on hardware provenance for any format, TPM2/PIV/Android included |
| [attested-peer](attested-peer/) | Is the other end of a connection a currently attested system? The quote→verdict primitive, IDevID/IAK credential validation, and TLS channel binding |
| [audit-log](audit-log/) | Tamper-evident audit records and their signing chain |
| [auth-factors](auth-factors/) | Factor composition, adapters, and the identity/key-domain split |
| [avr-device-backend](avr-device-backend/) | An AVR device with a secure-element identity as an xkms key provider and DICE attester, over the arduino-generic wire protocol |
| [certificate-authority](certificate-authority/) | `TrustedCA` — cross-signed root pool, AIA import, DANE TLSA publishing |
| [clustering](clustering/) | Embedding a go-qrdb clustered node behind the `raft` build tag: Raft config mapping, inter-node mTLS provisioning, not-leader redirects, the `xkmsctl cluster`/`rebalance` control plane, the read-only REST cluster status/membership surface for the web console, and cluster CA key custody |
| [crypto-backends](crypto-backends/) | The `Backend` contract and every software, hardware and cloud implementation |
| [datastore](datastore/) | The single global, qrdb-backed datastore every xkms subsystem stores through: the `storage.Backend` interface, `datastore.engine` (memory/file/pebble) and `datastore.mode` (standalone/remote) configuration, and why there is no per-subsystem storage choice left |
| [dice-device-identity](dice-device-identity/) | DICE-based device identity with a hardware root of trust: the TCG DICE certificate extensions, their verification, and the `dice-idevid` issuance profile |
| [escrow](escrow/) | External key escrow (KMIP + xkms federation): the agent factory, daemon config, and service layer — reachable today only through the embedded Go SDK, pending an RBAC vocabulary decision for the network transports |
| [fido2-ctap2](fido2-ctap2/) | The canonical FIDO2 CTAP2 implementation |
| [frost-threshold-signing](frost-threshold-signing/) | RFC 9591 FROST threshold signing (`-tags frost`) — trusted-dealer keygen, the explicit round API, and why the CLI's local path and the REST/gRPC/MCP network surface are independent |
| [host-embedding](host-embedding/) | Mounting the `xkms` ServiceModule in a qrdb-embedding host: the host supplies dependencies (qrdb client, barrier registry, PIN backend, sealer, CA config, PCR reader), `pkg/compose` builds the Password Manager, SSH, CA, platform store, credential and policy stores through the same path as `xkmsd`, and the barrier routes stay the host's unless it opts in |
| [init-ceremony](init-ceremony/) | `xkmsd init` — the KMS+CA half and the delegated IAM half |
| [key-management](key-management/) | Key lifecycle, key providers, symmetric and asymmetric operations |
| [luks](luks/) | The root module's `pkg/luks`: FIPS-aware LUKS volume lifecycle (`Manager`/`Executor`) and TPM 2.0 passphrase sealing (`TPMSealer`); `xkey`'s own LUKS2 implementation is documented separately in `xkey/docs/luks/` |
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
| [sealing-and-barrier](sealing-and-barrier/) | Hardware and cloud seal strategies contributed to the qrdb barrier |
| [share-custody](share-custody/) | Shamir share custody, custodian groups and share collection |
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
— `docs/acme/`, `docs/ca/`, `docs/frost/`, `xkey/docs/ble/`, `xkey/docs/gui/` —
already contain a file called `architecture.md`, so the shorter form overcounts
by five and reports unconverted folders as converted.

### Legacy paths superseded by a feature folder

| Feature folder | Legacy paths it supersedes |
|---|---|
| [key-management](key-management/) | `architecture/unified-keyid-jwk-integration.md`, `key-agreement.md` |
| [crypto-backends](crypto-backends/) | `backends/` |
| [tpm2](tpm2/) | `configuration/tpm2-session-encryption.md` — **absorbed and deleted** (go-xkms#1147): it documented the removed `EncryptSession` switch and an encrypted-versus-unencrypted comparison that no longer exists; session encryption is unconditional and documented in [`tpm2/engineering.md`](tpm2/engineering.md) §"Bus protection", its capture tests under §"Test strategy" |
| [attestation-verifier](attestation-verifier/) | `attestation/README.md` — **absorbed and deleted** |
| [pkcs11-provider-module](pkcs11-provider-module/) | `pkcs11/module/`, `references/pkcs11-v3.0-to-v3.2-changes.md`, `pkcs11/manager.md` |
| [pkcs11-backend](pkcs11-backend/) | `pkcs11/backend/` (architecture.md, configuration.md, operations.md, runbook.md, security.md, README.md) — also corrects that folder's config.Pin/SOPIN description (now `*types.SecretValue`, credential-resolved) and its AttestKey "placeholder" claim (now fully implemented) |
| [certificate-authority](certificate-authority/) | `ca/`, `ca-multi-keystore-design.md`, `architecture/hardware-certificate-storage.md` |
| [trust-bootstrap](trust-bootstrap/) | `trust/`, `bootstrap/`, `configuration/bootstrap.md` |
| [certificate-authority](certificate-authority/) | `ca/api-reference.md`, `ca/architecture.md`, `ca/certificate-types.md`, `ca/configuration.md`, `ca/multi-keystore.md`, `ca/protocol-parity.md`, `ca/README.md`, `ca-multi-keystore-design.md`, `architecture/hardware-certificate-storage.md` |
| [acme-issuance](acme-issuance/) | **absorbed and deleted** (go-xkms#942): `acme/configuration.md`, `acme/quickstart.md`, `acme/implementation-plan.md`, `acme/cli/cactl.md`, `acme/cli/trusted-acme-server.md`, `acme/cli/trusted-acme-client.md`, `acme/cli/README.md`, `acme/deployment/README.md`, `acme/deployment/bare-metal.md`, `acme/deployment/docker.md`, `acme/deployment/monitoring.md`, `acme/deployment/troubleshooting.md` — all pre-merge go-trusted-ca documentation for a `trusted-acme-server`/`cactl` binary pair and `TRUSTEDCA_*`/`CACTL_*` env prefixes that never existed in this repository. `acme/admin/configuration.md`, `acme/deployment/operations.md` (the retained operator checklists), `acme/gui/*` and `acme/protocols/*` were corrected in place instead of deleted — see the note below. A previous pass of this row claimed `acme/architecture.md`, `acme/client.md`, `acme/challenges.md`, `acme/challenge-resolver.md` were also absorbed and deleted; they are still present in the tree and that claim does not hold — see the note below. |
| [trust-bootstrap](trust-bootstrap/) | `trust/`, `bootstrap/`, `configuration/bootstrap.md` |
| [webauthn](webauthn/) | `webauthn/README.md`, `webauthn/client.md` — **absorbed and deleted** |
| [fido2-ctap2](fido2-ctap2/) | `fido2/README.md` |
| [piv-smartcard](piv-smartcard/) | `piv/` |
| [auth-factors](auth-factors/) | `auth/factors.md`, `auth/layering.md` |
| [pin-management](pin-management/) | `pin/`, `seal/pin.md`, `architecture/pin-architecture.md` |
| [sealing-and-barrier](sealing-and-barrier/) | `seal/` (except `seal/tenant-barriers.md`, superseded by `multi-tenancy` below), `seal/barrier.md` — **absorbed and deleted** (go-xkms#707): its layered LUKS+barrier architecture, the `pkg/storage/luks.Backend` gate, and barrier auto-unseal content are now covered by [`../xkey/docs/luks/architecture.md`](../xkey/docs/luks/architecture.md) §"The gate: `pkg/storage/luks.Backend`", [`../xkey/docs/seal/`](../xkey/docs/seal/) (policy-based barrier auto-unseal), [`../xkey/docs/setup-wizard/`](../xkey/docs/setup-wizard/) (the GUI's separate LUKS-volume TPM auto-unseal, `BarrierAutoUnsealBlobID`), and [`../xkey/docs/password/`](../xkey/docs/password/) (static-password-behind-the-barrier layering) — re-verified against all four for this pass, `sealed-storage/`, `architecture/barrier-integration.md` |
| [init-ceremony](init-ceremony/) | `init/`, `auth/bootstrap.md` |
| [share-custody](share-custody/) | `custodian/`, `sharestore/` |
| [multi-tenancy](multi-tenancy/) | `architecture/multi-tenant.md`, `seal/tenant-barriers.md`, `acme/multi-tenancy.md` |
| [escrow](escrow/) | `escrow/README.md` — **absorbed and deleted** |
| [password-vault](password-vault/) | `staticpw/` |
| [platform-secrets](platform-secrets/) | `platform-store/` |
| [post-quantum](post-quantum/) | `architecture/post-quantum-cryptography.md`, `backends/quantum.md` |
| [symmetric-aead](symmetric-aead/) | `architecture/symmetric-encryption.md`, `configuration/aead-auto-selection.md`, `configuration/symmetric-encryption.md` |
| [audit-log](audit-log/) | — |
| [cluster](cluster/) | `cluster/README.md` — **absorbed and deleted**; `cluster/ca-key-custody.md` retained as a companion deep-dive, linked from [`cluster/architecture.md`](cluster/architecture.md) |
| [luks](luks/) | — |
| [signing](signing/) | `verification/` — **absorbed and deleted** (its `ChecksumProvider` was never wired to a live verifier; superseded by `types.ChecksumProvider`) |
| [ssh-agent-sessions](ssh-agent-sessions/) | — (new surface; supersedes nothing) |
| [user-onboarding](user-onboarding/) | — (new surface; supersedes nothing) |
| [host-embedding](host-embedding/) | — (new surface; `architecture/server-architecture.md` §"Unified API Server" points here for host mode) |
| [xkmsd-configuration](xkmsd-configuration/) | `architecture/server-architecture.md` §"Configuration Management" (its `XKMS_REST_ADDRESS`-style names never existed) |
| [clustering](clustering/) | `cluster/` (`cluster/README.md`, `cluster/ca-key-custody.md`) — **absorbed and deleted**. The legacy `README.md`'s `/api/v1/cluster/*` REST routes and `admin:add_member`/`admin:remove_member` permissions described a proxy plane that was since deleted; `ca-key-custody.md` is retained as a companion deep-dive, now [`clustering/ca-key-custody.md`](clustering/ca-key-custody.md), linked from [`clustering/architecture.md`](clustering/architecture.md). A separate `docs/cluster/` five-file folder landed briefly (go-xkms#847, the read-only REST cluster status/membership surface for the web console) and duplicated this one; it was merged into `clustering/` in the same pass rather than kept as two folders for one feature. |
| [rbac](rbac/) | `architecture/rbac.md` |
| [datastore](datastore/) | `storage/` — the legacy `README.md`'s `objstore` backend example (`storage.backend: objstore` with S3/GCS/Azure options) is not reachable through `xkmsd`'s own datastore, same as before. Also supersedes this repo's own now-deleted `storage-engines/` folder (go-xkms#1345): the old per-subsystem `storage.backend` (file/pebble/memory as private, unreplicated alternatives to `qrdb`) was replaced by one global, always-qrdb-backed `datastore.engine`/`datastore.mode`. |
| [web-console](web-console/) | `web/` |

Several of these need a note rather than a row:

- **`architecture/pin-architecture.md`** and `fido2/authenticator/architecture.md`
  describe a `PINCoordinator` and a `pkg/pin` package. **Neither exists in this
  repository.** [`pin-management/architecture.md`](pin-management/architecture.md)
  documents what does — `pkg/pinselect` and `pkg/pintpm2` — and says so
  explicitly. Whether that design is a roadmap item or a stale document is an
  open question.
- **`acme/cli/cactl.md`** documented a binary that was never in this
  repository and whose project has been retired; it, and the rest of
  `acme/cli/`, were deleted by go-xkms#942 — see
  [`acme-issuance/cli.md`](acme-issuance/cli.md).
- **`acme/` is mostly still legacy, not superseded.** The table above lists
  only the specific root files `acme-issuance/` actually absorbed and
  deleted. The bulk of the tree — `acme/gui/` (dual-mode admin+client SPA,
  `pkg/acme/gui/{admin,client,guard,webui}`; go-xkms#942 corrected its
  `cactl`/`trusted-acme-server`/`TRUSTEDCA_*` references in place and
  flagged that `pkg/acme/gui/admin` and `pkg/acme/api/server` — which
  would mount its web build at `/ui/admin/` — have no confirmed `cmd/`
  caller; the admin web UI actually wired into `xkmsd` is a separate
  implementation, `pkg/acme/web/packages/admin` at `/admin-ui`,
  `cmd/xkmsd/admin.go:73`; reconciling the two is unresolved), `acme/admin/`
  (5 files: the Admin REST plane, `pkg/acme/admin` — handlers, RBAC, tenant
  and barrier ceremony endpoints; `configuration.md` is a retained operator
  checklist, corrected in place by go-xkms#942, the rest unconverted),
  `acme/protocols/` (5 files: the six-transport wiring; go-xkms#942
  corrected their `cactl`/`trusted-acme-server`/`TRUSTEDCA_*` references in
  place, and flagged that `unix-socket.md`'s premise conflicts with
  `acme-issuance/cli.md`'s own statement that the ACME admin plane has no
  Unix adapter), `acme/dns-01/` (6 files: per-provider DNS-01
  configuration), `acme/qrdb/` (3 files), `acme/sdk/README.md`,
  `acme/api-reference.md`, `acme/audit/`, `acme/auth/`, `acme/docker.md`,
  `acme/multi-tenancy.md` (superseded by [`multi-tenancy/`](multi-tenancy/),
  see the table above), and `acme/deployment/` (`security.md` and
  `operations.md` are the retained operator checklists — `operations.md`'s
  `trusted-acme-server` binary reference was corrected in place by
  go-xkms#942; the rest of `acme/deployment/` was fictional pre-merge
  go-trusted-ca documentation and was deleted by go-xkms#942) remain
  unconverted. `acme/boulder-comparison-enhancements.md` is deliberately
  retained as a reference, not absorbed
  ([`acme-issuance/architecture.md`](acme-issuance/architecture.md) cites
  it directly). A previous pass over this README claimed `acme-issuance/`
  superseded all of `acme/` except `ROADMAP.md`; that claim did not hold up
  against the code and has been narrowed here — and a later pass claimed
  `acme/architecture.md`, `acme/client.md`, `acme/challenges.md` and
  `acme/challenge-resolver.md` were absorbed and deleted, which is also not
  true: all four are still present. Whether their content is actually
  covered by `acme-issuance/` is unverified and out of go-xkms#942's scope
  (it addressed only nonexistent-binary/env-prefix references, not a full
  content audit).
- **`ca/dane.md`, `ca/bootstrap.md` and `ca/bootstrap-integration.md` are not
  superseded** by `certificate-authority/` or by `trust-bootstrap/`. Their
  DANE/TLSA field-semantics tables, DNSSEC walkthrough and per-project
  bootstrap integration recipes are not duplicated in either folder's five
  files (`trust-bootstrap/` covers the `dane generate-tlsa` CLI verb and the
  mode's place in the DANE/Noise/SPKI/Direct dispatch, nothing deeper).
  `ca/dane.md`'s own "Using the Go API" section is additionally **stale**:
  it imports `github.com/jeremyhahn/go-xkms/pkg/ca/dane`, a package that no
  longer exists — the DANE resolver now lives upstream, in
  `github.com/jeremyhahn/go-truststrap/pkg/dane`, consumed by
  `pkg/trust/bootstrap/tlsconfig.go`. `ca/bootstrap.md`'s "API Reference"
  section (`Bootstrapper`, `CABundleRequest`, `CABundleResponse`) describes
  the same pre-truststrap-composition shape and is stale the same way.
- **`cli/barrier.md` is not superseded** by `sealing-and-barrier/`. Its
  xkms-specific sections — the PIN-dispatch-through-separate-RPCs pattern
  (`applyInitialPINPair`, `verifySOPINIfSupplied` in `cmd/xkmsctl/barrier.go`),
  the `barrier rekey` `--threshold`/`--total`-required rationale, and the
  strategy+PIN validation matrix (`BarrierSecretNotAllowedError`,
  `PINsNotAllowedError`, `PINPairError`, `BarrierShamirOnInitError`, all
  verified still present in `cmd/xkmsctl/barrier.go`) — are not in
  [`sealing-and-barrier/cli.md`](sealing-and-barrier/cli.md), which lists
  the verbs and flags but not why the PIN flags work despite the wire
  types carrying no PIN fields.
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

**Nothing, as of this pass (go-xkms#707, 2026-09-24).** Every area this
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
| FROST threshold signatures | [`frost-threshold-signing/`](frost-threshold-signing/) (partial absorption — see the note below) |
| SSH key management | [`ssh-keys/`](ssh-keys/), [`ssh-agent-sessions/`](ssh-agent-sessions/), and [`ssh-sessions/`](ssh-sessions/) together — see the note below |
| PKCS#11 **backend** (consuming a token) | [`pkcs11-backend/`](pkcs11-backend/) |
| Web console | [`web-console/`](web-console/) |
| Clustering | [`clustering/`](clustering/) |
| RBAC | [`rbac/`](rbac/) |
| Browser trust injection | [`../xkey/docs/browser-trust-injection/`](../xkey/docs/browser-trust-injection/) — converted, but in the xkey module; see the note below |
| LUKS | [`luks/`](luks/) |
| Datastore | [`datastore/`](datastore/) |

[`frost-threshold-signing/`](frost-threshold-signing/),
[`ssh-keys/`](ssh-keys/), [`ssh-agent-sessions/`](ssh-agent-sessions/) and
[`ssh-sessions/`](ssh-sessions/) are all NORMATIVE folders, but no single
one of the SSH three fully absorbs [`ssh/README.md`](ssh/README.md) on
its own, so none gets its own "legacy paths superseded" row above — the
detail is recorded here instead:

- **FROST** — [`frost-threshold-signing/`](frost-threshold-signing/) is
  NORMATIVE for `pkg/keyprovider/frost` and its CLI/REST/gRPC/MCP surface.
  The legacy [`frost/`](frost/) folder's `backends.md` (per-backend
  `SecretBackend` setup) and `dkg-integration.md` (writing a custom
  `KeyGenerator`) were not re-verified for this conversion and remain
  legacy-only; treat them as unconfirmed until someone re-verifies them
  against source the way the rest of this folder was.
- **SSH** — [`ssh-keys/`](ssh-keys/) is NORMATIVE for SSH keys,
  known-hosts, and authorized-keys (plus the backend bridge and the
  shared key-ID layout). [`ssh-agent-sessions/`](ssh-agent-sessions/) is
  NORMATIVE for hostless agent-only signing sessions.
  [`ssh-sessions/`](ssh-sessions/) (go-xkms#707) is NORMATIVE for
  everything [`ssh-keys/architecture.md`](ssh-keys/architecture.md) named
  as still legacy when it was written — interactive console sessions, the
  `xkey` connection-profile manager, session history, and local
  `ssh_config`/agent discovery (`pkg/ssh/{console,connect,session,
  sessions,profile,local}`). Between the three, every subpackage of
  `pkg/ssh` (`agent`, `authorized`, `backend`, `connect`, `console`,
  `keys`, `known_hosts`, `local`, `profile`, `scope`, `session`,
  `sessions`) now has a NORMATIVE home, so `ssh/README.md` is fully
  covered — it is not deleted in this pass because no folder singly
  absorbs it end to end, but a future pass could reasonably delete it in
  favor of the three folders above.

Browser trust injection is converted, but the code and its folder live in the
xkey module, not here — see
[`../xkey/docs/browser-trust-injection/`](../xkey/docs/browser-trust-injection/)
and the superseded-path row in `xkey/docs/README.md`. That folder also
covers `xkey browser launch`'s NSS `cert9.db` and Firefox `policies.json`
mechanics — one of the three pieces `cli/trust-platform.md` (deleted this
pass) split into; see the "absorbed and deleted" note above (§"Legacy paths
superseded") for the other two. The legacy [`browser/`](browser/) path in
*this* tree is a stale duplicate the xkey folder does not track; it is left
as-is per this repository's no-deletion rule for legacy docs.

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

**Operator checklists are procedure, not backlog.** The checklists in
`acme/deployment/security.md`, `acme/deployment/operations.md`,
`acme/admin/configuration.md`, `frost/security.md` and
`pkcs11/module/security.md` are deployment and hardening procedure. They belong
in the relevant feature's `user.md` or under `deployment/`, and are retained
where they are until that absorption happens. Their unchecked boxes are not a
work queue.

## Documentation Structure

### [Architecture](architecture/)
Core architectural concepts, design patterns, and technical specifications:
- [Overview](architecture/overview.md) - System architecture and design philosophy
- [API Specifications](architecture/api-specifications.md) - API design and interface contracts
- [Server Architecture](architecture/server-architecture.md) - Server design and backend registry
- [Storage](architecture/storage.md) - Storage interfaces and abstraction layer
- [Symmetric Encryption](architecture/symmetric-encryption.md) - Symmetric key support architecture
- [Hardware Certificate Storage](architecture/hardware-certificate-storage.md) - HSM certificate storage design
- [RBAC](architecture/rbac.md) - Role-based access control

### [Backends](backends/)
Backend-specific documentation for all supported storage systems:
- **Software**: [Software](backends/software.md) (asymmetric + symmetric, default backend; [PKCS#8](backends/pkcs8.md) key provider)
- **Hardware**: [TPM 2.0](backends/tpm2.md), [PKCS#11](backends/pkcs11.md), [Nitrokey HSM](backends/nitrokey-hsm.md)
- **Cloud**: [AWS KMS](backends/awskms.md), [GCP KMS](backends/gcpkms.md), [Azure Key Vault](backends/azurekv.md), [HashiCorp Vault](backends/vault.md)
- **Quantum**: [Post-Quantum Cryptography](backends/quantum.md)

### [Configuration](configuration/)
Configuration guides for various components:
- [Build System](configuration/build-system.md) - Build tags and compilation options
- [AEAD Configuration](configuration/aead-auto-selection.md) - Authenticated encryption setup
- [Symmetric Encryption](configuration/symmetric-encryption.md) - Symmetric key configuration
- [TPM2 Session Encryption](tpm2/engineering.md#bus-protection) - TPM session security

### [Bootstrap](bootstrap/)
Secure trust establishment and server initialization:
- [Overview](bootstrap/README.md) - Bootstrap architecture, DANE/Noise/SPKI/Direct trust methods, custodian setup

### [Trust](trust/)
Canonical trust-bootstrap dispatch library:
- [Trust Bootstrap Library](trust/bootstrap.md) - `pkg/trust/bootstrap` Mode enum, Fetch entry point, and the four consumers (xkmsctl, xkey GUI, QuicBaaS SDK, go-trusted-platform via SDK)

### [Init](init/)
First-boot server initialization ceremony:
- [Init System](init/README.md) - The `xkmsd init` KMS+CA half plus the IAM half that delegates to the embedded qrdb node's first-boot

### [Auth](auth/)
Authentication, authorization, and bootstrap:
- [Bootstrap Authentication](auth/bootstrap.md) - Cert-based admin enrollment: the `xkmsd init` ceremony, officer claim protocol, and `xkmsctl admin` mTLS/FIDO2 enrollment
- [Layering](auth/layering.md) - Identity (qrdb) vs key-domain (xkms) split, Factor adapter composition

### [WebAuthn](webauthn/)
Converted to the five-file feature layout — see [Feature documentation](#feature-documentation) below.
- [Architecture](webauthn/architecture.md) - Canonical RP implementation consumed by every binary in the stack via the QuicBaaS SDK re-export
- [Engineering](webauthn/engineering.md) - Exported surface, ceremony invariants, the headless client used by `xkmsctl` and tests

### [PIN](pin/)
- [PIN Management](pin/README.md) - PIN service (qrdb) + TPM2 backend (xkms `pkg/pintpm2`) + composition via `WithPINBackend`

### [Seal](seal/)
- [Barrier Encryption Architecture](seal/README.md) - qrdb owns the barrier and StrategyRegistry; xkms owns every hardware/cloud strategy

### [Custodian](custodian/)
- [Custodian Groups](custodian/README.md) - M-of-N roster naming who holds each Shamir share; service API, REST routes, and `xkmsctl custodian`
- [Share Collection Plane](custodian/shares.md) - submitting, inspecting, and removing returned shares
- [Key Share Persistence](sharestore/README.md) - client-side storage of received shares

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

### [Sealed Storage](sealed-storage/)
Encrypted-at-rest storage and credential management:
- [Sealed Backend](sealed-storage/README.md) - Transparent value encryption via types.Sealer
- [PlatformStore](platform-store/README.md) - Named-secret credential store (macOS Keychain analog)
- [Static Passwords](staticpw/README.md) - Password manager with multi-tenant support and encryption

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
