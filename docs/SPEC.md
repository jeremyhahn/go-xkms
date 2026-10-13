# go-xkms specification

> **Status: NORMATIVE** · Last verified: 2026-10-13
> What go-xkms is, and every feature it has, with requirements and status. The plan by issue is [ROADMAP.md](../ROADMAP.md).

**Rule 1.** This file lists what the project is and every feature, with requirements and status. A feature listed here, in any status, is never deleted: not its docs, its code or its issues. Removing or re-scoping a feature needs the owner's change to this file.

Each feature's folder (`docs/<feature>/`, `xkey/docs/<feature>/`) is the detail behind its row and is normative for that feature.

## Purpose

go-xkms owns all hardware and cloud crypto and hardware identity in the stack: TPM 2.0, PKCS#11 (as a client backend and as a provider module), cloud KMS, FIDO2 CTAP2, the WebAuthn relying party, PIV, `TrustedCA` with ACME, trust-bootstrap dispatch, the phone-as-HSM pairing protocol, the SSH surface and RFC 9334 evidence-level attestation primitives.
It sits above go-qrdb, consumed only through `go-qrdb/sdk/go`, and exports its own crypto surface through `go-xkms/sdk/go`.
go-quicbaas composes it into the product, and go-trusted-platform reaches it through go-quicbaas. xkey, the desktop GUI and CLI in this repository, is its own product surface.

## Boundaries

go-xkms **owns** the canonical, single implementation of every capability above, and the hardware-side concerns of first boot (TPM enrollment, IDevID issuance, ACME directory enrollment). Its hardware and cloud seal strategies, PIN backends and factor adapters implement go-qrdb seams and register into go-qrdb's registries.

go-xkms **never**:

- ships a Raft state machine, KV store or any database surface, or re-exports go-qrdb's data plane from `sdk/go`;
- ships a barrier, bootstrap/first-boot implementation, user model or cert-binding scheme: those are go-qrdb's, consumed through `go-qrdb/sdk/go`;
- imports `go-qrdb/pkg/*`: node configuration uses the `qrdbsdk.Daemon*` re-exports;
- ships a multi-tenant Backend-as-a-Service facade (go-quicbaas) or application-level user, registration or JWT entities (the consumer's);
- reimplements go-truststrap's DANE, Noise or SPKI primitives; it composes them in `pkg/trust/bootstrap`;
- takes anything that the handbook's capability registry assigns to another owner.

Cross-cutting documentation, not features: [architecture/](architecture/), [configuration/](configuration/), [crypto/](crypto/), [deployment/](deployment/), [development/](development/), [fips/](fips/), [references/](references/), [testing/](testing/); in xkey, [architecture/](../xkey/docs/architecture/), [configuration/](../xkey/docs/configuration/), [testing/](../xkey/docs/testing/), [usage/](../xkey/docs/usage/).

## Features

| Feature | Status | Requirements | Detail |
|---|---|---|---|
| acme-issuance | shipped | ACME RFC 8555 server and client with ARI, DNS-01 and HTTP-01 challenges and TPM enrollment; the device-attest-01 challenge for DICE devices; the ACME admin plane and its GUI. | [acme-issuance/](acme-issuance/) |
| attestation-evidence | shipped | RFC 9334 evidence primitives in `sdk/go/evidence`: TPM2_Quote, AK and EK chains, strict TCG event-log parsing and replay, TPM2_Certify, IAK/IDevID, signed CoRIM reference values. | [attestation-evidence/](attestation-evidence/) |
| attestation-verifier | shipped | Backend-agnostic `pkg/attestation`: chain and signature verification and per-format key-binding invariants that gate CSR issuance on hardware provenance (TPM2, PIV, Android). | [attestation-verifier/](attestation-verifier/) |
| attested-peer | shipped | Decide whether a connection's peer is a currently attested system: quote to verdict, IDevID/IAK validation, TLS channel binding, and the verifier behind go-qrdb's attested-caller gate. | [attested-peer/](attested-peer/) |
| audit-log | shipped | Tamper-evident audit records and their signing chain. | [audit-log/](audit-log/) |
| auth-factors | shipped | Hardware factor adapters behind go-qrdb's `Factor` interface, factor composition, and the identity/key-domain split. | [auth-factors/](auth-factors/) |
| backend-credentials | shipped | Backend secrets (PKCS#11 User PIN, cloud KMS and Vault secrets) under `credentials.seal_strategy`, `credential://` resolution at startup, and the CLI, REST and MCP credential surface. | [backend-credentials/](backend-credentials/) |
| backend-registry | shipped | External backends register through the hook (`RegisterExternalBackend`), built-in backend types stay closed to external registration, and a blank import of an adapter module is the integration path; shipped in `v0.52.0-alpha`. | [crypto-backends/engineering.md](crypto-backends/engineering.md) |
| certificate-authority | shipped | `TrustedCA`, go-xkms's own CA, never replaced by go-qrdb's: cross-signed root pool, AIA import, DANE TLSA publishing, issuance profiles. | [certificate-authority/](certificate-authority/) |
| clustering | shipped | Embed a go-qrdb clustered node behind the `raft` tag: Raft config mapping, inter-node mTLS, leader redirects, the cluster control plane, cluster CA key custody and the enroll-01 join. | [clustering/](clustering/) |
| crypto-backends | shipped | One `Backend` contract with every software, hardware and cloud implementation, each compiled in by a `WITH_*` toggle. | [crypto-backends/](crypto-backends/) |
| datastore | shipped | One global, go-qrdb-backed datastore for every subsystem, configured by `datastore.engine` and `datastore.mode`, with no per-subsystem storage choice. | [datastore/](datastore/) |
| dice-device-identity | shipped | DICE device identity with a hardware root of trust: TCG DICE extensions and UCCS claims, their verification, and the `dice-idevid` issuance profile. | [dice-device-identity/](dice-device-identity/) |
| escrow | shipped | External key escrow (KMIP and xkms federation) through the agent factory, daemon config and service layer; reachable through the embedded Go SDK. | [escrow/](escrow/) |
| fido2-ctap2 | shipped | The stack's single FIDO2 CTAP2 client implementation. | [fido2-ctap2/](fido2-ctap2/) |
| frost-threshold-signing | shipped | RFC 9591 FROST threshold signing (`-tags frost`): trusted-dealer keygen, the explicit round API, the CLI and the network surface. | [frost-threshold-signing/](frost-threshold-signing/) |
| host-embedding | shipped | Mount the `xkms` ServiceModule in a go-qrdb-embedding host; `pkg/compose` builds every store through the same path as `xkmsd`. | [host-embedding/](host-embedding/) |
| hsm-device-protocol | future | The wire protocol between xkmsd and an HSM device, for both direct-attached and network HSM over 10G or 1G; the NXP FRDM-IMX95-PRO is the first device. xkmsd runs in the device's Linux portion and go-xkms does nothing for the device firmware; trusted-imx95 implements the device side (firmware, secure world, secure key handling) and go-trusted-platform provisions and attests the device. Open questions: what transport does direct attach use, and what protocol surface does the network HSM expose? | none |
| init-ceremony | shipped | `xkmsd init`, the single-administrator bootstrap: CA artifacts, the node's first boot and the administrator's login factors. | [init-ceremony/](init-ceremony/) |
| key-management | shipped | Key lifecycle, key providers, rotation, versions, cross-backend copy, and symmetric and asymmetric operations on every transport. | [key-management/](key-management/) |
| luks | shipped | The stack's single LUKS implementation: FIPS-aware volume lifecycle on go-luks2 and TPM 2.0 passphrase sealing. | [luks/](luks/) |
| multi-tenancy | shipped | Per-tenant isolation, tenant barriers and tenant-scoped keys. | [multi-tenancy/](multi-tenancy/) |
| observability | shipped | Prometheus instrumentation: operation counters and histograms, backend health, key and certificate totals, connection tracking. | [observability/](observability/) |
| oidc-credentials | shipped | Server-side OIDC credentials on the tenant barrier, kept fresh by a leader-elected scheduler, with device-flow and import logins and `GetAccessToken` by reference. | [oidc-credentials/](oidc-credentials/) |
| password-vault | shipped | Stored password credentials and their access modes. | [password-vault/](password-vault/) |
| pin-management | shipped | The PIN service and its TPM 2.0 backend. | [pin-management/](pin-management/) |
| piv-smartcard | shipped | PIV slot operations (sign, decrypt, attest) as a factor and as a CLI/SDK verb. | [piv-smartcard/](piv-smartcard/) |
| pkcs11-backend | shipped | xkms as a PKCS#11 client consuming an HSM or token (`-tags pkcs11`). | [pkcs11-backend/](pkcs11-backend/) |
| pkcs11-provider-module | shipped | The `pkcs11-module` cgo Cryptoki provider presenting xkms as a token, and its slot/token lifecycle. | [pkcs11-provider-module/](pkcs11-provider-module/) |
| platform-secrets | shipped | Platform secret storage and resolution. | [platform-secrets/](platform-secrets/) |
| post-quantum | shipped | ML-KEM and ML-DSA key generation and use, the stdlib/CIRCL split and FIPS behavior. | [post-quantum/](post-quantum/) |
| rbac | shipped | The `auth.Authorizer` seam over go-qrdb's identity plane: the xkms permission vocabulary, transport enforcement and the built-in roles. | [rbac/](rbac/) |
| release-engineering | shipped | Two-step `-alpha` releases (`make release-alpha` opens a PR, `make release-tag` tags it), lockstep tag namespaces, reciprocal `go.mod` pins, the exported-API growth gate. | [release-engineering/](release-engineering/) |
| sealing-and-barrier | shipped | Hardware and cloud seal strategies for go-qrdb's barrier, the pre-barrier store with the TPM-sealed PKCS#11 PIN, protected memory and process hardening. | [sealing-and-barrier/](sealing-and-barrier/) |
| sign-server | shipped | Embeddable node-local sign-only server on an exclusive SO_PEERCRED unix socket that a remote-mode PKCS#11 module signs through. | [sign-server/](sign-server/) |
| signing | shipped | The SDK's `Sign`/`Verify` with persisted per-blob checksums shared by every backend. | [signing/](signing/) |
| ssh-agent-sessions | shipped | Serve an xkms-held key over an ephemeral SSH agent socket with no connection target. | [ssh-agent-sessions/](ssh-agent-sessions/) |
| ssh-keys | shipped | SSH keys (software or backend-backed), host-key pins and authorized_keys entries on every transport. | [ssh-keys/](ssh-keys/) |
| ssh-sessions | shipped | Outbound SSH: interactive console, non-interactive `Run` and upload, connection profiles, session history, local `ssh_config`/agent discovery. | [ssh-sessions/](ssh-sessions/) |
| symmetric-aead | shipped | AES-GCM, ChaCha20-Poly1305, AES-CBC and AES-ECB, the AEAD safety tracker and GCM nonce modes under FIPS. | [symmetric-aead/](symmetric-aead/) |
| tpm-policies | shipped | Named, TPM-authorized policies (PolicyAuthorize with NV-counter revocation) shared by many keys and sealed objects, the key/policy registry and per-tenant TPM modes. | [tpm-policies/](tpm-policies/) |
| tpm2 | shipped | EK/SRK lifecycle, IDevID/LDevID issuance (TCG-CSR-IDEVID), PCR policy, attestation and sealed objects. | [tpm2/](tpm2/) |
| trust-bootstrap | shipped | The single DANE / Noise / SPKI / Direct / Auto mode-dispatch library that fetches and verifies a CA bundle for first-contact clients. | [trust-bootstrap/](trust-bootstrap/) |
| user-onboarding | shipped | Administrator-issued activation invitations, redeemed through the WebAuthn or PIV ceremony to enroll the first credential. | [user-onboarding/](user-onboarding/) |
| web-console | shipped | The Svelte console served by `xkmsd` at `/ui/` and by the `xkms-console` desktop shell. | [web-console/](web-console/) |
| webauthn | shipped | The stack's single WebAuthn relying party; challenge and session state live here. | [webauthn/](webauthn/) |
| xkmsd-configuration | shipped | Resolve daemon configuration from defaults, file, `XKMS_*` environment and flags, and feed the listeners. | [xkmsd-configuration/](xkmsd-configuration/) |

### xkey

xkey (`go-xkms/xkey`) is a product surface: CLI, desktop GUI, browser extension and local IPC. Reusable logic lives in `go-xkms/pkg/*` and xkey consumes it through `go-xkms/sdk/go`.

| Feature | Status | Requirements | Detail |
|---|---|---|---|
| agent | shipped | Network agent enrollment, connection-time revocation checking and removal. | [agent/](../xkey/docs/agent/) |
| agent-automation | shipped | PIN and touch automation for headless agents and CI. | [agent-automation/](../xkey/docs/agent-automation/) |
| autofill | shipped | Browser-extension credential and TOTP autofill: native messaging, pairing, CTAP2 assertion verification, policy. | [autofill/](../xkey/docs/autofill/) |
| ble | shipped | The BLE transport for the phone-as-HSM pairing protocol: GATT wire shape, both roles, BlueZ. | [ble/](../xkey/docs/ble/) |
| browser-trust-injection | shipped | Inject trust-store CA certificates into Chrome- and Firefox-family browsers through a pure-Go NSS `cert9.db` writer. | [browser-trust-injection/](../xkey/docs/browser-trust-injection/) |
| ca | planned | Standalone xkey either hosts a local `TrustedCA` (`xkey ca --local`) or stays remote-only with the GUI `CAService` wired for remote mode; decision pending on local `TrustedCA` versus remote-only. | none |
| device | shipped | The `xkey device` namespace: client-side agent enrollment and QR-code pairing. | [device/](../xkey/docs/device/) |
| fido2 | shipped | The `xkey fido2` daemon, its IPC verbs, and the GUI's FIDO2 device host. | [fido2/](../xkey/docs/fido2/) |
| gui | shipped | The Wails desktop GUI: the `App` root, the bound service surface, opt-in unix-socket IPC, events, the Svelte frontend. | [gui/](../xkey/docs/gui/) |
| headless-webauthn | shipped | Programmatic WebAuthn ceremonies without a browser or a human. | [headless-webauthn/](../xkey/docs/headless-webauthn/) |
| xkey-luks | shipped | The fail-closed LUKS2 lock gate shared by CLI and GUI, over the root `pkg/luks`. | [luks/](../xkey/docs/luks/) |
| oath | shipped | TOTP/HOTP credentials, QR scanning, barrier-backed storage. | [oath/](../xkey/docs/oath/) |
| oidc | shipped | OIDC relying-party login and the CLI's barrier-backed session token store. | [oidc/](../xkey/docs/oidc/) |
| password | shipped | Static passwords, folders, autofill metadata and xkmsd-backed session access modes. | [password/](../xkey/docs/password/) |
| phone | shipped | The phone FIDO2 key backend (`--backend phone`), its BLE/USB/TCP transports and the xkmsd bridge. | [phone/](../xkey/docs/phone/) |
| phone-hsm | shipped | The phone-as-HSM backend and its pairing protocol. | [phone-hsm/](../xkey/docs/phone-hsm/) |
| piv | shipped | The `xkey piv` CLI and GUI over the SDK's PIV certificate manager. | [piv/](../xkey/docs/piv/) |
| pkcs11 | shipped | GUI module/slot/token management, the embedded and IPC `PKCS11Transport`, and `--backend pkcs11`. | [pkcs11/](../xkey/docs/pkcs11/) |
| pkcs11-manager | shipped | The PKCS#11 module/token manager and its per-slot backend-registry sync. | [pkcs11-manager/](../xkey/docs/pkcs11-manager/) |
| platform-trust | shipped | Trust bootstrap, the classified truststore and SPKI-pinned platform CA import. | [platform-trust/](../xkey/docs/platform-trust/) |
| seal | shipped | The barrier, barrier auto-unseal through a named TPM policy, and the sealed-blob store. | [seal/](../xkey/docs/seal/) |
| secret-service | shipped | The `org.freedesktop.secrets` D-Bus daemon over the password store, locked and unlocked with the barrier. | [secret-service/](../xkey/docs/secret-service/) |
| setup-wizard | shipped | First-run personal and enterprise setup, SO provisioning and where the SO PIN may live. | [setup-wizard/](../xkey/docs/setup-wizard/) |
| ssh | shipped | SSH keys, profiles and host keys, connect/console, local discovery and the GUI SSH services. | [ssh/](../xkey/docs/ssh/) |
| usb | shipped | The virtual USB CCID smartcard device and portable USB disk images. | [usb/](../xkey/docs/usb/) |
| virtual-authenticator | shipped | The virtual FIDO2/CTAP2 authenticator over Linux UHID. | [virtual-authenticator/](../xkey/docs/virtual-authenticator/) |
| xkeysigner | shipped | `crypto.Signer` over IPC to the GUI's PIV slot, for the SDK's `WithXKeyAuth` mTLS option. | [xkeysigner/](../xkey/docs/xkeysigner/) |
| media-signing | future | Multi-signer, region- and segment-aware signing and verification of photos and videos, and a contacts store. | [roadmap/media.md](../xkey/docs/roadmap/media.md) |
| piv-i | future | PIV-I (FIPS 201-3, SP 800-73-4) profiles with every PIV key on FIPS-validated hardware. | [roadmap/piv.md](../xkey/docs/roadmap/piv.md) |
| browser-mode | future | Run the same Svelte GUI as a browser web app over a pluggable transport, authenticated with WebAuthn. | [roadmap/web.md](../xkey/docs/roadmap/web.md) |

## Interfaces

- **SDK**: [`sdk/go`](../sdk/go/), on the embedded, unix, gRPC, QUIC, REST and MCP transports; transport model in [key-management/api.md](key-management/api.md).
- **CLI**: [`xkmsctl`](../cmd/xkmsctl/), global flags in [key-management/cli.md](key-management/cli.md); [`xkey`](../xkey/cmd/xkey/), reference in [xkey/docs/usage/cli/](../xkey/docs/usage/cli/).
- **Daemon**: [`xkmsd`](../cmd/xkmsd/), configuration and listeners in [xkmsd-configuration/](xkmsd-configuration/).
- **PKCS#11 module**: [`cmd/pkcs11-module`](../cmd/pkcs11-module/), detail in [pkcs11-provider-module/](pkcs11-provider-module/).

## Release criteria

The Release candidate milestone (milestone 14) closes when all of these hold:

- Every open issue in the milestone is closed: #1406 (multi-tenancy), #1380 (auth-factors), #1468 (webauthn), #794 (init-ceremony), #1332 and #1333 (release-engineering, CI isolation), #1475 (spec-review scrub of `docs/`), #1439 and #1440 (backend-registry) and #1030 (public-release readiness, closed last).
- Every shipped feature in this file has a feature folder that matches the code.
- The release is cut by the [release-engineering](release-engineering/) process: a reviewed `chore(release)` pull request, the three lockstep tags on its merge commit, and the exported-API growth gate passed.
