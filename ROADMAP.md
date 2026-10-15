# go-xkms roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-14
> Per handbook `software/conventions/roadmap.md`: the Software Department refreshes it; the project agent proposes changes by PR.

## Mission

The third layer of the stack: hardware crypto, auth factors, KMS, CA, ACME and TPM policies as services on top of go-qrdb through ServiceModule (TPM2, PKCS#11 backend and provider module, cloud KMS, FIDO2/WebAuthn/PIV, `TrustedCA` + ACME, trust bootstrap, phone-as-HSM and attestation crypto primitives), with every go-qrdb service re-exported through `sdk/go`, so the go-qrdb client works unchanged against an xkms node. Scope and boundaries: [docs/SPEC.md](docs/SPEC.md).

## Milestones

- [Dev complete](../../milestone/14) — RC — due: 2026-11-09 — 10 open / 36 closed — multi-tenancy, auth-factors, webauthn, acme-issuance, init-ceremony, release-engineering, backend-registry, transparency-log, attested-caller-gate, trust-roots, image-signing, workload-identity; closing criteria in [docs/SPEC.md](docs/SPEC.md#release-criteria)
- [Working fundamentally: 3-node raft + quicbaas surface](../../milestone/30) — release — due: 2026-10-23 — 1 open / 7 closed — release-engineering, sealing-and-barrier

## Complete

- **attestation-evidence** — RFC 9334 evidence primitives in `sdk/go/evidence` — [v0.48.0-alpha](../../releases/tag/v0.48.0-alpha) — done
- **attested-peer** — quote-to-verdict peer attestation behind go-qrdb's attested-caller gate — [v0.9.5-alpha](../../releases/tag/v0.9.5-alpha) — done
- **audit-log** — xkms product audit events into go-qrdb's audit logger — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **auth-factors** — hardware factor adapters behind go-qrdb's `Factor` interface — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **backend-credentials** — backend secrets under `credentials.seal_strategy` and `credential://` resolution — [#1450](../../issues/1450), [#1464](../../issues/1464), [#1465](../../issues/1465) — done
- **backend-registry** — the external backend registration hook — [v0.52.0-alpha](../../releases/tag/v0.52.0-alpha) — done
- **certificate-authority** — `TrustedCA` root pool, AIA import, DANE TLSA and issuance profiles — [#1438](../../issues/1438) — done
- **clustering** — embedded go-qrdb clustered node behind the `raft` tag — [#1393](../../issues/1393) — done
- **crypto-backends** — one `Backend` contract with every implementation behind `WITH_*` toggles — [#1513](../../issues/1513) — done
- **datastore** — every subsystem on the deployment's one go-qrdb datastore — [#1345](../../issues/1345) — done
- **dice-device-identity** — DICE device identity and the `dice-idevid` profile — [#658](../../issues/658), [#1510](../../issues/1510) — done
- **escrow** — KMIP and xkms-federation key escrow — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **fido2-ctap2** — the stack's single FIDO2 CTAP2 client — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **frost-threshold-signing** — RFC 9591 FROST threshold signing under `-tags frost` — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **host-embedding** — the `xkms` ServiceModule mounted in a go-qrdb-embedding host — [v0.41.0-alpha](../../releases/tag/v0.41.0-alpha) — done
- **init-ceremony** — `xkmsd init` single-administrator bootstrap — [#1446](../../issues/1446) — done
- **key-management** — key lifecycle, rotation, versions and operations on every transport — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **luks** — FIPS-aware LUKS volume lifecycle with TPM 2.0 passphrase sealing — [#1427](../../issues/1427) — done
- **multi-tenancy** — per-tenant isolation and tenant-scoped keys — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **observability** — Prometheus instrumentation — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **oidc-credentials** — server-side OIDC credentials kept fresh by a leader-elected scheduler — [v0.48.0-alpha](../../releases/tag/v0.48.0-alpha) — done
- **password-vault** — stored password credentials and their access modes — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **pin-management** — the PIN service and its TPM 2.0 backend — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **piv-smartcard** — PIV slot operations as a factor and a CLI/SDK verb — [#1095](../../issues/1095), [#1467](../../issues/1467) — done
- **pkcs11-backend** — xkms as a PKCS#11 client under `-tags pkcs11` — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **pkcs11-provider-module** — the `pkcs11-module` Cryptoki provider — [#1512](../../issues/1512) — done
- **platform-secrets** — platform secret storage and resolution — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **post-quantum** — ML-KEM and ML-DSA key generation and use — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **rbac** — the `auth.Authorizer` seam and xkms permission vocabulary — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **release-engineering** — two-step `-alpha` releases with lockstep tags and the API growth gate — [#1434](../../issues/1434), [#1483](../../issues/1483), [#1055](../../issues/1055), [#1447](../../issues/1447) — done
- **sealing-and-barrier** — hardware and cloud seal strategies for go-qrdb's barrier — [#33](../../issues/33), [#1426](../../issues/1426) — done
- **sign-server** — node-local sign-only server on an SO_PEERCRED unix socket — [v0.48.0-alpha](../../releases/tag/v0.48.0-alpha) — done
- **signing** — SDK `Sign`/`Verify` with persisted per-blob checksums — [#1442](../../issues/1442) — done
- **ssh-agent-sessions** — xkms-held keys over an ephemeral SSH agent socket — [#54](../../issues/54) — done
- **ssh-keys** — SSH keys, host-key pins and authorized_keys entries on every transport — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **ssh-sessions** — outbound SSH console, `Run`, upload and profiles — [#1448](../../issues/1448) — done
- **symmetric-aead** — AEAD and block modes with the safety tracker under FIPS — [#1512](../../issues/1512) — done
- **tpm2** — EK/SRK lifecycle, IDevID/LDevID issuance, PCR policy and sealed objects — [#1466](../../issues/1466), [#1437](../../issues/1437) — done
- **trust-bootstrap** — the single DANE / Noise / SPKI / Direct / Auto dispatch library — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **user-onboarding** — activation invitations redeemed through WebAuthn or PIV — [#1294](../../issues/1294) — done
- **web-console** — the Svelte console at `/ui/` and the `xkms-console` shell — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **webauthn** — the stack's single WebAuthn relying party — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **xkmsd-configuration** — daemon configuration from defaults, file, environment and flags — [#140](../../issues/140) — done
- **agent** — network agent enrollment, revocation checking and removal — [#671](../../issues/671) — done
- **agent-automation** — PIN and touch automation for headless agents and CI — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **autofill** — browser-extension credential and TOTP autofill — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **ble** — the BLE transport for the phone-as-HSM pairing protocol — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **browser-trust-injection** — trust-store CA injection into Chrome- and Firefox-family browsers — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **device** — client-side agent enrollment and QR-code pairing — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **fido2** — the `xkey fido2` daemon, its IPC verbs and the GUI device host — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **gui** — the Wails desktop GUI — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **headless-webauthn** — programmatic WebAuthn ceremonies — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **xkey-luks** — the fail-closed LUKS2 lock gate shared by CLI and GUI — [#1427](../../issues/1427) — done
- **oath** — TOTP/HOTP credentials, QR scanning and barrier-backed storage — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **oidc** — OIDC relying-party login and the barrier-backed session token store — [#4](../../issues/4) — done
- **password** — static passwords, folders, autofill metadata and session access modes — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **phone** — the phone FIDO2 key backend and its transports — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **phone-hsm** — the phone-as-HSM backend and its pairing protocol — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **piv** — the `xkey piv` CLI and GUI — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **pkcs11** — GUI token management, `PKCS11Transport` and `--backend pkcs11` — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **pkcs11-manager** — the PKCS#11 module/token manager and per-slot registry sync — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **platform-trust** — trust bootstrap, classified truststore and SPKI-pinned platform CA import — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **seal** — go-qrdb's barrier with TPM-policy auto-unseal and the sealed-blob store — [#669](../../issues/669) — done
- **secret-service** — the `org.freedesktop.secrets` D-Bus daemon — [v0.25.0-alpha](../../releases/tag/v0.25.0-alpha) — done
- **setup-wizard** — first-run personal and enterprise setup and SO provisioning — [#432](../../issues/432) — done
- **ssh** — SSH keys, profiles, host keys, connect/console and the GUI SSH services — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **usb** — the virtual USB CCID smartcard and portable USB disk images — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done
- **virtual-authenticator** — the virtual FIDO2/CTAP2 authenticator over Linux UHID — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **xkeysigner** — `crypto.Signer` over IPC to the GUI's PIV slot — [v0.3.0-alpha](../../releases/tag/v0.3.0-alpha) — done

## Now

- **tpm-policies** — steps 1 and 2 of unattended unlock across updates: branch update from signed reference values, offline binding record with a static resolver, per-node records — [#1443](../../issues/1443) — open
- **attestation-verifier** — reference-value replay of an event log with a component digest from a signed CoRIM — [#1443](../../issues/1443) — open
- **acme-issuance** — phase C: `sdk/go` exports `AssemblePossessionCSR` for trusted-firmware's xkms adapter at device-attest-01 finalize — [trusted-firmware #28](../../../trusted-firmware/issues/28) — open

## Next

- **acme-issuance** — ACME admin listeners (gRPC, QUIC, MCP, unix) and the desktop admin GUI hosted by xkmsd — [#743](../../issues/743), [#746](../../issues/746) — open
- **acme-issuance** — finalize through `pkg/acme/issuance` with goodkey and zlint — [#744](../../issues/744) — open
- **acme-issuance** — CT precertificates and SCT embedding — [#745](../../issues/745) — open
- **attested-caller-gate** — wire `pkg/attestation/peergate` into the node through go-qrdb's peer-attestation gate, Challenge/Submit verbs, `sdk/go` `WithAttestedCallerGate`; provides go-quicbaas, through which go-trusted-platform consumes the gate — Dev complete — open
- **trust-roots** — one purpose-classified root store on a qrdb DAO, built from xkey's truststore; provides go-quicbaas — Dev complete — open
- **image-signing** — `pkg/image` DSSE/in-toto image signatures as OCI referrers with `VerifyImage` against trust-roots, and the `pkg/signing` verify for gtp's manifest RSA check; provides go-quicbaas, through which go-trusted-platform consumes the `pkg/signing` verify — Dev complete — open
- **transparency-log** — the transparency log as a CA service on go-qrdb's verifiable-log type, tree heads signed with the CA key through go-qrdb's `HeadSignerProvider`; consumes go-qrdb's verifiable log, provides go-quicbaas (tlog append) — Dev complete — blocked: go-qrdb's verifiable-log type (go-qrdb #721/#722)
- **workload-identity** — the tenant as the SPIFFE trust domain, SVIDs through ACME at deploy; provides go-quicbaas with SVIDs — Dev complete — blocked: go-qrdb accepting `spiffe://<tenant>/...`

## Later

- **platform-pcr-selection** — platform policy PCR selection: PCR 16 (`DefaultPlatformPCR`) or the board's boot PCRs — [#1443](../../issues/1443) — blocked: decision pending on PCR 16 versus boot PCRs
- **ca** — standalone xkey CA: local `TrustedCA` (`xkey ca --local`) or remote-only with the GUI `CAService` in remote mode — [#729](../../issues/729) — blocked: decision pending on local `TrustedCA` versus remote-only

## Future

- **hsm-device-protocol** — wire protocol between xkmsd and HSM devices, direct-attached or network over 10G/1G; FRDM-IMX95-PRO first — [#1521](../../issues/1521) — open
- **media-signing** — multi-signer, region- and segment-aware photo and video signing — [xkey/docs/roadmap/media.md](xkey/docs/roadmap/media.md) — open
- **piv-i** — PIV-I profiles with every PIV key on FIPS-validated hardware — [xkey/docs/roadmap/piv.md](xkey/docs/roadmap/piv.md) — open
- **browser-mode** — the Svelte GUI as a browser web app authenticated with WebAuthn — [xkey/docs/roadmap/web.md](xkey/docs/roadmap/web.md) — open

## Dependencies

- Up: go-qrdb v0.47.0-alpha, the layer below, inherited whole and re-exported through `sdk/go` (datastore, clustering, sealing-and-barrier, auth-factors); go-xkms v0.52.0-alpha is built on it ([#1447](../../issues/1447)).
- Up: go-enclave v0.8.0-alpha (sealing-and-barrier) — [#1426](../../issues/1426).
- Up: go-luks2 v1.0.0-rc.4 (luks) — [#1427](../../issues/1427).
- Up: go-qrdb's verifiable-log type with its `HeadSignerProvider` (transparency-log, go-qrdb #721/#722), no version yet.
- Up: go-qrdb's peer-attestation hook, `node.WithPeerAttestationGate` (attested-caller-gate); go-qrdb's per-tenant trust-domain verification of `spiffe://<tenant>/...` (workload-identity), ordered.
- Up, current: go-quicraft v0.20.0 (clustering, through go-qrdb), go-objstore v0.4.0-alpha (certificate-authority), go-truststrap v0.6.0-alpha (trust-bootstrap), go-frost v0.3.0-alpha (frost-threshold-signing), go-codec v1.4.0 (audit-log).
- Down: go-quicbaas composes go-qrdb and go-xkms and waits on the SDK exports [#1442](../../issues/1442) (signing) and [#1480](../../issues/1480) (acme-issuance); xkey-android by wire (phone-hsm, handbook `docs/12`).
- Down: trusted-firmware's xkms adapter provides the AVR backend through backend-registry at v0.52.0-alpha; go-quicbaas composes it by blank import, and at device-attest-01 finalize the adapter assembles the possession request with `sdk/go`'s `AssemblePossessionCSR` (acme-issuance, [trusted-firmware #28](../../../trusted-firmware/issues/28) phase C); xkey ([#1440](../../issues/1440)) takes it by blank import; go-trusted-platform ([#771](../../../go-trusted-platform/issues/771) in that repository) reaches it only through go-quicbaas.
- Down: go-quicbaas consumes tpm-policies by SDK re-export (`Security().TPMPolicy()`, the initrd static-resolver re-exports) ([#1443](../../issues/1443)); go-trusted-platform reaches it only through go-quicbaas.
- Down: go-quicbaas consumes the attested-caller-gate option, SVIDs (workload-identity), `VerifyImage` (image-signing), transparency-log append and trust-roots, and provides the PCR policy.
