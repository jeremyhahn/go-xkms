# go-xkms roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-16

## Mission

Hardware crypto, auth factors, KMS, CA, ACME and TPM policies as services on go-qrdb, with every go-qrdb service re-exported through `sdk/go`.
Scope and boundaries: [docs/SPEC.md](docs/SPEC.md).

## Milestones

- [Working fundamentally: 3-node raft + quicbaas surface](../../milestone/30) — release — due 2026-11-04 — 1 open / 7 closed
- [Dev complete](../../milestone/14) — RC — due 2026-11-09 — 18 open / 38 closed

## Complete

- **attestation-evidence** — RFC 9334 evidence primitives in `sdk/go/evidence` — [v0.48.0-alpha](../../releases/tag/v0.48.0-alpha) — done
- **attested-caller-gate** — `pkg/attestation/peergate` behind go-qrdb's peer-attestation gate — [#1544](../../issues/1544) — done
- **attested-peer** — quote-to-verdict peer attestation behind go-qrdb's attested-caller gate — [v0.9.5-alpha](../../releases/tag/v0.9.5-alpha) — done
- **audit-log** — xkms product audit events into go-qrdb's audit logger — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **auth-factors** — hardware factor adapters behind go-qrdb's `Factor` interface — [v0.9.0-alpha](../../releases/tag/v0.9.0-alpha) — done
- **authz-cli-roles** — xkmsctl on go-qrdb's role names — [#1557](../../issues/1557) — done
- **authz-loopback-admin** — loopback identity by go-qrdb role ID — [#1557](../../issues/1557) — done
- **authz-owner-grant** — the redundant Owner grant removed — [#1557](../../issues/1557) — done
- **authz-rest-role-ctx** — unused role context helpers removed — [#1557](../../issues/1557) — done
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

- **tpm-policies** — unattended unlock across updates, steps 1 and 2 — [#1443](../../issues/1443) — open
- **attestation-verifier** — event-log replay against signed CoRIM reference values — [#1443](../../issues/1443) — open
- **acme-issuance** — `sdk/go` `AssemblePossessionCSR` for device-attest-01 finalize — [trusted-firmware #28](../../../trusted-firmware/issues/28) — open

## Next

- **acme-issuance** — admin listeners, goodkey/zlint finalize, CT precertificates — [#743](../../issues/743), [#744](../../issues/744), [#745](../../issues/745), [#746](../../issues/746) — open
- **trust-roots** — one purpose-classified root store on a qrdb DAO — [Dev complete](../../milestone/14) — open
- **image-signing** — DSSE/in-toto image signatures as OCI referrers with `VerifyImage` — [Dev complete](../../milestone/14) — open
- **transparency-log** — CA transparency log on go-qrdb's verifiable-log type — [Dev complete](../../milestone/14) — blocked: go-qrdb #721/#722
- **workload-identity** — tenant as SPIFFE trust domain, SVIDs through ACME — [Dev complete](../../milestone/14) — blocked: go-qrdb `spiffe://<tenant>/...` support

## Later

- **platform-pcr-selection** — PCR 16 or the board's boot PCRs for the platform policy — [#1443](../../issues/1443) — blocked: decision pending
- **ca** — standalone xkey CA, local or remote-only — [#729](../../issues/729) — blocked: decision pending
- **ota-image-keys** — one OTA image-signing key per trusted-firmware board id — [SPEC](docs/SPEC.md#features) — open
- **authz-admin-grants** — module permissions granted per role with declared duties — [Dev complete](../../milestone/14) — open
- **authz-admin-perms-field** — ACME admin decisions from go-qrdb's authorizer, not token claims — [Dev complete](../../milestone/14) — open
- **authz-admin-routes** — each ACME admin route under its own permission — [Dev complete](../../milestone/14) — open
- **authz-cert-ou-roles** — subject OU read as the tenant, roles from go-qrdb bindings — [Dev complete](../../milestone/14) — open
- **authz-claim-roles** — roles from go-qrdb, not IdP or token claims — [Dev complete](../../milestone/14) — blocked: go-qrdb gap
- **authz-device-onboarding** — onboarding as users:invite and device-onboarding permissions — [Dev complete](../../milestone/14) — blocked: go-qrdb gap
- **authz-holds-role** — role membership from go-qrdb — [Dev complete](../../milestone/14) — blocked: go-qrdb gap
- **authz-method-tables** — method permissions declared on the proto and module seams — [Dev complete](../../milestone/14) — open
- **authz-object-owner** — object tenancy on go-qrdb's tenant rule — [Dev complete](../../milestone/14) — blocked: go-qrdb gap
- **authz-peercred-roles** — peer-credential roles by go-qrdb role ID — [Dev complete](../../milestone/14) — blocked: go-qrdb gap
- **authz-permission-vocabulary** — go-qrdb's permission constants, xkms-only ones registered — [Dev complete](../../milestone/14) — blocked: go-qrdb gap
- **authz-platform-scope** — system-tenant checks as cross-scoped permissions — [Dev complete](../../milestone/14) — open
- **authz-role-id** — role lookup by go-qrdb role ID and name — [Dev complete](../../milestone/14) — open
- **authz-role-reconcile** — built-in roles reconciled by go-qrdb — [Dev complete](../../milestone/14) — open
- **authz-shared-password** — shared-password override as a go-qrdb permission — [Dev complete](../../milestone/14) — blocked: go-qrdb gap
- **authz-tenant-bind** — target tenant from go-qrdb's tenant rules — [Dev complete](../../milestone/14) — open
- **authz-tenant-cross** — tenant CRUD under go-qrdb's cross-tenant permissions — [Dev complete](../../milestone/14) — open
- **authz-tenant-iam** — cross-tenant user and role administration — [Dev complete](../../milestone/14) — blocked: go-qrdb #683
- **authz-ui-matrix** — UI permissions from go-qrdb's permission listing — [Dev complete](../../milestone/14) — open
- **authz-xkey-uid0** — xkey audit access by `audit:read` — [Dev complete](../../milestone/14) — open
- **tenant-subject-ou** — the tenant as subject OU on every issued certificate — [Dev complete](../../milestone/14) — open

## Future

- **hsm-device-protocol** — xkmsd-to-HSM-device wire protocol, FRDM-IMX95-PRO first — [#1521](../../issues/1521) — open
- **hsm-self-defence** — lockdown or key wipe as predetermined HSM device responses — [SPEC](docs/SPEC.md#features) — open
- **media-signing** — multi-signer photo and video signing — [xkey/docs/roadmap/media.md](xkey/docs/roadmap/media.md) — open
- **piv-i** — PIV-I profiles on FIPS-validated hardware — [xkey/docs/roadmap/piv.md](xkey/docs/roadmap/piv.md) — open
- **browser-mode** — the GUI as a WebAuthn-authenticated web app — [xkey/docs/roadmap/web.md](xkey/docs/roadmap/web.md) — open

## Dependencies

- Up: go-qrdb v0.47.0-alpha (re-exported through `sdk/go`), go-enclave v0.8.0-alpha, go-luks2 v1.0.0-rc.4, go-quicraft v0.20.0, go-objstore v0.4.0-alpha, go-truststrap v0.6.0-alpha, go-frost v0.3.0-alpha, go-codec v1.4.0.
- Up, needed: go-qrdb verifiable log (#721/#722), `node.WithPeerAttestationGate`, per-tenant `spiffe://` verification.
- Down: go-quicbaas (SDK re-exports: [#1442](../../issues/1442), [#1480](../../issues/1480), [#1443](../../issues/1443)), trusted-firmware's xkms adapter ([#28](../../../trusted-firmware/issues/28)), xkey ([#1440](../../issues/1440)), xkey-android by wire; go-trusted-platform only through go-quicbaas.
