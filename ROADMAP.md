# go-xkms roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-16

## Mission

Hardware crypto, auth factors, KMS, CA, ACME and TPM policies as services on go-qrdb, with every go-qrdb service re-exported through `sdk/go`.
Scope and boundaries: [docs/SPEC.md](docs/SPEC.md).

## Milestones

- [Working fundamentally: 3-node raft + quicbaas surface](../../milestone/30) — release — due 2026-11-04 — 1 open / 7 closed
- [Dev complete](../../milestone/14) — RC — due 2026-11-09 — 19 open / 42 closed

## Complete

- attested-peer: attestation-evidence, attested-caller-gate, attested-peer
- auth-factors: auth-factors, fido2-ctap2, webauthn, piv-smartcard, user-onboarding, password-vault, oidc-credentials
- certificate-authority: certificate-authority, trust-bootstrap
- crypto: crypto-backends, backend-registry, backend-credentials, key-management, signing, symmetric-aead, post-quantum, frost-threshold-signing, escrow
- deployment: clustering, datastore, host-embedding, init-ceremony, xkmsd-configuration, observability, web-console, release-engineering
- pkcs11-backend: pkcs11-backend, pkcs11-provider-module
- rbac: rbac, multi-tenancy, audit-log, authz-cli-roles, authz-loopback-admin, authz-owner-grant, authz-rest-role-ctx, tenant-subject-ou
- ssh-keys: ssh-keys, ssh-sessions, ssh-agent-sessions, sign-server
- tpm2: tpm2, dice-device-identity, sealing-and-barrier, platform-secrets, pin-management, luks
- xkey fido2: fido2, headless-webauthn, virtual-authenticator, phone, phone-hsm, ble, device, agent, agent-automation
- xkey gui: gui, setup-wizard, seal, xkey-luks, ssh, platform-trust
- xkey password: password, oath, oidc, autofill, secret-service, browser-trust-injection
- xkey piv: piv, pkcs11, pkcs11-manager, xkeysigner, usb

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

- **platform-pcr-selection** — the board's boot PCRs for the platform policy, `TPMConfig.PlatformPCRs` (default 7 and 11) — [#1443](../../issues/1443), [#1551](../../issues/1551) — open
- **ca** — standalone xkey CA, local or remote-only — [#729](../../issues/729) — blocked: decision pending
- **ota-image-keys** — one OTA image-signing key per trusted-firmware board id — [SPEC](docs/SPEC.md#features) — open
- [Dev complete](../../milestone/14): authz-admin-grants, authz-admin-perms-field, authz-admin-routes, authz-cert-ou-roles, authz-method-tables, authz-platform-scope, authz-role-id, authz-role-reconcile, authz-tenant-bind, authz-tenant-cross, authz-ui-matrix, authz-xkey-uid0 — open; authz-claim-roles, authz-device-onboarding, authz-holds-role, authz-object-owner, authz-peercred-roles, authz-permission-vocabulary, authz-shared-password — blocked: go-qrdb gap; authz-tenant-iam — blocked: go-qrdb #683

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
