# go-xkms roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-13
> Per handbook `software/conventions/roadmap.md`: the Software Department refreshes it; the project agent proposes changes by PR.

## Mission

All hardware and cloud crypto for the stack: TPM2, PKCS#11 (backend and provider module), cloud KMS, FIDO2/WebAuthn/PIV, `TrustedCA` + ACME, trust bootstrap, phone-as-HSM and attestation crypto primitives, exported through `sdk/go` for its own product. Scope and boundaries: [docs/SPEC.md](docs/SPEC.md).

## Milestones

- [Release candidate](../../milestone/14) — RC — due: 2026-11-09 — 10 open / 36 closed — multi-tenancy, auth-factors, webauthn, acme-issuance, init-ceremony, release-engineering, backend-registry; closing criteria in [docs/SPEC.md](docs/SPEC.md#release-criteria)
- [Working fundamentally: 3-node raft + quicbaas surface](../../milestone/30) — release — due: 2026-10-23 — 1 open / 7 closed — release-engineering, sealing-and-barrier

## Complete

- acme-issuance — [docs/acme-issuance/](docs/acme-issuance/) — [#1240](../../issues/1240), [#1480](../../issues/1480), [#828](../../issues/828), [#1511](../../issues/1511)
- attestation-evidence — [docs/attestation-evidence/](docs/attestation-evidence/)
- attestation-verifier — [docs/attestation-verifier/](docs/attestation-verifier/)
- attested-peer — [docs/attested-peer/](docs/attested-peer/)
- audit-log — [docs/audit-log/](docs/audit-log/)
- auth-factors — [docs/auth-factors/](docs/auth-factors/)
- backend-registry — [docs/crypto-backends/](docs/crypto-backends/) — the registration hook, shipped in v0.52.0-alpha
- backend-credentials — [docs/backend-credentials/](docs/backend-credentials/) — [#1450](../../issues/1450), [#1464](../../issues/1464), [#1465](../../issues/1465)
- certificate-authority — [docs/certificate-authority/](docs/certificate-authority/) — [#1438](../../issues/1438)
- clustering — [docs/clustering/](docs/clustering/) — [#1393](../../issues/1393)
- crypto-backends — [docs/crypto-backends/](docs/crypto-backends/) — [#1513](../../issues/1513)
- datastore — [docs/datastore/](docs/datastore/) — [#1345](../../issues/1345)
- dice-device-identity — [docs/dice-device-identity/](docs/dice-device-identity/) — [#658](../../issues/658), [#1510](../../issues/1510)
- escrow — [docs/escrow/](docs/escrow/)
- fido2-ctap2 — [docs/fido2-ctap2/](docs/fido2-ctap2/)
- frost-threshold-signing — [docs/frost-threshold-signing/](docs/frost-threshold-signing/)
- host-embedding — [docs/host-embedding/](docs/host-embedding/)
- init-ceremony — [docs/init-ceremony/](docs/init-ceremony/) — [#1446](../../issues/1446)
- key-management — [docs/key-management/](docs/key-management/)
- luks — [docs/luks/](docs/luks/) — [#1427](../../issues/1427)
- multi-tenancy — [docs/multi-tenancy/](docs/multi-tenancy/)
- observability — [docs/observability/](docs/observability/)
- oidc-credentials — [docs/oidc-credentials/](docs/oidc-credentials/)
- password-vault — [docs/password-vault/](docs/password-vault/)
- pin-management — [docs/pin-management/](docs/pin-management/)
- piv-smartcard — [docs/piv-smartcard/](docs/piv-smartcard/) — [#1095](../../issues/1095), [#1467](../../issues/1467)
- pkcs11-backend — [docs/pkcs11-backend/](docs/pkcs11-backend/)
- pkcs11-provider-module — [docs/pkcs11-provider-module/](docs/pkcs11-provider-module/) — [#1512](../../issues/1512)
- platform-secrets — [docs/platform-secrets/](docs/platform-secrets/)
- post-quantum — [docs/post-quantum/](docs/post-quantum/)
- rbac — [docs/rbac/](docs/rbac/)
- release-engineering — [docs/release-engineering/](docs/release-engineering/) — [#1434](../../issues/1434), [#1483](../../issues/1483), [#1055](../../issues/1055), [#1447](../../issues/1447)
- sealing-and-barrier — [docs/sealing-and-barrier/](docs/sealing-and-barrier/) — [#33](../../issues/33), [#1426](../../issues/1426)
- sign-server — [docs/sign-server/](docs/sign-server/)
- signing — [docs/signing/](docs/signing/) — [#1442](../../issues/1442)
- ssh-agent-sessions — [docs/ssh-agent-sessions/](docs/ssh-agent-sessions/) — [#54](../../issues/54)
- ssh-keys — [docs/ssh-keys/](docs/ssh-keys/)
- ssh-sessions — [docs/ssh-sessions/](docs/ssh-sessions/) — [#1448](../../issues/1448)
- symmetric-aead — [docs/symmetric-aead/](docs/symmetric-aead/) — [#1512](../../issues/1512)
- tpm-policies — [docs/tpm-policies/](docs/tpm-policies/)
- tpm2 — [docs/tpm2/](docs/tpm2/) — [#1466](../../issues/1466), [#1437](../../issues/1437)
- trust-bootstrap — [docs/trust-bootstrap/](docs/trust-bootstrap/)
- user-onboarding — [docs/user-onboarding/](docs/user-onboarding/) — [#1294](../../issues/1294)
- web-console — [docs/web-console/](docs/web-console/)
- webauthn — [docs/webauthn/](docs/webauthn/)
- xkmsd-configuration — [docs/xkmsd-configuration/](docs/xkmsd-configuration/) — [#140](../../issues/140)

## Now

- multi-tenancy — [docs/multi-tenancy/](docs/multi-tenancy/) — [#1406](../../issues/1406) unix scope: absent identity is the platform, no system-tenant lift — RC — open
- auth-factors — [docs/auth-factors/](docs/auth-factors/) — [#1402](../../issues/1402) go-qrdb `DecoyEnroller` for every hardware factor — open
- certificate-authority — [docs/certificate-authority/](docs/certificate-authority/) — [#1518](../../issues/1518) SDK re-exports the RFC 5280 CRL reason codes — open
- backend-registry — [docs/crypto-backends/](docs/crypto-backends/) — [#1439](../../issues/1439) steps 3 and 4: remove pkg/backend/avr, sdk/go backends_avr, the AVR enums, the agsim scripts, the four arduino-generic requires and docs/avr-device-backend/, and make comments device-neutral — RC — blocked: until trusted-firmware releases its xkms adapter and go-trusted-platform #771 and xkey #1440 have switched
- backend-registry — [docs/crypto-backends/](docs/crypto-backends/) — [#1440](../../issues/1440) xkey reaches AVR devices through trusted-firmware's xkms adapter by blank import — RC — blocked: until trusted-firmware releases its xkms adapter
- sealing-and-barrier — [docs/sealing-and-barrier/](docs/sealing-and-barrier/) — [#623](../../issues/623) hand-rolled `GuardedBuffer` retired for go-enclave — milestone 30 — open
- release-engineering — [docs/release-engineering/](docs/release-engineering/) — [#1332](../../issues/1332) PR test code cannot reach the release runner's Docker daemon — RC — open

## Next

- auth-factors — [docs/auth-factors/](docs/auth-factors/) — [#1380](../../issues/1380) go-qrdb unified authentication chain adopted — blocked: see issue
- init-ceremony — [docs/init-ceremony/](docs/init-ceremony/) — [#794](../../issues/794) SDK clients present the init-issued admin certificate — blocked: see issue
- webauthn — [docs/webauthn/](docs/webauthn/) — [#1468](../../issues/1468) WebAuthn stops writing the email into qrdb's `Username` — blocked: see issue
- release-engineering — [docs/release-engineering/](docs/release-engineering/) — [#1333](../../issues/1333) private-module token out of untrusted CI job environments — blocked: see issue
- release-engineering — [docs/release-engineering/](docs/release-engineering/) — [#1475](../../issues/1475) spec-review scrub of `docs/` for the RC — blocked: see issue
- release-engineering — [docs/release-engineering/](docs/release-engineering/) — [#1030](../../issues/1030) public-release readiness checklist — blocked: the rest of the RC milestone

## Later

- acme-issuance — [docs/acme-issuance/](docs/acme-issuance/) — [#743](../../issues/743), [#746](../../issues/746) ACME admin listeners (gRPC, QUIC, MCP, unix) and the desktop admin GUI hosted by xkmsd; [#744](../../issues/744) finalize through `pkg/acme/issuance` with goodkey and zlint; [#745](../../issues/745) CT precertificates and SCT embedding — open
- tpm-policies — [docs/tpm-policies/](docs/tpm-policies/) — [#1443](../../issues/1443) protected seals for a predicted boot state, for unattended upgrade unlock — blocked: see issue
- sealing-and-barrier — [docs/sealing-and-barrier/](docs/sealing-and-barrier/) — [#1415](../../issues/1415) hardware-rooted go-enclave `KeyProtector` / `RootUnsealer`; [#677](../../issues/677) PKCS#11 PIN sealed to the TPM; [#1355](../../issues/1355) unified share-holder API replaces `ceremony.ShareService` — open
- clustering — [docs/clustering/](docs/clustering/) — [#1381](../../issues/1381) go-qrdb cluster CA signer seam and CSR enrollment — blocked: see issue
- release-engineering — [docs/release-engineering/](docs/release-engineering/) — [#23](../../issues/23) CI gate under `fips140=only`; [#342](../../issues/342) CI jobs off the public Ubuntu archive — open

## Future

- hsm-device-protocol — [#1521](../../issues/1521) wire protocol between xkmsd and HSM devices, direct-attached or network over 10G/1G; FRDM-IMX95-PRO first — future

## xkey

### Complete

- agent — [xkey/docs/agent/](xkey/docs/agent/) — [#671](../../issues/671)
- agent-automation — [xkey/docs/agent-automation/](xkey/docs/agent-automation/)
- autofill — [xkey/docs/autofill/](xkey/docs/autofill/)
- ble — [xkey/docs/ble/](xkey/docs/ble/)
- browser-trust-injection — [xkey/docs/browser-trust-injection/](xkey/docs/browser-trust-injection/)
- device — [xkey/docs/device/](xkey/docs/device/)
- fido2 — [xkey/docs/fido2/](xkey/docs/fido2/)
- gui — [xkey/docs/gui/](xkey/docs/gui/)
- headless-webauthn — [xkey/docs/headless-webauthn/](xkey/docs/headless-webauthn/)
- xkey-luks — [xkey/docs/luks/](xkey/docs/luks/) — [#1427](../../issues/1427)
- oath — [xkey/docs/oath/](xkey/docs/oath/)
- oidc — [xkey/docs/oidc/](xkey/docs/oidc/) — [#4](../../issues/4)
- password — [xkey/docs/password/](xkey/docs/password/)
- phone — [xkey/docs/phone/](xkey/docs/phone/)
- phone-hsm — [xkey/docs/phone-hsm/](xkey/docs/phone-hsm/)
- piv — [xkey/docs/piv/](xkey/docs/piv/)
- pkcs11 — [xkey/docs/pkcs11/](xkey/docs/pkcs11/)
- pkcs11-manager — [xkey/docs/pkcs11-manager/](xkey/docs/pkcs11-manager/)
- platform-trust — [xkey/docs/platform-trust/](xkey/docs/platform-trust/)
- seal — [xkey/docs/seal/](xkey/docs/seal/) — [#669](../../issues/669)
- secret-service — [xkey/docs/secret-service/](xkey/docs/secret-service/)
- setup-wizard — [xkey/docs/setup-wizard/](xkey/docs/setup-wizard/) — [#432](../../issues/432)
- ssh — [xkey/docs/ssh/](xkey/docs/ssh/)
- usb — [xkey/docs/usb/](xkey/docs/usb/)
- virtual-authenticator — [xkey/docs/virtual-authenticator/](xkey/docs/virtual-authenticator/)
- xkeysigner — [xkey/docs/xkeysigner/](xkey/docs/xkeysigner/)

### Now

None.

### Next

None.

### Later

- ca — [docs/SPEC.md#xkey](docs/SPEC.md#xkey) (planned) — [#729](../../issues/729) standalone xkey CA: local `TrustedCA` (`xkey ca --local`) or remote-only with the GUI `CAService` in remote mode — blocked: decision pending on local `TrustedCA` versus remote-only
- oath — [xkey/docs/oath/](xkey/docs/oath/) — [#864](../../issues/864) wire or retire `CompositeStore` and the `staticpw` encrypted, PIN-access and session stores — blocked: see issue
- password — [xkey/docs/password/](xkey/docs/password/) — [#864](../../issues/864) wire or retire `CompositeStore` and the `staticpw` encrypted, PIN-access and session stores — blocked: see issue
- phone-hsm — [xkey/docs/phone-hsm/](xkey/docs/phone-hsm/) — [#128](../../issues/128) per-request generation in the pairing wire protocol for full duplicate-response protection — open

### Future

- media-signing — [xkey/docs/roadmap/media.md](xkey/docs/roadmap/media.md)
- piv-i — [xkey/docs/roadmap/piv.md](xkey/docs/roadmap/piv.md)
- browser-mode — [xkey/docs/roadmap/web.md](xkey/docs/roadmap/web.md)

## Dependencies

- Up: go-qrdb v0.47.0-alpha (datastore, clustering, sealing-and-barrier, auth-factors); go-xkms v0.52.0-alpha is built on it ([#1447](../../issues/1447)).
- Up: go-enclave v0.8.0-alpha (sealing-and-barrier) — [#1426](../../issues/1426).
- Up: go-luks2 v1.0.0-rc.4 (luks) — [#1427](../../issues/1427).
- Up, current: go-quicraft v0.20.0 (clustering, through go-qrdb), go-objstore v0.4.0-alpha (certificate-authority), go-truststrap v0.6.0-alpha (trust-bootstrap), go-frost v0.3.0-alpha (frost-threshold-signing), go-codec v1.4.0 (audit-log).
- Down: go-quicbaas waits on the SDK exports [#1442](../../issues/1442) (signing) and [#1480](../../issues/1480) (acme-issuance); xkey-android by wire (phone-hsm, handbook `docs/12`).
- Down: trusted-firmware's xkms adapter provides the AVR backend through backend-registry at v0.52.0-alpha; go-trusted-platform ([#771](../../../go-trusted-platform/issues/771) in that repository) and xkey ([#1440](../../issues/1440)) take it by blank import.
