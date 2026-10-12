# go-xkms roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-12
> Per handbook `software/conventions/roadmap.md`: the Software Department refreshes it; the project agent proposes changes by PR.

## Mission

All hardware and cloud crypto for the stack: TPM2, PKCS#11 (backend and provider module), cloud KMS, FIDO2/WebAuthn/PIV, `TrustedCA` + ACME, trust bootstrap, phone-as-HSM and attestation crypto primitives, exported through `sdk/go` for its own product (handbook `docs/00` L1, L5, §R).

## Current milestone

- [Release candidate](../../milestone/14) — RC — projected: department plan
- [Working fundamentally: 3-node raft + quicbaas surface](../../milestone/30) — release — projected: 2026-10-23

## Now

- [#1332](../../issues/1332) — PR test code cannot reach the release runner's Docker daemon — [docs/release-engineering/](docs/release-engineering/) — open
- [#1393](../../issues/1393) — SPIFFE node URI stamped from a verified identity — [docs/clustering/](docs/clustering/) — open
- [#1465](../../issues/1465) — backend credential values unreadable through the platform-secrets API — [docs/platform-secrets/](docs/platform-secrets/) — open
- [#1467](../../issues/1467) — PIV login module refuses evidence a strict verifier rejects — [docs/piv-smartcard/](docs/piv-smartcard/) — open
- [#1095](../../issues/1095) — PIV login honours the user's permitted-auth-method policy — [docs/auth-factors/](docs/auth-factors/) — open
- [#1437](../../issues/1437) — `AnswerCredentialChallenge` loads a non-persistent EK — [docs/tpm2/](docs/tpm2/) — open
- [#1466](../../issues/1466) — `pkg/tpm2` cross-compiles: `linuxudstpm` behind a build tag — [docs/tpm2/](docs/tpm2/) — open
- [#1464](../../issues/1464) — `xkmsctl credential list` calls the served route — [docs/backend-credentials/](docs/backend-credentials/) — open
- [#1406](../../issues/1406) — unix scope: absent identity is the platform, no system-tenant lift — [docs/multi-tenancy/](docs/multi-tenancy/) — open
- [#33](../../issues/33) — protected memory sets `PR_SET_DUMPABLE=0` — `docs/memory-protection/` (to add) — open
- [#1434](../../issues/1434) — `make lint` runs actionlint, `make security` requires trivy — [docs/release-engineering/](docs/release-engineering/) — open

## Next

- [#828](../../issues/828) — ACME attestation challenges bind the attested device to the authorized identifier — [docs/acme-issuance/](docs/acme-issuance/) — open
- [#1380](../../issues/1380) — go-qrdb unified authentication chain adopted — [docs/auth-factors/](docs/auth-factors/) — open
- [#1240](../../issues/1240) — tenant users authenticate on the ACME admin plane — [docs/acme-issuance/](docs/acme-issuance/) — blocked: see issue
- [#794](../../issues/794) — SDK clients present the init-issued admin certificate — [docs/init-ceremony/](docs/init-ceremony/) — blocked: see issue
- [#1468](../../issues/1468) — WebAuthn stops writing the email into qrdb's `Username` — [docs/webauthn/](docs/webauthn/) — blocked: see issue
- [#1333](../../issues/1333) — private-module token out of untrusted CI job environments — [docs/release-engineering/](docs/release-engineering/) — blocked: see issue
- [#1483](../../issues/1483) — tiered CI with ref-keyed cancel-in-progress — [docs/release-engineering/](docs/release-engineering/) — open
- [#1433](../../issues/1433) — docs conform: feature folders, banners — [docs/README.md](docs/README.md) — open
- [#1475](../../issues/1475) — spec-review scrub of `docs/` for the RC — [docs/README.md](docs/README.md) — blocked: see issue
- [#1030](../../issues/1030) — public-release readiness checklist — [docs/release-engineering/](docs/release-engineering/) — blocked: the rest of the RC milestone

### Working fundamentally (milestone 30)

- [#1442](../../issues/1442) — SDK exports `SignerStorer`, `SignerOpts`, `NewSignerStore` — [docs/signing/](docs/signing/) — open
- [#1480](../../issues/1480) — SDK re-exports `NewDeviceProfileHook` and tpm2 `ErrAuthFailed` — [docs/acme-issuance/](docs/acme-issuance/) — open
- [#1446](../../issues/1446) — `EnrollAdminFactors` preflight refuses a FIDO2 factor with no handler — [docs/init-ceremony/](docs/init-ceremony/) — open
- [#1055](../../issues/1055) — nightly integration tests read arduino-generic — [docs/release-engineering/](docs/release-engineering/) — open
- [#1447](../../issues/1447) — a go-xkms tag built on go-qrdb v0.47.0-alpha — [docs/release-engineering/](docs/release-engineering/) — blocked: go-qrdb v0.47.0-alpha
- [#1426](../../issues/1426) — go-enclave v0.8.0-alpha adopted — `docs/memory-protection/` (to add) — blocked: see issue
- [#623](../../issues/623) — hand-rolled `GuardedBuffer` retired for go-enclave — `docs/memory-protection/` (to add) — blocked: see issue

## Later

- [#743](../../issues/743), [#746](../../issues/746) — ACME admin listeners and admin GUI hosted by xkmsd — `docs/acme-web-ui/` (to add) — open
- [#745](../../issues/745) — CT/SCT handling at issuance — [docs/acme-issuance/](docs/acme-issuance/) — open
- [#23](../../issues/23) — CI gate under `fips140=only` — `docs/fips/` (to convert) — open
- [#1415](../../issues/1415) — hardware-rooted go-enclave `KeyProtector` — `docs/memory-protection/` (to add) — open

## xkey

- Next: [#1427](../../issues/1427) — go-luks2 v1.0.0-rc.2 adopted — [xkey/docs/luks/](xkey/docs/luks/), [docs/luks/](docs/luks/) — blocked: see issue
- Later: [#704](../../issues/704) — xkey packages at 90% coverage — `xkey/docs/testing/` (to convert) — open
- Later: [#729](../../issues/729) — standalone xkey CA — `xkey/docs/ca/` (to add) — open
- Later: [#730](../../issues/730) — PKCS#11 provider backed by xkey — [xkey/docs/pkcs11/](xkey/docs/pkcs11/) — open
- Later: [xkey/docs/roadmap/](xkey/docs/roadmap/) — media signing, PIV-I, browser mode designs — no issue yet

## Dependencies

- Up: go-qrdb v0.46.0-alpha, needs v0.47.0-alpha ([#1447](../../issues/1447)).
- Up: go-enclave v0.7.0-alpha, needs v0.8.0-alpha ([#1426](../../issues/1426)).
- Up: go-luks2 v0.5.0-alpha, needs v1.0.0-rc.2 ([#1427](../../issues/1427)).
- Up, current: go-quicraft v0.19.0, go-objstore v0.3.0-alpha, go-truststrap v0.4.0-alpha, go-frost v0.3.0-alpha, go-codec v1.4.0, arduino-generic v0.7.0-alpha.
- Down: go-quicbaas waits on the SDK exports [#1442](../../issues/1442) and [#1480](../../issues/1480); xkey-android by wire (handbook `docs/12`).

## Non-goals

- Everything §R of handbook [docs/00](../../../handbook/src/branch/main/software/docs/00-ownership-and-sdk-boundary.md) assigns to another owner.
