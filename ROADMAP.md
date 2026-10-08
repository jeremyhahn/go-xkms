# go-xkms roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Per handbook `software/conventions/roadmap.md`: the Software Department refreshes it; the project agent proposes changes by PR.

## Mission

All hardware and cloud crypto for the stack: TPM2, PKCS#11, cloud KMS, WebAuthn/FIDO2/PIV, `TrustedCA` + ACME, trust bootstrap, phone-as-HSM, the SSH surface and attestation crypto primitives. Exported for its own product only; not a database server (handbook `docs/00` L1, L5).

## Current milestone

`Public release` milestone (M14): 2 open, 0 closed. Release candidate projected **2026-10-29**, bound by go-qrdb. The milestone holds 1 of 38 open issues, so Now below is the proposed RC scope.

## Now

- #1428 — go-qrdb v0.46 everywhere — in review
- #1426 — go-enclave v0.8.0-alpha adopted — open
- #1427 — go-luks2 v1.0.0-rc.2 adopted — open
- #33 — PR_SET_DUMPABLE=0 via go-qrdb (go-qrdb#554 closed 2026-10-01) — blocked: needs the go-qrdb bump
- #1332 — PR jobs cannot reach the release builder's Docker daemon (critical) — open
- #1333 — private-module token out of untrusted job environments — open
- #1334 — signed, verified release artifacts — open

## Next

- #1409 — release tag carrying #1407 for go-quicbaas — open
- #1393 — SPIFFE node URI bound to a verified identity — open
- #828 — ACME challenge binds the attested device to the identifier — open
- #1095 — PIV login honours the permitted-auth-method policy — open
- #1380 — go-qrdb unified authentication chain — open
- #1381 — go-qrdb cluster CA signer seam and CSR enrollment — open
- #23 — FIPS gate under `fips140=only` — blocked

## Later

- #743–#746 — ACME admin API, issuance finalize, CT/SCT, admin GUI
- #677 — PKCS#11 PIN sealed to the TPM
- #1415 — hardware-rooted go-enclave KeyProtector

### xkey

- Now: #704 — xkey packages at 90% coverage — open
- Next: #729 — standalone xkey CA — open; #730 — PKCS#11 provider backed by xkey — open; #864 — wire or retire oath and staticpw stores — open
- Later: `xkey/docs/roadmap/` designs (media signing, PIV-I, browser mode) — issues to file

## Dependencies

- Up: go-qrdb v0.28.1-alpha (latest v0.46.0-alpha), go-quicraft v0.15.0-alpha (v0.20.0), go-enclave v0.6.1-alpha (v0.8.0-alpha), go-luks2 v0.2.0-alpha (v1.0.0-rc.2), go-objstore, go-truststrap, go-frost, go-codec, arduino-generic.
- Down: go-quicbaas (pins v0.49.0-alpha), go-trusted-platform residue (v0.17.0-alpha), xkey-android by wire (handbook `docs/12`).

## Non-goals

- Database and data-plane surfaces: go-qrdb. Composition and the attestation Verifier: go-quicbaas.
