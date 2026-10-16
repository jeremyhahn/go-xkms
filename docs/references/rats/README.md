# RATS and attestation specifications

> **Status: REFERENCE** · Last verified: 2026-10-16
> Index of the remote-attestation specifications kept in `docs/references/rats/` and the code that implements each.

The IETF RATS, EAT, CoRIM, CMW, CSR-attestation and ACME device-attestation
specifications this project implements against, kept locally byte for byte
as published.

- `rfc9334.txt` — IETF RFC 9334, "Remote ATtestation procedureS (RATS)
  Architecture". The roles and evidence model of `pkg/attestation`: the
  evidence primitives in `pkg/attestation/evidence` (re-exported by
  `sdk/go/evidence`), the signed reference values in
  `pkg/attestation/refvalue`, and the verifier in `pkg/attestation`.
- `rfc9711.txt` — IETF RFC 9711, "The Entity Attestation Token (EAT)". The
  `ueid` and `eat_nonce` claims: `pkg/attestation/dice` reads and produces
  them in the UCCS evidence of a DICE alias certificate, the verifier in
  `pkg/attestation` checks the `eat_nonce` echo, and
  `pkg/acme/challenges/device-attest-01` matches the `ueid` against its
  device registry.
- `rfc9781.txt` — IETF RFC 9781, "A Concise Binary Object Representation
  (CBOR) Tag for Unprotected CBOR Web Token Claims Sets (UCCS)".
  `pkg/attestation/dice` (`uccs.go`) reads and produces the UCCS claims set
  of the tcg-dice-UCCS-evidence extension, and
  `pkg/acme/challenges/device-attest-01` reads it from the possession CSR.
- `rfc9782.txt` — IETF RFC 9782, "Entity Attestation Token (EAT) Media
  Types". Not yet implemented.
- `rfc9999.txt` — IETF RFC 9999, "Remote ATtestation procedureS (RATS)
  Conceptual Message Wrapper (CMW)". Not yet implemented.
- `rfc10013.txt` — IETF RFC 10013, "Entity Attestation Token (EAT) Measured
  Component". Not yet implemented.
- `rfc9683.txt` — IETF RFC 9683, "Remote Integrity Verification of Network
  Devices Containing Trusted Platform Modules" (RIV). The TPM attestation
  path: `pkg/tpm2` produces the TPM2_Quote (`TPM2.Quote`),
  `pkg/attestation/evidence` verifies the quote, the AK and EK chains and
  the event log, and the verifier in `pkg/attestation` appraises it.
  go-quicbaas consumes the verifier as go-qrdb's attested-caller gate
  through `sdk/go` `WithAttestedCallerGate` (SPEC attested-caller-gate).
- `draft-ietf-rats-corim-11.txt` — IETF draft-ietf-rats-corim, revision 11,
  "Concise Reference Integrity Manifest". Pinned at this revision;
  compliance means this revision until the RFC is published. The signed
  CoRIM reference values of `pkg/attestation/refvalue`, re-exported by
  `sdk/go/evidence`, which the verifier in `pkg/attestation` replays.
- `draft-ietf-lamps-csr-attestation-29.txt` — IETF
  draft-ietf-lamps-csr-attestation, revision 29, "Use of Remote Attestation
  with Certification Signing Requests". Pinned at this revision; compliance
  means this revision until the RFC is published. CSR attestation at
  issuance in `pkg/ca` and `pkg/acme`. The draft's evidence attribute is
  not yet implemented: issuance is gated today by the key-binding
  invariants of `pkg/attestation` and by device-attest-01's possession CSR,
  which carries TCG DICE evidence.
- `draft-ietf-acme-device-attest-10.txt` — IETF
  draft-ietf-acme-device-attest, revision 10, "Automatic Certificate
  Management Environment (ACME) Device Attestation Extension". Pinned at
  this revision; compliance means this revision until the RFC is
  published. The device-attest-01 challenge of
  `pkg/acme/challenges/device-attest-01`, served by `pkg/acme/server` and
  answered by `pkg/acme/client`. go-quicbaas composes it through `sdk/go`
  `AssemblePossessionCSR` (SPEC acme-issuance).
