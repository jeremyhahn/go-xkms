# Reference specifications

> **Status: REFERENCE** · Last verified: 2026-10-16
> Index of the public specifications kept in `docs/references/` and the code that implements each.

Public specification documents this project implements against. Nothing here
is proprietary; each entry is a publicly published standard, kept locally so
implementation work does not depend on the publisher's site staying up.

- `TCG-TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.00-r12.pdf` — TCG
  "TPM 2.0 Keys for Device Identity and Attestation", v1.00 r12. IAK/IDevID
  key templates, the TCG-CSR-IDEVID enrollment structure, and the identity
  provisioning strategies `pkg/tpm2` implements (`ParseIdentityProvisioningStrategy`).
- `TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.10r9_pub.pdf` — the
  same TCG specification, revision v1.10 r9 (public review draft). Kept
  alongside v1.00 r12 rather than replacing it: this project's IAK/IDevID
  code was implemented and is tested against r12, and the two revisions are
  compared here before any migration, not silently swapped.
- `DWG_Smart-Card_CCID_Rev110.pdf` — USB Implementers Forum, "Universal Serial
  Bus Device Class: Smart Card CCID", revision 1.10. USB CCID framing used by
  PIV/smart-card integration.
- `kmip-spec-v1.4-os.pdf` — OASIS "Key Management Interoperability Protocol
  Specification", version 1.4.
- `NIST.SP.800-73pt1-5.pdf`, `NIST.SP.800-73pt2-5.pdf`, `NIST-SP-800-73pt3.pdf`
  — NIST SP 800-73, "Interfaces for Personal Identity Verification", parts
  1-3, the PIV card application and data model `pkg/factor/piv` and
  `pkg/pivcert` target.
- `rfc-8555.txt` — IETF RFC 8555, "Automatic Certificate Management
  Environment (ACME)", the protocol `pkg/acme/server` implements.
  [RFC_8555_COMPLIANCE.md](RFC_8555_COMPLIANCE.md) maps each section to its
  implementation and conformance test.
- `NIST.SP.800-76-2.pdf` — NIST SP 800-76-2, "Biometric Specifications for
  Personal Identity Verification".
- `NIST.SP.800-78-5.pdf` — NIST SP 800-78-5, "Cryptographic Algorithms and Key
  Sizes for Personal Identity Verification".
- `pkcs11-3.2.html`, `pkcs11-v3.0-to-v3.2-changes.md` — OASIS PKCS#11
  Cryptographic Token Interface, version 3.2, and its changes from 3.0, the
  API `pkg/pkcs11` and `cmd/pkcs11-module` implement.
- `rats/` — the IETF RATS, EAT, CoRIM, CMW, CSR-attestation and ACME
  device-attestation specifications, indexed in [rats/README.md](rats/README.md).
