- **IDevID and IAK certificates now carry the subjectAltName TCG "TPM 2.0 Keys
  for Device Identity and Attestation" v1.00 r12 §8.1 makes a SHALL.** The
  extension holds two otherNames: an RFC 4108 `hardwareModuleName` with the TPM
  2.0 hwType 2.23.133.1.2 and an hwSerialNum of `<TCG TPM manufacturer
  code>:<EK authority key identifier>:<EK certificate serial number>`, and an
  RFC 4043 `permanentIdentifier` whose assigner is `tcg-on-ekPermIdSha256`
  (2.23.133.12.1) and whose identifierValue is `hex(SHA-256(EK certificate
  DER))`. Neither reached a certificate before: the hardware module name
  builder was never called and emitted a standalone extension under the
  otherName's own OID rather than inside subjectAltName, and the permanent
  identifier carried the product model and serial with no assigner. Both are
  now derived from the endorsement key certificate the TCG-CSR-IDEVID carries;
  a request without one, or whose TPM manufacturer code cannot be determined
  from that certificate or from the new `CertificateRequest.TPMManufacturer`,
  is refused rather than certified with a name that identifies the wrong TPM.

- **The §8.2 TCG assertions are issued as certificate policies only, and the
  fixed and restricted assertions are no longer combined.** §8.2 defines
  `tcg-cap-verifiedTPMResidency`, `-Fixed` and `-Restricted` as policy
  identifiers carrying "No data"; the boolean-valued standalone extensions that
  also claimed them are removed. §8.2 further makes each of the fixed and
  restricted assertions a MUST NOT beside the other: an IAK certificate now
  carries residency and restricted, an IDevID residency and fixed. The extended
  key usage gains "the one TCG OID most appropriate for the type of key used"
  per §8.1 — the restricted OID on an attestation key, the fixed OID on an
  identity key — beside the TLS usages.

- **`ErrTCGMandatoryExtension` refuses issuance when an extension TCG DevID
  §8.1 requires cannot be built.** Extension construction discarded its errors
  (`if ext, err := ...; err == nil`), so a certificate could be issued
  asserting less than the CA had verified with nothing reporting why.

- **An IDevID's key usage is `digitalSignature` alone.** §8.1 Table 22 reserves
  the encryption usages for a Combined key, which the TCG-CSR verifier refuses
  to accept. The device model
  moves from `tcg-at-tpmModel` to `tcg-at-platformModel` and the device serial
  number out of `tcg-at-tpmVersion` into the subject's `serialNumber`
  attribute, where §8.1 asks for it; the two TPM OIDs name the TPM's own model
  and firmware version, not the platform's.
