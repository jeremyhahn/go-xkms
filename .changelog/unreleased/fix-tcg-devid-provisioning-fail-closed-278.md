- **Device identity provisioning fails closed.** `Install` used to discard
  the EK certificate lookup error (`ekCert, _ :=`), log a failed
  `CreateIDevID` as "continuing without it", ignore every IDevID lookup
  answer other than TPM_RC_HANDLE, and return success — a device with no
  IDevID reported itself provisioned. Under TCG "TPM 2.0 Keys for Device
  Identity and Attestation" v1.00 r12 the ceremony either completes or the
  device has no identity: the TCG-CSR-IDEVID carries the EK certificate
  (§6.2.2 step 4b) and the CA verifies it before issuing (step 6b). Each site
  now refuses with a typed error — `ErrDevIDProvisionEKCert`,
  `ErrDevIDProvisionIDevID`, `ErrDevIDProvisionIAK`,
  `ErrDevIDProvisionLookup` — with the cause reachable through `errors.Is`.
  A platform whose EK certificate is not in NV RAM or the certificate store
  must provision it (`ProvisionEKCert`) before asking for an IDevID, or
  install without the `IDevID` option. A quote the TPM refuses while building
  the CSR's `prodCaData` is likewise refused (`ErrTCGCSRAttestation`) instead
  of being dropped from the CSR; absence of a transport to quote over is
  still reported as an absent field, as §13.1 allows.

- **TCG-CSR-IDEVID emitted to §13.1.** Three departures fixed in the
  structure the device sends to the CA: `TCG_CSR_IDEVID.structVer` is now
  `0x01000100` ("Version 1.0 = 0x01000100"; the leading `0x01` identifies an
  IDevID CSR) where the content structure's `0x00000100` was written before;
  the pad is `padSz` bytes of random data from the TPM's RNG, not a `=`
  filler; and `hashAlgoId`/`hashSz` both describe the signer's hash — the
  IAK's under the IAK strategy, the IDevID's under single-pass — where they
  were taken from two different keys and agreed only while both used SHA-256.
  Exported as `TCGCSRIDevIDStructVer`, `TCGIDevIDContentStructVer` and
  `TCGCSRAlignment`. The parser (`UnmarshalIDevIDCSR`) is unchanged and
  accepts both structure versions, so a CA on this release still enrolls
  devices on the previous one. Pinned by a reader written from the
  specification's field list (`tcg_csr_structure_simulator_test.go`) that
  never consults the packer under test.

- **`pkg/tpm2` runs in CI.** `make test` greps `pkg/tpm2` out of its package
  list, so no simulator suite — the TCG policy vectors, the CSR structure
  test, the provisioning tests — had ever run in CI. New targets
  `test-tpm2-simulator`, `coverage-tpm2-simulator` and
  `bench-tpm2-simulator` run the package under the
  `codec_cbor codec_json codec_msgpack tpm_simulator` tags, and the CI job
  `tpm2-simulator` invokes the first. The job is not yet in the `ci-gate`
  needs list.
