- **`xkey device pair` is testable end to end without a phone (#120).**
  `runDevicePair` opens its transport, reads and writes the devices file and
  loads its attestation trust through `pairingSeams`, wired to the BLE
  transport, `devices.yaml` and the trust store in production and replaced
  in tests. Three command-flow tests drive the whole command against a
  simulated phone: a failed attestation under the default policy returns
  before anything is saved, an opted-in policy saves a record with no
  attestation claim, and a verified attestation is recorded. No pairing
  behaviour changes.
