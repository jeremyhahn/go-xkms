# Attestation Evidence — User Guide

> **Status: NORMATIVE** · Feature: `attestation-evidence` · Repo: `go-xkms` · Last verified: 2026-10-01

## Verify a TPM quote from a remote machine

You have, from the attester: the AK certificate (PEM), the TPMS_ATTEST bytes,
the signature, the PCR values it reported, and optionally its firmware event
log. You have, from your own configuration: the AK trust anchors and the
nonce you sent.

1. Verify the AK certificate with `VerifyAKCertificate`. Keep the returned
   key; nothing else is trusted to verify the quote.
2. Verify the quote with `VerifyQuote`. On success the reported PCR values
   are proven: they are what the TPM signed.
3. If you have the event log, parse it with `ParseEventLog` and check it
   with `VerifyEventLog(log, quote.Bank, reported)`. On success the events
   explain the values, so you can appraise the events instead of opaque
   digests.
4. Compare against reference values with `ComparePCRs`, or hand the proven
   values to your verifier.

## Reading failures

`errors.Is(err, evidence.ErrForged)` means the evidence is wrong: treat it
as an incident. `errors.Is(err, evidence.ErrAbsent)` means a check could
not run (missing nonce, no anchors, an unaccepted bank): fix collection or
configuration. `err.Error()` names the check and the reason.

## Verify a device's endorsement key

`ParseEKCertificateChain` accepts the DER certificate or a PEM bundle with
intermediates; `VerifyEKCertificate` needs the TPM manufacturers' roots.
There is no mode without anchors.
