# Plan: release-signing-key, CoRIM signer over the repository release key

Row: release-signing-key (docs/SPEC.md:121), epic #1697.

## Objective

go-xkms verifies signed CoRIM reference values (`refvalue.VerifySigned`) and
names one signing key per repository (`appraisal.ReleaseSigningKeyID`,
`pkg/attestation/appraisal/signing_keys.go`), but cannot sign a CoRIM. This
slice adds the signer, so a release pipeline has xkms sign a repository's
CoRIM with that repository's key, and the private key never leaves the
backend (the signer is a `crypto.Signer` only).

## API

- `refvalue.Sign(ctx, unsigned []byte, signer crypto.Signer, alg cose.Algorithm, signerName string) ([]byte, error)`:
  wraps an unsigned CoRIM (CBOR) in a COSE Sign1 with the CoRIM meta header,
  through go-cose `cose.NewSigner` and `(*corim.SignedCorim).Sign`. Refuses a
  nil signer (`ErrNilSigner`), a key go-cose cannot sign with
  (`ErrUnsupportedKey`) and a malformed CoRIM (`ErrMalformed`).
- `(*XKMSService).SignReleaseCoRIM(ctx, req *SignReleaseCoRIMRequest) ([]byte, error)`:
  the tenant comes from the caller's context, like every signing-key method
  (the brief's explicit tenant argument would let a caller sign for another
  tenant); resolves the repository's key with `ResolveSigningKey` (release key
  unless a binding names another), takes the tenant-scoped backend signer and
  calls `refvalue.Sign`. An unknown key returns the backend's not-found error.
- `sdk/go` re-exports `refvalue.Sign` and `SignReleaseCoRIMRequest`.

## Slices

1. Test commit, refvalue: Sign then VerifySigned round-trips for ES256, ES384
   and EdDSA; a wrong key fails with `ErrSignature`; a nil signer and an
   unsupported key type are refused.
2. Feat commit, refvalue: `pkg/attestation/refvalue/sign.go`.
3. Test commit, xkms: SignReleaseCoRIM signs with the resolved release key and
   the output verifies with its public part; an unknown key is not-found.
4. Feat commit, xkms: `pkg/xkms/release_signing.go`, sdk/go re-exports.

## Out of scope

Transports (gRPC, REST, MCP, QUIC, unix), the CLI and its permission wiring:
a later slice.
