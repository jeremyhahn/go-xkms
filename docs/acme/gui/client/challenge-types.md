# Challenge Types

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on the challenge types known to the ACME client (`pkg/acme/client/types.go:160-177`).

The GUI's Challenges view (`ChallengeConfig.svelte`) shows a read-only card
for each type below. Nothing is configured from the GUI.

## Standard ACME challenges

### http-01

Proves control of a domain by serving a token at
`http://{domain}/.well-known/acme-challenge/{token}`. Needs port 80.

### dns-01

Proves control with a `_acme-challenge.{domain}` TXT record. Works for
wildcards and for hosts without public HTTP.

### tls-alpn-01

Proves control with a self-signed certificate carrying the ACME ALPN extension
on port 443. The constant exists, but the default `SupportedChallenges` list
(`pkg/acme/client/trustedca_config.go:195`) does not include it.

## Trusted computing challenges

### device-attest-01

TPM-based device attestation. The client proves platform identity with
TPM-backed attestation evidence.

### endorse-01

Uses the TPM's manufacturer-provisioned EK certificate to prove hardware identity.

### enroll-01

Device enrollment that combines EK verification with attestation-key creation
to bootstrap trust for a new device.

## Choosing a challenge

Each certificate spec in the client YAML config names its challenge
(`certificates.<name>.challenge`, `CertificateSpec` at
`pkg/acme/client/service/config.go:84`). Solver settings for http-01 and
dns-01 live under the top-level `challenge` key (`ChallengeConfig`,
`config.go:257`). See [configuration.md](configuration.md).
