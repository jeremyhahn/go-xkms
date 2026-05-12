# Challenge Types

The ACME client supports multiple challenge types for domain validation. Select the appropriate type based on your environment.

## Standard ACME Challenges

### http-01

Proves control of a domain by serving a token file at `http://{domain}/.well-known/acme-challenge/{token}`. Requires port 80 access.

### dns-01

Proves control by creating a `_acme-challenge.{domain}` TXT record. Works for wildcard certificates and systems without public HTTP access.

### tls-alpn-01

Proves control via a self-signed certificate with the ACME ALPN extension on port 443. No separate port or DNS access needed.

## Trusted Computing Challenges

### device-attest-01

TPM-based device attestation challenge. The client provides a TPM quote and signature to prove platform integrity. Requires a TPM with enrolled attestation key.

### endorse-01

Endorsement key-based challenge using the TPM's manufacturer-provisioned EK certificate to prove hardware identity.

### enroll-01

Device enrollment challenge that combines EK certificate verification with attestation key creation to bootstrap trust for new devices.

## Configuration

Set the default challenge type in the Configuration view or override per-request in the Request Certificate view. Challenge-specific settings are managed in the Challenges view.
