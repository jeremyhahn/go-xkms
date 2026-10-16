// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package image signs and verifies container images.
//
// A Signer signs with a KMS crypto.Signer (TPM, PKCS#11 or cloud KMS),
// never a key file, certified by TrustedCA's code-signing profile. It
// attests an image digest in a DSSE envelope over an in-toto statement,
// optionally timestamps the envelope through an RFC 3161 TSA, and pushes
// the attestation both as an OCI 1.1 referrer of the image and to the
// image's cosign "sha256-<hex>.att" tag, so cosign verify-attestation
// reads either.
//
// A Verifier reads an image's attestations, referrers first and the ".att"
// tag as fallback, and accepts the first whose envelope signature, subject
// digest, optional timestamp and code-signing chain to a trust-roots root
// all verify.
package image
