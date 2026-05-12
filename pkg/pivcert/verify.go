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

// Package pivcert provides PIV (Personal Identity Verification) certificate storage abstraction.
package pivcert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// VerifyChain verifies that leaf is trusted by the provided root and intermediate pools,
// and that the certificate includes the ClientAuth extended key usage.
func VerifyChain(leaf *x509.Certificate, roots *x509.CertPool, intermediates *x509.CertPool) error {
	if leaf == nil {
		return &VerifyError{Reason: "leaf certificate is nil"}
	}
	if roots == nil {
		return &VerifyError{Reason: "root pool is nil"}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := leaf.Verify(opts); err != nil {
		return &VerifyChainError{Cause: err}
	}

	return nil
}

// ThumbprintSHA256 returns the hex-encoded SHA-256 digest of the certificate's DER encoding.
func ThumbprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// VerifyError is returned when a certificate fails basic validation.
type VerifyError struct {
	Reason string
}

// Error implements the error interface.
func (e *VerifyError) Error() string {
	return "piv certificate verification failed: " + e.Reason
}

// VerifyChainError is returned when chain verification fails.
type VerifyChainError struct {
	Cause error
}

// Error implements the error interface.
func (e *VerifyChainError) Error() string {
	return "piv certificate chain verification failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *VerifyChainError) Unwrap() error {
	return e.Cause
}
