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

// Package ca provides an embedded CA service that bridges the SDK transport
// CA operations to the go-xkms XKMSCA implementation for standalone mode.
package ca

import "errors"

// Configuration errors indicate issues with service setup.
var (
	// ErrNilCA is returned when a nil XKMSCA is provided to the service.
	ErrNilCA = errors.New("xkey/ca: certificate authority is required")

	// ErrNilConfig is returned when a nil configuration is provided.
	ErrNilConfig = errors.New("xkey/ca: configuration is required")
)

// Request validation errors indicate issues with incoming requests.
var (
	// ErrNilRequest is returned when a nil request is provided.
	ErrNilRequest = errors.New("xkey/ca: request is required")

	// ErrEmptyCSR is returned when a CSR request contains no CSR data.
	ErrEmptyCSR = errors.New("xkey/ca: CSR PEM data is required")

	// ErrEmptyCommonName is returned when a certificate issuance request
	// has no common name specified.
	ErrEmptyCommonName = errors.New("xkey/ca: common name is required")

	// ErrEmptySerialNumber is returned when a revocation or status check
	// has no serial number specified.
	ErrEmptySerialNumber = errors.New("xkey/ca: serial number is required")

	// ErrInvalidSerialNumber is returned when a serial number cannot be parsed.
	ErrInvalidSerialNumber = errors.New("xkey/ca: invalid serial number format")
)

// TCG enrollment errors indicate failures during TCG Trusted Computing operations.
var (
	// ErrTCGCertIssuance is returned when a TCG certificate issuance fails.
	ErrTCGCertIssuance = errors.New("xkey/ca: failed to issue tcg certificate")

	// ErrTCGCSRSigning is returned when TCG-CSR-IDEVID signing fails.
	ErrTCGCSRSigning = errors.New("xkey/ca: failed to sign tcg-csr-idevid")

	// ErrTCGEnrollment is returned when TCG device enrollment fails.
	ErrTCGEnrollment = errors.New("xkey/ca: failed to enroll device")

	// ErrNilTCGCSR is returned when a nil TCG-CSR-IDEVID is provided.
	ErrNilTCGCSR = errors.New("xkey/ca: tcg-csr-idevid is required")

	// ErrEmptyPackedCSR is returned when an empty packed CSR is provided.
	ErrEmptyPackedCSR = errors.New("xkey/ca: packed csr data is required")
)

// Operation errors indicate failures during CA operations.
var (
	// ErrCANotInitialized is returned when the underlying CA has not been
	// initialized or loaded.
	ErrCANotInitialized = errors.New("xkey/ca: certificate authority not initialized")

	// ErrBundleGeneration is returned when CA bundle retrieval fails.
	ErrBundleGeneration = errors.New("xkey/ca: failed to retrieve CA bundle")

	// ErrCACertificateRetrieval is returned when the CA certificate cannot
	// be retrieved.
	ErrCACertificateRetrieval = errors.New("xkey/ca: failed to retrieve CA certificate")

	// ErrCSRSigning is returned when CSR signing fails.
	ErrCSRSigning = errors.New("xkey/ca: failed to sign CSR")

	// ErrCertificateIssuance is returned when certificate issuance fails.
	ErrCertificateIssuance = errors.New("xkey/ca: failed to issue certificate")

	// ErrCertificateRevocation is returned when certificate revocation fails.
	ErrCertificateRevocation = errors.New("xkey/ca: failed to revoke certificate")

	// ErrCRLGeneration is returned when CRL generation fails.
	ErrCRLGeneration = errors.New("xkey/ca: failed to generate CRL")

	// ErrRevocationCheck is returned when a revocation status check fails.
	ErrRevocationCheck = errors.New("xkey/ca: failed to check revocation status")

	// ErrPEMEncoding is returned when PEM encoding of a certificate fails.
	ErrPEMEncoding = errors.New("xkey/ca: failed to encode certificate as PEM")
)
