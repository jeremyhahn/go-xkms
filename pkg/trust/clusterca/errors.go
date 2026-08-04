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

package clusterca

import "fmt"

// ErrMissingOption is returned by New when a required Options field is unset
// for the selected provisioning mode.
type ErrMissingOption struct {
	// Field names the missing Options field.
	Field string

	// Mode names the provisioning mode that requires it.
	Mode string
}

// Error implements the error interface.
func (e *ErrMissingOption) Error() string {
	return "clusterca: option " + e.Field + " is required in " + e.Mode + " mode"
}

// ErrFileRead is returned when an operator-supplied PEM file cannot be read.
type ErrFileRead struct {
	// Field is the ExplicitFiles field name.
	Field string

	// Path is the offending file path.
	Path string

	// Err is the underlying I/O error.
	Err error
}

// Error implements the error interface.
func (e *ErrFileRead) Error() string {
	return fmt.Sprintf("clusterca: explicit file %s: cannot read %q: %v", e.Field, e.Path, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrFileRead) Unwrap() error { return e.Err }

// ErrLeafDecode is returned when an issued or cached node leaf PEM cannot be
// decoded. Node startup must fail rather than serve a malformed certificate.
type ErrLeafDecode struct{}

// Error implements the error interface.
func (e *ErrLeafDecode) Error() string {
	return "clusterca: node leaf PEM did not decode"
}

// ErrExistingCAWithoutStagedCerts is returned when the first-node pre-stage
// finds CA identity keys already present in the keystores but no staged
// certificates in the cache. Generating a fresh hierarchy would silently fork
// a second root, so provisioning fails closed. This occurs when growing an
// existing standalone node into a cluster: enable cluster ACME mode, restart
// once so the running CA mirrors its certificates into the cluster-ca cache,
// then add members.
type ErrExistingCAWithoutStagedCerts struct {
	// Identity is the common name whose key was found.
	Identity string
}

// Error implements the error interface.
func (e *ErrExistingCAWithoutStagedCerts) Error() string {
	return "clusterca: CA key for identity " + e.Identity + " already exists but no staged " +
		"certificates were found — refusing to generate a second root. To grow an existing " +
		"node into a cluster: enable cluster ACME mode, restart once (the CA mirrors its " +
		"certificates into the cluster-ca cache), then add members"
}

// ErrAnchorMismatch is returned when an enrolled or cached node certificate
// does not chain to the cluster trust anchor.
type ErrAnchorMismatch struct {
	// Reason describes the verification failure.
	Reason string
}

// Error implements the error interface.
func (e *ErrAnchorMismatch) Error() string {
	return "clusterca: node certificate does not verify against the cluster trust anchor: " + e.Reason
}

// ErrSPIFFEMismatch is returned when an enrolled certificate's SPIFFE node
// SAN does not match this node's expected identity.
type ErrSPIFFEMismatch struct {
	// Expected is the SPIFFE URI this node expects.
	Expected string

	// Got lists the URI SANs found in the certificate.
	Got []string
}

// Error implements the error interface.
func (e *ErrSPIFFEMismatch) Error() string {
	return fmt.Sprintf("clusterca: enrolled certificate SPIFFE SAN mismatch: expected %s, got %v (is the "+
		"pre-sign hook registered on the ACME server and this node present in its cluster membership?)",
		e.Expected, e.Got)
}

// ErrACMEBackendUnsupported is returned when ACME-attested mode is configured
// with a key backend that has no enrollment path yet (only tpm2 enroll-01 is
// implemented; the software/pkcs11 CSR variant is tracked separately).
type ErrACMEBackendUnsupported struct {
	// KeyBackend is the configured backend name.
	KeyBackend string
}

// Error implements the error interface.
func (e *ErrACMEBackendUnsupported) Error() string {
	return "clusterca: ACME-attested enrollment for key backend " + e.KeyBackend +
		" is not implemented (tpm2 enroll-01 only)"
}

// ErrNoTPM is returned when the tpm2 enrollment path cannot obtain a
// TrustedPlatformModule from the resolved backend.
type ErrNoTPM struct {
	// KeyBackend is the configured backend name.
	KeyBackend string
}

// Error implements the error interface.
func (e *ErrNoTPM) Error() string {
	return "clusterca: backend " + e.KeyBackend + " does not expose a TPM (TrustedPlatformModule required for enroll-01)"
}

// ErrNoSecureCAKeyProtection is returned when no secure protection is available
// for the cluster CA keystore (no TPM/HSM sealer and no passphrase) and
// insecure/plaintext mode is not explicitly enabled.
type ErrNoSecureCAKeyProtection struct{}

// Error implements the error interface.
func (e *ErrNoSecureCAKeyProtection) Error() string {
	return "clusterca: no secure cluster CA key protection available — configure a TPM/HSM " +
		"seal backend or a passphrase, or explicitly enable insecure mode for development/testing"
}

// ErrSealerUnavailable is returned when a hardware key-protection mode is
// selected but no usable sealer is present.
type ErrSealerUnavailable struct {
	// Mode is the requested protection mode.
	Mode string
}

// Error implements the error interface.
func (e *ErrSealerUnavailable) Error() string {
	return "clusterca: key-protection mode " + e.Mode + " requires a usable TPM/HSM sealer, none available"
}

// ErrSealBlobCorrupt is returned when the cached sealed CA-key password blob
// cannot be decoded.
type ErrSealBlobCorrupt struct {
	// Path is the sealed blob path.
	Path string

	// Err is the underlying decode error.
	Err error
}

// Error implements the error interface.
func (e *ErrSealBlobCorrupt) Error() string {
	return "clusterca: sealed CA-key blob " + e.Path + " is corrupt: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrSealBlobCorrupt) Unwrap() error { return e.Err }
