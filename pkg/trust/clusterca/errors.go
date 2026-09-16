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

// ErrACMEBackendUnsupported is returned when a JOINING node in ACME-attested
// mode is configured with a key backend that cannot satisfy the attestation
// the cluster CA's ACME server requires of a joining node's identity. For an
// IP or permanent-identifier authorization — what a Raft node's address maps
// to — the ACME server offers only the enroll-01, endorse-01, and
// device-attest-01 challenges (see pkg/acme/server/handlers/new_order.go
// createChallenges), and every one of them is satisfiable only by a backend
// that exposes a real TPM 2.0: an Endorsement Key certificate, an
// Attestation Identity Key, and PCR quote / credential-activation. Software
// keys and PKCS#11 tokens can sign and decrypt but cannot produce any of
// that, so there is no challenge on this server's directory a non-tpm2
// backend can complete — this is a protocol boundary, not a missing code
// path.
//
// The security property lost without it is hardware-bound proof of node
// identity: with TPM attestation, the cluster CA confirms the joining key
// is non-exportable and resident in a specific, previously-known physical
// device. Without it, the CA can confirm only that some private key signed
// the join CSR — it cannot tell a legitimate operator's software or
// PKCS#11 key apart from one created by an attacker who obtained network
// access to the join listener, cloned a disk image, or briefly touched a
// key store. Any of those lets an impostor obtain a valid Raft mTLS
// certificate and join as a peer.
//
// A software or PKCS#11 node joins a cluster today through one of the two
// modes that do not depend on ACME attestation: hardware-resident node-key
// mode (set Options.KeyBackend, leave Options.ACME nil) or the default
// software auto-enrollment mode (leave both unset).
type ErrACMEBackendUnsupported struct {
	// KeyBackend is the configured backend name.
	KeyBackend string
}

// Error implements the error interface.
func (e *ErrACMEBackendUnsupported) Error() string {
	return "clusterca: ACME-attested cluster join requires TPM attestation (enroll-01/endorse-01/" +
		"device-attest-01 — the only challenges the cluster CA offers for a joining node's identity); " +
		"key backend " + e.KeyBackend + " has no Endorsement Key, Attestation Identity Key, or quote/" +
		"credential-activation capability to satisfy any of them, so the CA cannot verify the joining " +
		"key is non-exportable and bound to a known device — anyone who can run the joiner with a " +
		e.KeyBackend + " key could otherwise impersonate a cluster member; join instead with " +
		"KeyBackend set and ACME unset (hardware-resident node-key mode), or with the default " +
		"software auto-enrollment mode"
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
