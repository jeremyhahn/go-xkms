// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// OrderFinalizeHookContext contains all the contextual information available
// to order finalization hooks. This allows applications integrating with the
// CA to perform custom logic upon successful order finalization.
type OrderFinalizeHookContext struct {
	// Context is the request context
	Context context.Context

	// Order is the finalized ACME order
	Order *entities.ACMEOrder

	// Certificate is the issued certificate
	Certificate *x509.Certificate

	// CertificatePEM is the PEM-encoded certificate chain
	CertificatePEM []byte

	// CSR is the original certificate signing request
	CSR *x509.CertificateRequest

	// ClientIP is the IP address of the client that submitted the order
	ClientIP string

	// IsTCGCSR indicates if this was a TCG-CSR-IDEVID enrollment
	IsTCGCSR bool

	// TCGData contains TCG-specific data (only populated if IsTCGCSR is true)
	TCGData *TCGEnrollmentData
}

// TCGEnrollmentData contains TPM/TCG-specific enrollment information
// available when finalizing a TCG-CSR-IDEVID order.
type TCGEnrollmentData struct {
	// ProductModel is the device product model from the TCG CSR
	ProductModel string

	// ProductSerial is the device product serial number from the TCG CSR
	ProductSerial string

	// PermanentIdentifier is the device permanent identifier
	PermanentIdentifier string

	// EKCertificate is the Endorsement Key certificate
	EKCertificate *x509.Certificate

	// IAKCertificateDER is the DER-encoded IAK certificate
	IAKCertificateDER []byte

	// IDevIDCertificateDER is the DER-encoded IDevID certificate
	IDevIDCertificateDER []byte

	// AttestationPublicKey is the attestation key public portion
	AttestationPublicKey []byte

	// SigningPublicKey is the signing key public portion
	SigningPublicKey []byte

	// EventLog is the TCG event log (from BootEvntLog field)
	EventLog []byte

	// ProdCaData contains CA-specific attestation data (Quote + PCRs)
	// from the TCG-CSR-IDEVID ProdCaData field. Per TCG specification,
	// this field is used for CA-specific required data. This implementation
	// uses it to carry the device's initial attestation state (TPM Quote
	// and PCR values) to the CA during enrollment.
	//
	// Use tpm2.UnpackProdCaData() to extract the attestation data:
	//   prodCaData, err := tpm2.UnpackProdCaData(tcgData.ProdCaData)
	//   if err == nil && prodCaData != nil {
	//       quote := prodCaData.ToQuote()
	//       // quote.EventLog is nil - use tcgData.EventLog instead
	//       quote.EventLog = tcgData.EventLog
	//       // Now store the complete attestation: quote, PCRs, eventlog
	//   }
	ProdCaData []byte
}

// OrderFinalizeHook is a function that gets called after an order has been
// successfully finalized and a certificate has been issued. Hooks receive
// contextual information about the order and certificate.
//
// Hooks should return an error if they fail. When a hook returns an error,
// the finalization process will be rolled back and the order will not be
// marked as valid.
//
// Example use cases for hooks:
//   - Registering DNS records for issued certificates
//   - Recording device enrollment in a device inventory system
//   - Sending notifications about certificate issuance
//   - Enforcing custom policy checks
//   - Logging certificate issuance events
type OrderFinalizeHook func(ctx *OrderFinalizeHookContext) error

// OrderFinalizeHookRegistry manages registered order finalization hooks.
type OrderFinalizeHookRegistry struct {
	hooks []OrderFinalizeHook
}

// NewOrderFinalizeHookRegistry creates a new hook registry.
func NewOrderFinalizeHookRegistry() *OrderFinalizeHookRegistry {
	return &OrderFinalizeHookRegistry{
		hooks: make([]OrderFinalizeHook, 0),
	}
}

// Register adds a new hook to the registry.
func (r *OrderFinalizeHookRegistry) Register(hook OrderFinalizeHook) {
	r.hooks = append(r.hooks, hook)
}

// Execute runs all registered hooks in order. If any hook returns an error,
// execution stops and the error is returned.
func (r *OrderFinalizeHookRegistry) Execute(ctx *OrderFinalizeHookContext) error {
	for _, hook := range r.hooks {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Count returns the number of registered hooks.
func (r *OrderFinalizeHookRegistry) Count() int {
	return len(r.hooks)
}

// =============================================================================
// Pre-Issuance Hooks
// =============================================================================

// PreIssuanceHookContext contains contextual information available to
// pre-issuance hooks. These hooks execute BEFORE certificate signing,
// enabling validation and compliance checks that can block certificate issuance.
type PreIssuanceHookContext struct {
	// Context is the request context
	Context context.Context

	// Order is the ACME order being finalized
	Order *entities.ACMEOrder

	// CSR is the certificate signing request (nil for TCG-CSR-IDEVID)
	CSR *x509.CertificateRequest

	// ClientIP is the IP address of the client that submitted the order
	ClientIP string

	// IsTCGCSR indicates if this is a TCG-CSR-IDEVID enrollment
	IsTCGCSR bool

	// TCGData contains TCG-specific data (only populated if IsTCGCSR is true)
	TCGData *TCGEnrollmentData

	// ComplianceData contains the signed compliance report from the device
	// (only populated if the device submitted compliance data)
	ComplianceData *ComplianceData

	// ComplianceConfig is the resolved compliance configuration for this enrollment
	// (per-tenant or global fallback)
	ComplianceConfig *ComplianceConfig
}

// ComplianceData contains a signed compliance report from the device.
// The report is typically generated by a compliance scanner (e.g., Trivy)
// running on the device and signed with the device's attestation key.
type ComplianceData struct {
	// Timestamp is when the compliance scan was performed
	Timestamp time.Time `json:"timestamp"`

	// ScanType identifies the scanner that produced this report
	// Common values: "trivy", "openscap", "custom"
	ScanType string `json:"scanType"`

	// Report is the raw scan output in JSON format
	Report json.RawMessage `json:"report"`

	// Signature is the report signed by the device's attestation key
	Signature []byte `json:"signature"`

	// SignatureAlg is the algorithm used for signing
	// Examples: "RSA-PSS-SHA256", "ECDSA-P256-SHA256", "Ed25519"
	SignatureAlg string `json:"signatureAlg"`
}

// Type aliases for compliance configuration types from entities package.
// These are defined in entities to avoid circular imports since TenantSettings
// references ComplianceConfig.
type (
	// ComplianceConfig defines compliance requirements for certificate issuance.
	ComplianceConfig = entities.ComplianceConfig

	// GlobalComplianceConfig is the server-wide default compliance configuration.
	GlobalComplianceConfig = entities.GlobalComplianceConfig
)

// ResolveComplianceConfig is an alias to the entities package function.
// It determines the effective compliance configuration for an enrollment
// based on the global and tenant settings.
var ResolveComplianceConfig = entities.ResolveComplianceConfig

// PreIssuanceHook is a function that executes BEFORE certificate signing.
// Hooks can validate compliance, attestation, or any other criteria and
// return an error to block certificate issuance.
//
// Example use cases:
//   - Validating Trivy compliance scan results
//   - Verifying TPM attestation (PCR values, event log)
//   - Enforcing device profile/expected state matching
//   - Custom policy enforcement
type PreIssuanceHook func(ctx *PreIssuanceHookContext) error

// PreIssuanceHookRegistry manages registered pre-issuance hooks.
type PreIssuanceHookRegistry struct {
	hooks []PreIssuanceHook
}

// NewPreIssuanceHookRegistry creates a new pre-issuance hook registry.
func NewPreIssuanceHookRegistry() *PreIssuanceHookRegistry {
	return &PreIssuanceHookRegistry{
		hooks: make([]PreIssuanceHook, 0),
	}
}

// Register adds a new hook to the registry.
func (r *PreIssuanceHookRegistry) Register(hook PreIssuanceHook) {
	r.hooks = append(r.hooks, hook)
}

// Execute runs all registered hooks in order. If any hook returns an error,
// execution stops and the error is returned, blocking certificate issuance.
func (r *PreIssuanceHookRegistry) Execute(ctx *PreIssuanceHookContext) error {
	for _, hook := range r.hooks {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Count returns the number of registered hooks.
func (r *PreIssuanceHookRegistry) Count() int {
	return len(r.hooks)
}
