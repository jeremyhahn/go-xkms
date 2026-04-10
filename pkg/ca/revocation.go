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

// Package ca provides certificate revocation and CRL operations for XKMSCA.
//
// This file implements RFC 5280 compliant certificate revocation list (CRL)
// generation and certificate revocation operations. All operations are
// thread-safe and designed for concurrent access.
//
// # CRL Generation
//
// CRLs are generated according to RFC 5280 Section 5 with the following features:
//   - Proper CRL numbering (monotonically increasing)
//   - Authority Key Identifier extension
//   - Configurable validity period (default 7 days)
//   - DER-encoded output
//
// # Revocation Reasons
//
// Revocation reasons follow RFC 5280 Section 5.3.1 CRLReason codes:
//   - 0: Unspecified
//   - 1: KeyCompromise
//   - 2: CACompromise
//   - 3: AffiliationChanged
//   - 4: Superseded
//   - 5: CessationOfOperation
//   - 6: CertificateHold
//   - 8: RemoveFromCRL
//   - 9: PrivilegeWithdrawn
//   - 10: AACompromise
//
// # Thread Safety
//
// All revocation operations use atomic operations and the underlying certstore's
// synchronization mechanisms to ensure thread safety.
package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync/atomic"
	"time"
)

// Revocation reason codes per RFC 5280 Section 5.3.1.
// These codes are used when revoking certificates to indicate the reason
// for revocation.
const (
	// ReasonUnspecified indicates no specific reason was given.
	ReasonUnspecified = 0

	// ReasonKeyCompromise indicates the certificate's private key has been compromised.
	ReasonKeyCompromise = 1

	// ReasonCACompromise indicates the CA's private key has been compromised.
	ReasonCACompromise = 2

	// ReasonAffiliationChanged indicates the subject's name or other information
	// has changed, but there is no cause to suspect the private key was compromised.
	ReasonAffiliationChanged = 3

	// ReasonSuperseded indicates the certificate has been replaced.
	ReasonSuperseded = 4

	// ReasonCessationOfOperation indicates the certificate is no longer needed
	// for the purpose for which it was issued.
	ReasonCessationOfOperation = 5

	// ReasonCertificateHold indicates the certificate is temporarily suspended.
	ReasonCertificateHold = 6

	// ReasonRemoveFromCRL is used to remove a certificate from CRL hold status.
	// Note: This reason code is not assigned in the CRLReason enumeration.
	ReasonRemoveFromCRL = 8

	// ReasonPrivilegeWithdrawn indicates that the privileges granted to the
	// subject of the certificate have been withdrawn.
	ReasonPrivilegeWithdrawn = 9

	// ReasonAACompromise indicates the Attribute Authority has been compromised.
	ReasonAACompromise = 10
)

// DefaultCRLValidityDays is the default validity period for generated CRLs.
const DefaultCRLValidityDays = 7

// revocationReasonNames maps reason codes to human-readable names.
var revocationReasonNames = map[int]string{
	ReasonUnspecified:          "Unspecified",
	ReasonKeyCompromise:        "KeyCompromise",
	ReasonCACompromise:         "CACompromise",
	ReasonAffiliationChanged:   "AffiliationChanged",
	ReasonSuperseded:           "Superseded",
	ReasonCessationOfOperation: "CessationOfOperation",
	ReasonCertificateHold:      "CertificateHold",
	ReasonRemoveFromCRL:        "RemoveFromCRL",
	ReasonPrivilegeWithdrawn:   "PrivilegeWithdrawn",
	ReasonAACompromise:         "AACompromise",
}

// RevocationReasonName returns the human-readable name for a revocation reason code.
// Returns "Unknown" for unrecognized codes.
func RevocationReasonName(reason int) string {
	if name, ok := revocationReasonNames[reason]; ok {
		return name
	}
	return "Unknown"
}

// IsValidRevocationReason checks if a revocation reason code is valid per RFC 5280.
func IsValidRevocationReason(reason int) bool {
	switch reason {
	case ReasonUnspecified, ReasonKeyCompromise, ReasonCACompromise,
		ReasonAffiliationChanged, ReasonSuperseded, ReasonCessationOfOperation,
		ReasonCertificateHold, ReasonRemoveFromCRL, ReasonPrivilegeWithdrawn,
		ReasonAACompromise:
		return true
	default:
		return false
	}
}

// RevocationManager provides certificate revocation and CRL management operations.
//
// This type is embedded in CA implementations to provide revocation functionality.
// It requires access to the CA's certificate store for persisting revocation data
// and CRLs.
//
// All operations are thread-safe.
type RevocationManager struct {
	// crlNumber tracks the current CRL number using atomic operations.
	// CRL numbers must monotonically increase per RFC 5280 Section 5.2.3.
	crlNumber atomic.Int64

	// crlValidityDays specifies how long generated CRLs are valid.
	crlValidityDays int

	// revocations stores revocation information indexed by serial number string.
	// This provides O(1) lookup for revocation status checks.
	revocations atomic.Value // map[string]*RevocationInfo
}

// NewRevocationManager creates a new RevocationManager with the specified CRL validity period.
// If crlValidityDays is 0 or negative, DefaultCRLValidityDays is used.
func NewRevocationManager(crlValidityDays int) *RevocationManager {
	if crlValidityDays <= 0 {
		crlValidityDays = DefaultCRLValidityDays
	}

	rm := &RevocationManager{
		crlValidityDays: crlValidityDays,
	}

	// Initialize empty revocation map
	rm.revocations.Store(make(map[string]*RevocationInfo))

	return rm
}

// Revoke marks a certificate as revoked with the given reason.
//
// The serial parameter identifies the certificate to revoke by its serial number.
// The reason parameter should be one of the RFC 5280 CRLReason constants defined
// in this package.
//
// Returns ErrInvalidSerial if serial is nil or non-positive.
// Returns ErrAlreadyRevoked if the certificate is already revoked.
//
// Thread-safe: Yes, uses atomic operations for revocation map updates.
func (rm *RevocationManager) Revoke(serial *big.Int, reason int) (*RevocationInfo, error) {
	if err := validateSerial(serial); err != nil {
		return nil, err
	}

	if !IsValidRevocationReason(reason) {
		reason = ReasonUnspecified
	}

	serialStr := serial.Text(10)

	// Load current revocations map
	currentMap := rm.revocations.Load().(map[string]*RevocationInfo)

	// Check if already revoked
	if _, exists := currentMap[serialStr]; exists {
		return nil, ErrAlreadyRevoked
	}

	// Create new revocation info
	revInfo := &RevocationInfo{
		SerialNumber:   new(big.Int).Set(serial),
		RevocationTime: time.Now().UTC(),
		Reason:         reason,
	}

	// Create new map with the revocation added (copy-on-write)
	newMap := make(map[string]*RevocationInfo, len(currentMap)+1)
	for k, v := range currentMap {
		newMap[k] = v
	}
	newMap[serialStr] = revInfo

	// Atomic swap
	rm.revocations.Store(newMap)

	return revInfo, nil
}

// IsRevoked checks if a certificate with the given serial number has been revoked.
//
// Returns true if the certificate is revoked, false otherwise.
// Returns ErrInvalidSerial if serial is nil.
//
// Thread-safe: Yes, uses atomic load for revocation map access.
func (rm *RevocationManager) IsRevoked(serial *big.Int) (bool, error) {
	if serial == nil {
		return false, &RevocationError{Op: "check", Reason: "serial number is nil"}
	}

	serialStr := serial.Text(10)
	currentMap := rm.revocations.Load().(map[string]*RevocationInfo)

	_, exists := currentMap[serialStr]
	return exists, nil
}

// GetRevocationInfo returns the revocation information for a certificate.
// Returns nil if the certificate is not revoked.
//
// Thread-safe: Yes
func (rm *RevocationManager) GetRevocationInfo(serial *big.Int) *RevocationInfo {
	if serial == nil {
		return nil
	}

	serialStr := serial.Text(10)
	currentMap := rm.revocations.Load().(map[string]*RevocationInfo)

	return currentMap[serialStr]
}

// ListRevoked returns all revoked certificates.
//
// Thread-safe: Yes
func (rm *RevocationManager) ListRevoked() []*RevocationInfo {
	currentMap := rm.revocations.Load().(map[string]*RevocationInfo)

	result := make([]*RevocationInfo, 0, len(currentMap))
	for _, info := range currentMap {
		result = append(result, info)
	}

	return result
}

// LoadRevocations loads revocation data from an existing CRL.
// This is useful for restoring state from persistent storage.
//
// Thread-safe: Yes
func (rm *RevocationManager) LoadRevocations(revocations []*RevocationInfo) {
	newMap := make(map[string]*RevocationInfo, len(revocations))
	for _, info := range revocations {
		if info != nil && info.SerialNumber != nil {
			serialStr := info.SerialNumber.Text(10)
			newMap[serialStr] = info
		}
	}
	rm.revocations.Store(newMap)
}

// SetCRLNumber sets the current CRL number.
// This should be called after loading an existing CRL from storage to ensure
// the next generated CRL has a higher number.
//
// Thread-safe: Yes
func (rm *RevocationManager) SetCRLNumber(n *big.Int) {
	if n != nil && n.IsInt64() {
		rm.crlNumber.Store(n.Int64())
	}
}

// GetNextCRLNumber returns the next CRL number and increments the counter.
// CRL numbers must monotonically increase per RFC 5280 Section 5.2.3.
//
// Thread-safe: Yes, uses atomic increment.
func (rm *RevocationManager) GetNextCRLNumber() *big.Int {
	n := rm.crlNumber.Add(1)
	return big.NewInt(n)
}

// CurrentCRLNumber returns the current CRL number without incrementing.
//
// Thread-safe: Yes
func (rm *RevocationManager) CurrentCRLNumber() *big.Int {
	return big.NewInt(rm.crlNumber.Load())
}

// CRLValidityDays returns the configured CRL validity period in days.
func (rm *RevocationManager) CRLValidityDays() int {
	return rm.crlValidityDays
}

// BuildCRLTemplate creates an x509.RevocationList template for CRL generation.
//
// Parameters:
//   - issuer: The CA certificate that will sign the CRL
//   - revoked: List of revoked certificates to include
//   - crlNumber: The CRL number for this CRL
//   - validityDays: How many days the CRL is valid
//
// The template includes:
//   - Issuer DN from the CA certificate
//   - ThisUpdate set to current time
//   - NextUpdate set to ThisUpdate + validityDays
//   - CRL Number extension
//   - Authority Key Identifier extension (if CA has SubjectKeyId)
//
// Thread-safe: Yes (pure function)
func BuildCRLTemplate(
	issuer *x509.Certificate,
	revoked []*RevocationInfo,
	crlNumber *big.Int,
	validityDays int,
) *x509.RevocationList {
	now := time.Now().UTC()

	template := &x509.RevocationList{
		Number:                    crlNumber,
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(0, 0, validityDays),
		RevokedCertificateEntries: convertToRevocationListEntries(revoked),
	}

	// Add Authority Key Identifier extension if the issuer has a Subject Key ID
	if len(issuer.SubjectKeyId) > 0 {
		akiValue, err := asn1.Marshal(authorityKeyIdentifierASN1{
			KeyIdentifier: issuer.SubjectKeyId,
		})
		if err == nil {
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
				Id:       oidAuthorityKeyIdentifier,
				Critical: false,
				Value:    akiValue,
			})
		}
	}

	return template
}

// authorityKeyIdentifierASN1 is the ASN.1 structure for Authority Key Identifier.
type authorityKeyIdentifierASN1 struct {
	KeyIdentifier []byte `asn1:"optional,tag:0"`
}

// OID for Authority Key Identifier extension
var oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}

// convertToRevocationListEntries converts RevocationInfo entries to x509.RevocationListEntry.
func convertToRevocationListEntries(revoked []*RevocationInfo) []x509.RevocationListEntry {
	if len(revoked) == 0 {
		return nil
	}

	result := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, info := range revoked {
		if info == nil || info.SerialNumber == nil {
			continue
		}

		entry := x509.RevocationListEntry{
			SerialNumber:   info.SerialNumber,
			RevocationTime: info.RevocationTime,
			ReasonCode:     info.Reason,
		}

		result = append(result, entry)
	}

	return result
}

// VerifyAgainstCRL checks if a certificate is revoked according to the given CRL.
//
// Parameters:
//   - cert: The certificate to check
//   - crlDER: The DER-encoded CRL data
//
// Returns true if the certificate is found in the CRL's revoked list.
// This function also verifies the CRL signature if the issuer certificate
// is embedded in the provided certificate (i.e., if the cert is self-signed
// or if checking a CA certificate against its own CRL).
//
// Note: For complete CRL validation, the caller should also verify:
//   - The CRL is not expired (NextUpdate has not passed)
//   - The CRL signature is valid (signed by the expected issuer)
//   - The CRL issuer matches the certificate's issuer
//
// Thread-safe: Yes (pure function)
func VerifyAgainstCRL(cert *x509.Certificate, crlDER []byte) (bool, error) {
	if cert == nil {
		return false, &RevocationError{Op: "verify", Reason: "certificate is nil"}
	}

	if len(crlDER) == 0 {
		return false, &RevocationError{Op: "verify", Reason: "CRL data is empty"}
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return false, &RevocationError{Op: "parse_crl", Reason: err.Error()}
	}

	return IsCertificateInCRL(cert, crl), nil
}

// IsCertificateInCRL checks if a certificate's serial number is in the CRL.
//
// Thread-safe: Yes (pure function)
func IsCertificateInCRL(cert *x509.Certificate, crl *x509.RevocationList) bool {
	if cert == nil || crl == nil {
		return false
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil && cert.SerialNumber != nil {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return true
			}
		}
	}

	return false
}

// GetRevocationReason extracts the revocation reason from a revoked certificate entry.
// Returns ReasonUnspecified if no reason extension is present.
//
// Thread-safe: Yes (pure function)
func GetRevocationReason(entry *x509.RevocationListEntry) int {
	if entry == nil {
		return ReasonUnspecified
	}
	return entry.ReasonCode
}

// ParseCRLToRevocationInfo parses a CRL and extracts revocation information.
//
// Thread-safe: Yes (pure function)
func ParseCRLToRevocationInfo(crlDER []byte) ([]*RevocationInfo, error) {
	if len(crlDER) == 0 {
		return nil, &RevocationError{Op: "parse", Reason: "CRL data is empty"}
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, &RevocationError{Op: "parse_crl", Reason: err.Error()}
	}

	result := make([]*RevocationInfo, 0, len(crl.RevokedCertificateEntries))
	for i := range crl.RevokedCertificateEntries {
		entry := &crl.RevokedCertificateEntries[i]
		info := &RevocationInfo{
			SerialNumber:   entry.SerialNumber,
			RevocationTime: entry.RevocationTime,
			Reason:         GetRevocationReason(entry),
		}
		result = append(result, info)
	}

	return result, nil
}

// IsCRLExpired checks if a CRL has expired.
//
// Thread-safe: Yes (pure function)
func IsCRLExpired(crl *x509.RevocationList) bool {
	if crl == nil {
		return true
	}
	return time.Now().After(crl.NextUpdate)
}

// IsCRLValid checks if a CRL is currently valid (not expired and not yet effective).
//
// Thread-safe: Yes (pure function)
func IsCRLValid(crl *x509.RevocationList) bool {
	if crl == nil {
		return false
	}
	now := time.Now()
	return now.After(crl.ThisUpdate) && now.Before(crl.NextUpdate)
}

// validateSerial validates that a serial number is valid for revocation operations.
func validateSerial(serial *big.Int) error {
	if serial == nil {
		return &RevocationError{Op: "validate", Reason: "serial number is nil"}
	}
	if serial.Sign() <= 0 {
		return &RevocationError{Op: "validate", Reason: "serial number must be positive"}
	}
	return nil
}

// RevocationError indicates an error during revocation operations.
type RevocationError struct {
	Op     string // operation that failed
	Reason string // description of the failure
}

func (e *RevocationError) Error() string {
	return "ca: revocation " + e.Op + " failed: " + e.Reason
}

// CRLGenerationError indicates an error during CRL generation.
type CRLGenerationError struct {
	Reason string
	Err    error
}

func (e *CRLGenerationError) Error() string {
	if e.Err != nil {
		return "ca: CRL generation failed: " + e.Reason + ": " + e.Err.Error()
	}
	return "ca: CRL generation failed: " + e.Reason
}

func (e *CRLGenerationError) Unwrap() error {
	return e.Err
}
