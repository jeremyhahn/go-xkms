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

package pairing

// PIV slot identifiers following the NIST SP 800-73 standard.
// These map to the standard PIV application key slots used in smart cards.
const (
	// PIVSlotAuthentication is slot 9a, used for PIV card authentication.
	PIVSlotAuthentication = "9a"

	// PIVSlotDigitalSignature is slot 9c, used for digital signatures.
	PIVSlotDigitalSignature = "9c"

	// PIVSlotKeyManagement is slot 9d, used for key management (encryption/decryption).
	PIVSlotKeyManagement = "9d"

	// PIVSlotCardAuth is slot 9e, used for card authentication (contactless).
	PIVSlotCardAuth = "9e"
)

// PIV method names for bidirectional PIV-like certificate-based key management
// between laptop and phone. These methods enable PIV slot-based key generation,
// certificate import, slot listing, signing, and certificate retrieval.
//
// Protocol Direction:
//   - local.*  methods: Laptop sends TO phone (operates on phone's keystore)
//   - remote.* methods: Phone sends TO laptop (operates on laptop's xkms)
const (
	// MethodLocalPIVGenerateKey requests the phone to generate a key in a PIV slot.
	MethodLocalPIVGenerateKey = "local.pivGenerateKey"

	// MethodLocalPIVImportCert sends a certificate to the phone for a PIV slot.
	MethodLocalPIVImportCert = "local.pivImportCert"

	// MethodLocalPIVListSlots requests the list of PIV slot contents on the phone.
	MethodLocalPIVListSlots = "local.pivListSlots"

	// MethodLocalPIVSign requests the phone to sign using a PIV slot key.
	MethodLocalPIVSign = "local.pivSign"

	// MethodLocalPIVGetCert requests the certificate from a PIV slot on the phone.
	MethodLocalPIVGetCert = "local.pivGetCert"

	// MethodRemotePIVListSlots is sent by the phone to request the laptop's
	// PIV slot contents.
	MethodRemotePIVListSlots = "remote.pivListSlots"

	// MethodRemotePIVSign is sent by the phone to request the laptop to sign
	// using a PIV slot key.
	MethodRemotePIVSign = "remote.pivSign"

	// MethodRemotePIVGetCert is sent by the phone to request a certificate
	// from a laptop's PIV slot.
	MethodRemotePIVGetCert = "remote.pivGetCert"
)

// PIVSlotInfo describes the contents and state of a single PIV slot.
type PIVSlotInfo struct {
	Slot           string `json:"slot"`                   // 9a, 9c, 9d, 9e
	Label          string `json:"label,omitempty"`        // Human-readable name
	Algorithm      string `json:"algorithm,omitempty"`    // ECDSA-P256, RSA-2048, etc.
	HasKey         bool   `json:"has_key"`                // True if a key is present in slot
	HasCertificate bool   `json:"has_certificate"`        // True if a certificate is present
	CertSubject    string `json:"cert_subject,omitempty"` // CN from cert
	CertExpiry     string `json:"cert_expiry,omitempty"`  // ISO 8601 expiry
}

// --- local.pivGenerateKey ---

// LocalPIVGenerateKeyParams contains parameters for local.pivGenerateKey.
// The laptop requests the phone to generate a key in a specific PIV slot.
type LocalPIVGenerateKeyParams struct {
	Slot      string `json:"slot"`            // PIV slot: 9a, 9c, 9d, 9e
	Algorithm string `json:"algorithm"`       // Key algorithm (e.g., ECDSA-P256, RSA-2048)
	Label     string `json:"label,omitempty"` // Optional human-readable label
}

// LocalPIVGenerateKeyResult contains the result of local.pivGenerateKey.
type LocalPIVGenerateKeyResult struct {
	Slot         string `json:"slot"`
	PublicKeyDER []byte `json:"public_key_der,omitempty"` // DER-encoded public key
	Algorithm    string `json:"algorithm"`
}

// --- local.pivImportCert ---

// LocalPIVImportCertParams contains parameters for local.pivImportCert.
// The laptop sends a certificate to the phone for storage in a PIV slot.
type LocalPIVImportCertParams struct {
	Slot           string `json:"slot"`            // PIV slot: 9a, 9c, 9d, 9e
	CertificateDER []byte `json:"certificate_der"` // DER-encoded X.509 certificate
}

// LocalPIVImportCertResult contains the result of local.pivImportCert.
type LocalPIVImportCertResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// --- local.pivListSlots ---

// LocalPIVListSlotsParams contains parameters for local.pivListSlots.
// Currently empty; filters may be added in the future.
type LocalPIVListSlotsParams struct{}

// LocalPIVListSlotsResult contains the result of local.pivListSlots.
type LocalPIVListSlotsResult struct {
	Slots []PIVSlotInfo `json:"slots"`
}

// --- local.pivSign ---

// LocalPIVSignParams contains parameters for local.pivSign.
// The laptop requests the phone to sign data using a PIV slot key.
type LocalPIVSignParams struct {
	Slot      string `json:"slot"`                // PIV slot: 9a, 9c, 9d, 9e
	Data      []byte `json:"data"`                // Data to sign
	Algorithm string `json:"algorithm,omitempty"` // Optional: override signing algorithm
}

// LocalPIVSignResult contains the result of local.pivSign.
type LocalPIVSignResult struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// --- local.pivGetCert ---

// LocalPIVGetCertParams contains parameters for local.pivGetCert.
// The laptop requests the certificate from a specific PIV slot on the phone.
type LocalPIVGetCertParams struct {
	Slot string `json:"slot"` // PIV slot: 9a, 9c, 9d, 9e
}

// LocalPIVGetCertResult contains the result of local.pivGetCert.
type LocalPIVGetCertResult struct {
	CertificateDER []byte `json:"certificate_der"`
	Subject        string `json:"subject,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	Expiry         string `json:"expiry,omitempty"` // ISO 8601
}

// --- remote.pivListSlots ---

// RemotePIVListSlotsParams contains parameters for remote.pivListSlots.
// The phone requests the laptop's PIV slot contents.
type RemotePIVListSlotsParams struct {
	Backend string `json:"backend,omitempty"` // Optional backend filter
}

// RemotePIVListSlotsResult contains the result of remote.pivListSlots.
type RemotePIVListSlotsResult struct {
	Slots []PIVSlotInfo `json:"slots"`
}

// --- remote.pivSign ---

// RemotePIVSignParams contains parameters for remote.pivSign.
// The phone requests the laptop to sign data using a PIV slot key.
type RemotePIVSignParams struct {
	Slot      string `json:"slot"`                // PIV slot: 9a, 9c, 9d, 9e
	Data      []byte `json:"data"`                // Data to sign
	Algorithm string `json:"algorithm,omitempty"` // Optional: override signing algorithm
	Backend   string `json:"backend,omitempty"`   // Optional backend
}

// RemotePIVSignResult contains the result of remote.pivSign.
type RemotePIVSignResult struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// --- remote.pivGetCert ---

// RemotePIVGetCertParams contains parameters for remote.pivGetCert.
// The phone requests a certificate from a PIV slot on the laptop.
type RemotePIVGetCertParams struct {
	Slot    string `json:"slot"`              // PIV slot: 9a, 9c, 9d, 9e
	Backend string `json:"backend,omitempty"` // Optional backend
}

// RemotePIVGetCertResult contains the result of remote.pivGetCert.
type RemotePIVGetCertResult struct {
	CertificateDER []byte `json:"certificate_der"`
	Subject        string `json:"subject,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	Expiry         string `json:"expiry,omitempty"` // ISO 8601
}

// pivLocalMethodNames contains all valid local.* PIV method names.
var pivLocalMethodNames = map[string]bool{
	MethodLocalPIVGenerateKey: true,
	MethodLocalPIVImportCert:  true,
	MethodLocalPIVListSlots:   true,
	MethodLocalPIVSign:        true,
	MethodLocalPIVGetCert:     true,
}

// pivRemoteMethodNames contains all valid remote.* PIV method names.
var pivRemoteMethodNames = map[string]bool{
	MethodRemotePIVListSlots: true,
	MethodRemotePIVSign:      true,
	MethodRemotePIVGetCert:   true,
}

// IsPIVLocalMethod returns true if the method name is a valid
// local.* PIV method.
func IsPIVLocalMethod(method string) bool {
	return pivLocalMethodNames[method]
}

// IsPIVRemoteMethod returns true if the method name is a valid
// remote.* PIV method.
func IsPIVRemoteMethod(method string) bool {
	return pivRemoteMethodNames[method]
}

func init() {
	// Register PIV methods with the global local and remote method maps.
	for method := range pivLocalMethodNames {
		localMethodNames[method] = true
	}
	for method := range pivRemoteMethodNames {
		remoteMethodNames[method] = true
	}
}
