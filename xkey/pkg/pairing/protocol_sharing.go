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

// Key sharing method names for bidirectional key exchange between
// laptop and phone. These methods enable public key distribution,
// symmetric key wrapping, and key import/export flows.
//
// Protocol Direction:
//   - local.*  methods: Laptop sends TO phone (operates on phone's keystore)
//   - remote.* methods: Phone sends TO laptop (operates on laptop's xkms)
const (
	// MethodLocalSharePublicKey sends the laptop's public key and optional
	// certificate to the phone for storage.
	MethodLocalSharePublicKey = "local.sharePublicKey"

	// MethodLocalShareSymmetric sends a wrapped symmetric key to the phone
	// for import into its keystore.
	MethodLocalShareSymmetric = "local.shareSymmetric"

	// MethodLocalImportSharedKey requests the phone to export a key for
	// sharing with the laptop.
	MethodLocalImportSharedKey = "local.importSharedKey"

	// MethodRemoteSharePublicKey sends the phone's public key and optional
	// certificate to the laptop for storage.
	MethodRemoteSharePublicKey = "remote.sharePublicKey"

	// MethodRemoteShareSymmetric sends wrapped symmetric key material from
	// the phone to the laptop for import.
	MethodRemoteShareSymmetric = "remote.shareSymmetric"

	// MethodRemoteImportSharedKey requests the laptop to export a key for
	// sharing with the phone.
	MethodRemoteImportSharedKey = "remote.importSharedKey"
)

// --- local.sharePublicKey ---

// LocalSharePublicKeyParams contains parameters for local.sharePublicKey.
// The laptop sends its public key and optional certificate to the phone.
type LocalSharePublicKeyParams struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	PublicKeyPEM   []byte `json:"public_key_pem"`
	CertificatePEM []byte `json:"certificate_pem,omitempty"`
	Algorithm      string `json:"algorithm"`
	Label          string `json:"label,omitempty"`
}

// LocalSharePublicKeyResult contains the result of local.sharePublicKey.
type LocalSharePublicKeyResult struct {
	Accepted bool   `json:"accepted"`
	ImportID string `json:"import_id"`
}

// --- remote.sharePublicKey ---

// RemoteSharePublicKeyParams contains parameters for remote.sharePublicKey.
// The phone sends its public key and optional certificate to the laptop.
type RemoteSharePublicKeyParams struct {
	KeyID          string `json:"key_id"`
	PublicKeyPEM   []byte `json:"public_key_pem"`
	CertificatePEM []byte `json:"certificate_pem,omitempty"`
	Algorithm      string `json:"algorithm"`
	Label          string `json:"label,omitempty"`
	Backend        string `json:"backend,omitempty"`
}

// RemoteSharePublicKeyResult contains the result of remote.sharePublicKey.
type RemoteSharePublicKeyResult struct {
	Accepted bool   `json:"accepted"`
	ImportID string `json:"import_id"`
	Backend  string `json:"backend"`
}

// --- local.shareSymmetric ---

// LocalShareSymmetricParams contains parameters for local.shareSymmetric.
// The laptop sends a wrapped symmetric key to the phone for import.
type LocalShareSymmetricParams struct {
	Backend    string `json:"backend"`
	KeyID      string `json:"key_id"`
	WrappedKey []byte `json:"wrapped_key"`
	Algorithm  string `json:"algorithm"`
	KeySize    int    `json:"key_size"`
	Label      string `json:"label,omitempty"`
}

// LocalShareSymmetricResult contains the result of local.shareSymmetric.
type LocalShareSymmetricResult struct {
	Accepted bool   `json:"accepted"`
	ImportID string `json:"import_id"`
}

// --- remote.shareSymmetric ---

// RemoteShareSymmetricParams contains parameters for remote.shareSymmetric.
// The phone sends wrapped symmetric key material to the laptop for import.
type RemoteShareSymmetricParams struct {
	KeyID      string `json:"key_id"`
	WrappedKey []byte `json:"wrapped_key"`
	Algorithm  string `json:"algorithm"`
	KeySize    int    `json:"key_size"`
	Label      string `json:"label,omitempty"`
	Backend    string `json:"backend,omitempty"`
}

// RemoteShareSymmetricResult contains the result of remote.shareSymmetric.
type RemoteShareSymmetricResult struct {
	Accepted bool   `json:"accepted"`
	ImportID string `json:"import_id"`
	Backend  string `json:"backend"`
}

// --- local.importSharedKey ---

// LocalImportSharedKeyParams contains parameters for local.importSharedKey.
// The laptop requests the phone to export a key for sharing.
type LocalImportSharedKeyParams struct {
	KeyID  string `json:"key_id"`
	Format string `json:"format,omitempty"`
}

// LocalImportSharedKeyResult contains the result of local.importSharedKey.
type LocalImportSharedKeyResult struct {
	PublicKeyPEM   []byte `json:"public_key_pem"`
	CertificatePEM []byte `json:"certificate_pem,omitempty"`
	Algorithm      string `json:"algorithm"`
	KeyType        string `json:"key_type"`
	WrappedKey     []byte `json:"wrapped_key,omitempty"`
	KeySize        int    `json:"key_size,omitempty"`
	Exportable     bool   `json:"exportable"`
}

// --- remote.importSharedKey ---

// RemoteImportSharedKeyParams contains parameters for remote.importSharedKey.
// The phone requests the laptop to export a key for sharing.
type RemoteImportSharedKeyParams struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Format  string `json:"format,omitempty"`
}

// RemoteImportSharedKeyResult contains the result of remote.importSharedKey.
type RemoteImportSharedKeyResult struct {
	PublicKeyPEM   []byte `json:"public_key_pem"`
	CertificatePEM []byte `json:"certificate_pem,omitempty"`
	Algorithm      string `json:"algorithm"`
	KeyType        string `json:"key_type"`
	WrappedKey     []byte `json:"wrapped_key,omitempty"`
	KeySize        int    `json:"key_size,omitempty"`
	Exportable     bool   `json:"exportable"`
}

// sharingLocalMethodNames contains all valid local.* sharing method names.
var sharingLocalMethodNames = map[string]bool{
	MethodLocalSharePublicKey:  true,
	MethodLocalShareSymmetric:  true,
	MethodLocalImportSharedKey: true,
}

// sharingRemoteMethodNames contains all valid remote.* sharing method names.
var sharingRemoteMethodNames = map[string]bool{
	MethodRemoteSharePublicKey:  true,
	MethodRemoteShareSymmetric:  true,
	MethodRemoteImportSharedKey: true,
}

// IsSharingLocalMethod returns true if the method name is a valid
// local.* sharing method.
func IsSharingLocalMethod(method string) bool {
	return sharingLocalMethodNames[method]
}

// IsSharingRemoteMethod returns true if the method name is a valid
// remote.* sharing method.
func IsSharingRemoteMethod(method string) bool {
	return sharingRemoteMethodNames[method]
}

func init() {
	// Register sharing methods with the global local and remote method maps.
	for method := range sharingLocalMethodNames {
		localMethodNames[method] = true
	}
	for method := range sharingRemoteMethodNames {
		remoteMethodNames[method] = true
	}
}
