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

// OATH credential sync method names for bidirectional OATH credential
// management between laptop and phone. These methods enable credential
// addition, listing, OTP generation, and removal on both sides.
//
// Protocol Direction:
//   - local.*  methods: Laptop sends TO phone (operates on phone's OATH store)
//   - remote.* methods: Phone sends TO laptop (operates on laptop's OATH store)
const (
	// MethodLocalOATHAdd sends an OATH credential to the phone for storage.
	MethodLocalOATHAdd = "local.oathAdd"

	// MethodLocalOATHList requests the phone to list its OATH credentials.
	MethodLocalOATHList = "local.oathList"

	// MethodLocalOATHGenerate requests the phone to generate the current
	// OTP code for a credential.
	MethodLocalOATHGenerate = "local.oathGenerate"

	// MethodLocalOATHRemove requests the phone to remove an OATH credential.
	MethodLocalOATHRemove = "local.oathRemove"

	// MethodRemoteOATHAdd is sent by the phone to add an OATH credential
	// to the laptop's store.
	MethodRemoteOATHAdd = "remote.oathAdd"

	// MethodRemoteOATHGenerate is sent by the phone to request the laptop
	// to generate the current OTP code for a credential.
	MethodRemoteOATHGenerate = "remote.oathGenerate"
)

// OATHCredentialInfo is a shared type for credential transfer between
// laptop and phone. It contains all fields needed to fully recreate
// an OATH TOTP/HOTP credential on the receiving side.
type OATHCredentialInfo struct {
	Name        string `json:"name"`
	Issuer      string `json:"issuer,omitempty"`
	AccountName string `json:"account_name,omitempty"`
	Secret      string `json:"secret"`              // Base32-encoded shared secret
	Type        string `json:"type"`                // "totp" or "hotp"
	Algorithm   string `json:"algorithm,omitempty"` // SHA1, SHA256, SHA512
	Digits      int    `json:"digits,omitempty"`    // 6, 7, or 8
	Period      int    `json:"period,omitempty"`    // TOTP period in seconds
	Counter     uint64 `json:"counter,omitempty"`   // HOTP counter
}

// --- local.oathAdd ---

// LocalOATHAddParams contains parameters for local.oathAdd.
// The laptop sends an OATH credential to the phone for storage.
type LocalOATHAddParams struct {
	Credential OATHCredentialInfo `json:"credential"`
}

// LocalOATHAddResult contains the result of local.oathAdd.
type LocalOATHAddResult struct {
	Success      bool   `json:"success"`
	CredentialID string `json:"credential_id"`
	Message      string `json:"message,omitempty"`
}

// --- local.oathList ---

// LocalOATHListParams contains parameters for local.oathList.
// Currently empty; filters may be added in the future.
type LocalOATHListParams struct{}

// LocalOATHListResult contains the result of local.oathList.
type LocalOATHListResult struct {
	Credentials []OATHCredentialInfo `json:"credentials"`
}

// --- local.oathGenerate ---

// LocalOATHGenerateParams contains parameters for local.oathGenerate.
// The laptop requests the phone to generate the current OTP code.
type LocalOATHGenerateParams struct {
	CredentialID string `json:"credential_id"`
}

// LocalOATHGenerateResult contains the result of local.oathGenerate.
type LocalOATHGenerateResult struct {
	Code      string `json:"code"`
	ExpiresIn int    `json:"expires_in,omitempty"` // Seconds until code expires (TOTP only)
}

// --- local.oathRemove ---

// LocalOATHRemoveParams contains parameters for local.oathRemove.
type LocalOATHRemoveParams struct {
	CredentialID string `json:"credential_id"`
}

// LocalOATHRemoveResult contains the result of local.oathRemove.
type LocalOATHRemoveResult struct {
	Deleted bool `json:"deleted"`
}

// --- remote.oathAdd ---

// RemoteOATHAddParams contains parameters for remote.oathAdd.
// The phone sends an OATH credential to the laptop for storage.
type RemoteOATHAddParams struct {
	Credential OATHCredentialInfo `json:"credential"`
}

// RemoteOATHAddResult contains the result of remote.oathAdd.
type RemoteOATHAddResult struct {
	Success      bool   `json:"success"`
	CredentialID string `json:"credential_id"`
	Message      string `json:"message,omitempty"`
}

// --- remote.oathGenerate ---

// RemoteOATHGenerateParams contains parameters for remote.oathGenerate.
// The phone requests the laptop to generate the current OTP code.
type RemoteOATHGenerateParams struct {
	CredentialID string `json:"credential_id"`
}

// RemoteOATHGenerateResult contains the result of remote.oathGenerate.
type RemoteOATHGenerateResult struct {
	Code      string `json:"code"`
	ExpiresIn int    `json:"expires_in,omitempty"` // Seconds until code expires (TOTP only)
}

// oathLocalMethodNames contains all valid local.* OATH method names.
var oathLocalMethodNames = map[string]bool{
	MethodLocalOATHAdd:      true,
	MethodLocalOATHList:     true,
	MethodLocalOATHGenerate: true,
	MethodLocalOATHRemove:   true,
}

// oathRemoteMethodNames contains all valid remote.* OATH method names.
var oathRemoteMethodNames = map[string]bool{
	MethodRemoteOATHAdd:      true,
	MethodRemoteOATHGenerate: true,
}

// IsOATHLocalMethod returns true if the method name is a valid
// local.* OATH method.
func IsOATHLocalMethod(method string) bool {
	return oathLocalMethodNames[method]
}

// IsOATHRemoteMethod returns true if the method name is a valid
// remote.* OATH method.
func IsOATHRemoteMethod(method string) bool {
	return oathRemoteMethodNames[method]
}

func init() {
	// Register OATH methods with the global local and remote method maps.
	for method := range oathLocalMethodNames {
		localMethodNames[method] = true
	}
	for method := range oathRemoteMethodNames {
		remoteMethodNames[method] = true
	}
}
