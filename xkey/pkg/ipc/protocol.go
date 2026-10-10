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

package ipc

import "fmt"

// Message types identify the kind of request sent from client to server.
const (
	MessageTypeTouch        = "touch"
	MessageTypeTypePassword = "type_password"
	MessageTypeStatus       = "status"
	MessageTypePKCS11       = "pkcs11"
	MessageTypeAutofill     = "autofill"
	MessageTypePairing      = "pairing"
	MessageTypeUnlock       = "unlock"
	MessageTypeState        = "state"
	MessageTypeVault        = "vault"
)

// Response statuses indicate success or failure.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// Response actions describe what the server did in response to a message.
const (
	ActionApprovedUP    = "approved_up"
	ActionTypedPassword = "typed_password"
	ActionNoPending     = "no_pending"
	ActionDaemonReady   = "daemon_ready"

	// ActionLocked and ActionUnlocked are the lock states a daemon that owns
	// an app lock reports from HandleStatus. They let a client verify that the
	// state an unlock reported is the state the daemon is actually in.
	ActionLocked   = "locked"
	ActionUnlocked = "unlocked"
	// ActionUnsupported marks an error response the client can act on
	// structurally rather than by matching an error string: the daemon is
	// alive but does not serve this question. Callers use it to fall back
	// to a different source and say so, instead of reporting a false
	// negative or a hard failure.
	ActionUnsupported = "unsupported"
)

// PKCS#11 action constants identify the specific operation within a PKCS#11
// IPC message. Used for map-based O(1) dispatch.
const (
	ActionGenerateKey          = "generate_key"
	ActionSign                 = "sign"
	ActionVerify               = "verify"
	ActionEncrypt              = "encrypt"
	ActionEncryptAsym          = "encrypt_asym"
	ActionDecrypt              = "decrypt"
	ActionDeriveKey            = "derive_key"
	ActionDeriveKeyECDH        = "derive_key_ecdh"
	ActionWrapKeyByID          = "wrap_key_by_id"
	ActionUnwrapKeyByID        = "unwrap_key_by_id"
	ActionExportKeyMaterial    = "export_key_material"
	ActionGetImportParameters  = "get_import_parameters"
	ActionImportKey            = "import_key"
	ActionListPIVSlots         = "list_piv_slots"
	ActionGetPIVCertificate    = "get_piv_certificate"
	ActionGeneratePIVKey       = "generate_piv_key"
	ActionStorePIVCertificate  = "store_piv_certificate"
	ActionDeletePIVCertificate = "delete_piv_certificate"
	ActionImportPIVCertificate = "import_piv_certificate"
	ActionExportPIVCertificate = "export_piv_certificate"
	ActionGeneratePIVCSR       = "generate_piv_csr"
	ActionBarrierStatus        = "barrier_status"
)

// validMessageTypes is the set of recognized message types for O(1) lookup.
var validMessageTypes = map[string]bool{
	MessageTypeTouch:        true,
	MessageTypeTypePassword: true,
	MessageTypeStatus:       true,
	MessageTypePKCS11:       true,
	MessageTypeAutofill:     true,
	MessageTypePairing:      true,
	MessageTypeUnlock:       true,
	MessageTypeState:        true,
	MessageTypeVault:        true,
}

// Message is sent from the client to the server over the Unix domain socket.
type Message struct {
	Type     string           `json:"type"`               // "touch", "type_password", "status", "pkcs11", "autofill", "pairing", "unlock", "state"
	Name     string           `json:"name,omitempty"`     // password name (for type_password)
	PKCS11   *PKCS11Payload   `json:"pkcs11,omitempty"`   // PKCS#11 payload (for pkcs11)
	Autofill *AutofillPayload `json:"autofill,omitempty"` // autofill payload (for autofill)
	Pairing  *PairingPayload  `json:"pairing,omitempty"`  // pairing payload (for pairing)
	Unlock   *UnlockPayload   `json:"unlock,omitempty"`   // unlock payload (for unlock)
	State    *StatePayload    `json:"state,omitempty"`    // live-state payload (for state)
	Vault    *VaultPayload    `json:"vault,omitempty"`    // password-vault payload (for vault)
}

// Response is sent from the server to the client over the Unix domain socket.
type Response struct {
	Status   string          `json:"status"`             // "ok" or "error"
	Action   string          `json:"action,omitempty"`   // "approved_up", "typed_password", "no_pending", "daemon_ready", "unsupported"
	Error    string          `json:"error,omitempty"`    // error message when status is "error"
	PKCS11   *PKCS11Result   `json:"pkcs11,omitempty"`   // PKCS#11 result (for pkcs11 responses)
	Autofill *AutofillResult `json:"autofill,omitempty"` // autofill result (for autofill responses)
	Pairing  *PairingResult  `json:"pairing,omitempty"`  // pairing result (for pairing responses)
	Unlock   *UnlockResult   `json:"unlock,omitempty"`   // unlock result (for unlock responses)
	State    *StateResult    `json:"state,omitempty"`    // live-state result (for state responses)
	Vault    *VaultResult    `json:"vault,omitempty"`    // password-vault result (for vault responses)
	Storage  *StorageResult  `json:"storage,omitempty"`  // credential store description (for status responses)
}

// StorageResult describes the credential store a running daemon is using.
//
// It exists because the store a passkey lands in is not otherwise visible: the
// encrypted and plaintext layouts compose to the same on-disk path, so the file
// name tells an operator nothing about whether the private key inside it is
// protected. Naming the live store is the only way to answer "are my passkeys
// encrypted at rest" without reading the files.
type StorageResult struct {
	// Type is the configured store: "memory", "file" or "barrier".
	Type string `json:"type"`

	// Path is the directory backing the store. Empty for in-memory storage,
	// which keeps nothing after the daemon exits.
	Path string `json:"path,omitempty"`

	// Prefix is the key namespace within the backend. It differs between the
	// barrier and file layouts and compensates for their differing roots, so
	// it is reported rather than inferred.
	Prefix string `json:"prefix,omitempty"`

	// EncryptedAtRest reports whether stored values are encrypted by the
	// barrier. When false, credential records — including passkey private keys
	// — are readable by anything with the file permissions.
	EncryptedAtRest bool `json:"encrypted_at_rest"`
}

// Validate checks that the message is well-formed. It returns ErrInvalidMessage
// if the type is empty, unrecognized, or if required fields are missing.
func (m *Message) Validate() error {
	if m.Type == "" {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": type is required"}
	}
	if !validMessageTypes[m.Type] {
		return &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": unknown message type %q", m.Type)}
	}
	if m.Type == MessageTypeTypePassword && m.Name == "" {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": name is required for type_password"}
	}
	if m.Type == MessageTypeVault {
		if m.Vault == nil {
			return &DetailError{Err: ErrInvalidMessage, Detail: ": vault payload is required"}
		}
		return m.Vault.Validate()
	}
	if m.Type == MessageTypePKCS11 {
		if m.PKCS11 == nil {
			return &DetailError{Err: ErrInvalidMessage, Detail: ": pkcs11 payload is required"}
		}
		return m.PKCS11.Validate()
	}
	if m.Type == MessageTypeAutofill {
		if m.Autofill == nil {
			return &DetailError{Err: ErrInvalidMessage, Detail: ": autofill payload is required"}
		}
		return m.Autofill.Validate()
	}
	if m.Type == MessageTypePairing {
		if m.Pairing == nil {
			return &DetailError{Err: ErrInvalidMessage, Detail: ": pairing payload is required"}
		}
		return m.Pairing.Validate()
	}
	if m.Type == MessageTypeUnlock {
		if m.Unlock == nil {
			return &DetailError{Err: ErrInvalidMessage, Detail: ": unlock payload is required"}
		}
		return m.Unlock.Validate()
	}
	if m.Type == MessageTypeState {
		if m.State == nil {
			return &DetailError{Err: ErrInvalidMessage, Detail: ": state payload is required"}
		}
		return m.State.Validate()
	}
	return nil
}

// OKResponse creates a success response with the given action.
func OKResponse(action string) *Response {
	return &Response{
		Status: StatusOK,
		Action: action,
	}
}

// ErrorResponse creates an error response with the given message.
func ErrorResponse(err string) *Response {
	return &Response{
		Status: StatusError,
		Error:  err,
	}
}
