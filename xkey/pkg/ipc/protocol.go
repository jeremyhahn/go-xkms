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
)

// PKCS#11 action constants identify the specific operation within a PKCS#11
// IPC message. Used for map-based O(1) dispatch.
const (
	ActionSign              = "sign"
	ActionGetPIVCertificate = "get_piv_certificate"
	ActionListPIVSlots      = "list_piv_slots"
	ActionBarrierStatus     = "barrier_status"
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
}

// Message is sent from the client to the server over the Unix domain socket.
type Message struct {
	Type     string           `json:"type"`               // "touch", "type_password", "status", "pkcs11", "autofill", "pairing", "unlock"
	Name     string           `json:"name,omitempty"`     // password name (for type_password)
	PKCS11   *PKCS11Payload   `json:"pkcs11,omitempty"`   // PKCS#11 payload (for pkcs11)
	Autofill *AutofillPayload `json:"autofill,omitempty"` // autofill payload (for autofill)
	Pairing  *PairingPayload  `json:"pairing,omitempty"`  // pairing payload (for pairing)
	Unlock   *UnlockPayload   `json:"unlock,omitempty"`   // unlock payload (for unlock)
}

// Response is sent from the server to the client over the Unix domain socket.
type Response struct {
	Status   string          `json:"status"`             // "ok" or "error"
	Action   string          `json:"action,omitempty"`   // "approved_up", "typed_password", "no_pending", "daemon_ready"
	Error    string          `json:"error,omitempty"`    // error message when status is "error"
	PKCS11   *PKCS11Result   `json:"pkcs11,omitempty"`   // PKCS#11 result (for pkcs11 responses)
	Autofill *AutofillResult `json:"autofill,omitempty"` // autofill result (for autofill responses)
	Pairing  *PairingResult  `json:"pairing,omitempty"`  // pairing result (for pairing responses)
	Unlock   *UnlockResult   `json:"unlock,omitempty"`   // unlock result (for unlock responses)
}

// Validate checks that the message is well-formed. It returns ErrInvalidMessage
// if the type is empty, unrecognized, or if required fields are missing.
func (m *Message) Validate() error {
	if m.Type == "" {
		return fmt.Errorf("%w: type is required", ErrInvalidMessage)
	}
	if !validMessageTypes[m.Type] {
		return fmt.Errorf("%w: unknown message type %q", ErrInvalidMessage, m.Type)
	}
	if m.Type == MessageTypeTypePassword && m.Name == "" {
		return fmt.Errorf("%w: name is required for type_password", ErrInvalidMessage)
	}
	if m.Type == MessageTypePKCS11 {
		if m.PKCS11 == nil {
			return fmt.Errorf("%w: pkcs11 payload is required", ErrInvalidMessage)
		}
		return m.PKCS11.Validate()
	}
	if m.Type == MessageTypeAutofill {
		if m.Autofill == nil {
			return fmt.Errorf("%w: autofill payload is required", ErrInvalidMessage)
		}
		return m.Autofill.Validate()
	}
	if m.Type == MessageTypePairing {
		if m.Pairing == nil {
			return fmt.Errorf("%w: pairing payload is required", ErrInvalidMessage)
		}
		return m.Pairing.Validate()
	}
	if m.Type == MessageTypeUnlock {
		if m.Unlock == nil {
			return fmt.Errorf("%w: unlock payload is required", ErrInvalidMessage)
		}
		return m.Unlock.Validate()
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
