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

// Package audit provides audit logging for xkey security-relevant operations.
package audit

import (
	"log/slog"
	"time"
)

// OperationType defines the type of operation being logged.
type OperationType string

const (
	// Key operations.
	OpKeyCreated  OperationType = "key_created"
	OpKeyDeleted  OperationType = "key_deleted"
	OpKeyAccessed OperationType = "key_accessed"
	OpKeyAttested OperationType = "key_attested"

	// Cryptographic operations.
	OpSignRequest    OperationType = "sign_request"
	OpVerifyRequest  OperationType = "verify_request"
	OpEncryptRequest OperationType = "encrypt_request"
	OpDecryptRequest OperationType = "decrypt_request"
	OpDeriveKey      OperationType = "derive_key"

	// Connection operations.
	OpConnectionEstablished OperationType = "connection_established"
	OpConnectionClosed      OperationType = "connection_closed"
	OpPairingApproved       OperationType = "pairing_approved"
	OpPairingDenied         OperationType = "pairing_denied"

	// Device attestation.
	OpDeviceAttested OperationType = "device_attested"

	// Service operations.
	OpServiceStarted OperationType = "service_started"
	OpServiceStopped OperationType = "service_stopped"

	// Policy.
	OpPolicyDenied OperationType = "policy_denied"

	// FIDO2 operations.
	OpFIDO2CredentialCreated  OperationType = "fido2_credential_created"
	OpFIDO2CredentialDeleted  OperationType = "fido2_credential_deleted"
	OpFIDO2CredentialAccessed OperationType = "fido2_credential_accessed"

	// FIDO2 RP policy operations.
	OpFIDO2RPPolicySet      OperationType = "fido2.rp_policy.set"
	OpFIDO2RPPolicyDeleted  OperationType = "fido2.rp_policy.deleted"
	OpFIDO2RPPolicyAccessed OperationType = "fido2.rp_policy.accessed"

	// Import/export/rotate operations.
	OpKeyImported OperationType = "key_imported"
	OpKeyExported OperationType = "key_exported"
	OpKeyRotated  OperationType = "key_rotated"

	// PIN operations.
	OpPINVerified   OperationType = "pin_verified"
	OpPINFailed     OperationType = "pin_failed"
	OpPINChanged    OperationType = "pin_changed"
	OpPINLocked     OperationType = "pin_locked"
	OpSOPINVerified OperationType = "so_pin_verified"
	OpSOPINFailed   OperationType = "so_pin_failed"
	OpSOPINChanged  OperationType = "so_pin_changed"
	OpPINSeeded     OperationType = "pin_seeded"

	// TPM operations.
	OpTPMProvisioned      OperationType = "tpm_provisioned"
	OpTPMAuthFailed       OperationType = "tpm_auth_failed"
	OpTPMHierarchyChanged OperationType = "tpm_hierarchy_changed"
	OpTPMSealFailed       OperationType = "tpm_seal_failed"
	OpTPMUnsealFailed     OperationType = "tpm_unseal_failed"
	OpTPMReset            OperationType = "tpm_reset"

	// Password store operations (autofill/browser extension).
	OpPasswordStoreUnlocked OperationType = "password_store_unlocked"
	OpPasswordStoreLocked   OperationType = "password_store_locked"
	OpPasswordAccessed      OperationType = "password_accessed"
	OpPasswordCreated       OperationType = "password_created"
	OpPasswordDeleted       OperationType = "password_deleted"
	OpPasswordUpdated       OperationType = "password_updated"
	OpAutofillRequested     OperationType = "autofill_requested"
	OpAutofillDenied        OperationType = "autofill_denied"

	// User presence operations.
	OpUserPresenceRequested OperationType = "user_presence_requested"
	OpUserPresenceConfirmed OperationType = "user_presence_confirmed"
	OpUserPresenceTimedOut  OperationType = "user_presence_timed_out"
	OpUserPresenceCancelled OperationType = "user_presence_cancelled"
	OpTouchEventReceived    OperationType = "touch_event_received"

	// Browser extension / native messaging operations.
	OpExtensionHandshake    OperationType = "extension_handshake"
	OpExtensionIdentityOK   OperationType = "extension_identity_ok"
	OpExtensionRejected     OperationType = "extension_rejected"
	OpExtensionRelay        OperationType = "extension_relay"
	OpExtensionDisconnected OperationType = "extension_disconnected"

	// Pairing verification operations.
	OpPairingStarted      OperationType = "pairing_started"
	OpPairingCompleted    OperationType = "pairing_completed"
	OpPairingFailed       OperationType = "pairing_failed"
	OpPairingUnpaired     OperationType = "pairing_unpaired"
	OpPairingIdentityOK   OperationType = "pairing_identity_ok"
	OpPairingIdentityFail OperationType = "pairing_identity_fail"
	OpPairingRateLimited  OperationType = "pairing_rate_limited"
	OpPairingManifest     OperationType = "pairing_manifest"

	// OATH operations.
	OpOATHCredentialCreated  OperationType = "oath_credential_created"
	OpOATHCredentialAccessed OperationType = "oath_credential_accessed"
	OpOATHCredentialUpdated  OperationType = "oath_credential_updated"
	OpOATHCredentialDeleted  OperationType = "oath_credential_deleted"
	OpOATHCodeGenerated      OperationType = "oath_code_generated"
	OpOATHCodeValidated      OperationType = "oath_code_validated"
	OpOATHCodeInvalid        OperationType = "oath_code_invalid"

	// IPC operations.
	OpIPCMessageDispatched OperationType = "ipc_message_dispatched"
	OpIPCMessageFailed     OperationType = "ipc_message_failed"

	// SecretService (D-Bus) operations.
	OpSecretServiceSessionOpened  OperationType = "secretservice_session_opened"
	OpSecretServiceSessionClosed  OperationType = "secretservice_session_closed"
	OpSecretServiceSearch         OperationType = "secretservice_search"
	OpSecretServiceSecretAccessed OperationType = "secretservice_secret_accessed"
	OpSecretServiceUnlock         OperationType = "secretservice_unlock"
	OpSecretServiceLock           OperationType = "secretservice_lock"

	// Barrier operations.
	OpBarrierInitialized     OperationType = "barrier_initialized"
	OpBarrierUnsealed        OperationType = "barrier_unsealed"
	OpBarrierSealed          OperationType = "barrier_sealed"
	OpBarrierPasswordChanged OperationType = "barrier_password_changed"

	// Seal operations.
	OpSealData        OperationType = "seal_data"
	OpUnsealData      OperationType = "unseal_data"
	OpSealBlobDeleted OperationType = "seal_blob_deleted"

	// Configuration operations.
	OpConfigUpdated OperationType = "config_updated"
)

// Entry represents an audit log entry.
type Entry struct {
	Timestamp  time.Time
	Operation  OperationType
	Backend    string
	KeyID      string
	DeviceID   string
	DeviceName string
	Success    bool
	Error      string
	DurationMs int64
	Details    map[string]any
}

// Logger is the audit logger interface.
type Logger interface {
	Log(entry Entry)
	LogKeyOperation(op OperationType, backend, keyID string, success bool, err error, durationMs int64)
	LogCryptoOperation(op OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64)
	LogConnectionEvent(op OperationType, deviceID, deviceName string, details map[string]any)
	LogServiceEvent(op OperationType, details map[string]any)
	LogPINOperation(op OperationType, backend string, success bool, err error, details map[string]any)
	LogTPMOperation(op OperationType, success bool, err error, details map[string]any)
	LogPasswordStoreOperation(op OperationType, source string, success bool, err error, details map[string]any)
	LogUserPresenceEvent(op OperationType, source string, success bool, details map[string]any)
}

// SlogLogger wraps slog for audit logging.
type SlogLogger struct {
	logger *slog.Logger
}

// NewSlogLogger creates a new audit logger using slog.
func NewSlogLogger(logger *slog.Logger) *SlogLogger {
	return &SlogLogger{
		logger: logger.With("component", "audit"),
	}
}

// Log writes an audit entry.
func (l *SlogLogger) Log(e Entry) {
	attrs := []any{
		"operation", string(e.Operation),
		"success", e.Success,
		"timestamp", e.Timestamp.Format(time.RFC3339Nano),
	}
	if e.Backend != "" {
		attrs = append(attrs, "backend", e.Backend)
	}
	if e.KeyID != "" {
		attrs = append(attrs, "keyId", e.KeyID)
	}
	if e.DeviceID != "" {
		attrs = append(attrs, "deviceId", e.DeviceID)
	}
	if e.DeviceName != "" {
		attrs = append(attrs, "deviceName", e.DeviceName)
	}
	if e.Error != "" {
		attrs = append(attrs, "error", e.Error)
	}
	if e.DurationMs > 0 {
		attrs = append(attrs, "durationMs", e.DurationMs)
	}
	for k, v := range e.Details {
		attrs = append(attrs, k, v)
	}

	if e.Success {
		l.logger.Info("audit", attrs...)
	} else {
		l.logger.Warn("audit", attrs...)
	}
}

// LogKeyOperation logs a key-related operation.
func (l *SlogLogger) LogKeyOperation(op OperationType, backend, keyID string, success bool, err error, durationMs int64) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	l.Log(Entry{
		Timestamp:  time.Now(),
		Operation:  op,
		Backend:    backend,
		KeyID:      keyID,
		Success:    success,
		Error:      errStr,
		DurationMs: durationMs,
	})
}

// LogCryptoOperation logs a cryptographic operation.
func (l *SlogLogger) LogCryptoOperation(op OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	l.Log(Entry{
		Timestamp:  time.Now(),
		Operation:  op,
		Backend:    backend,
		KeyID:      keyID,
		DeviceID:   deviceID,
		DeviceName: deviceName,
		Success:    success,
		Error:      errStr,
		DurationMs: durationMs,
	})
}

// LogConnectionEvent logs a connection-related event.
func (l *SlogLogger) LogConnectionEvent(op OperationType, deviceID, deviceName string, details map[string]any) {
	l.Log(Entry{
		Timestamp:  time.Now(),
		Operation:  op,
		DeviceID:   deviceID,
		DeviceName: deviceName,
		Success:    true,
		Details:    details,
	})
}

// LogServiceEvent logs a service lifecycle event.
func (l *SlogLogger) LogServiceEvent(op OperationType, details map[string]any) {
	l.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   true,
		Details:   details,
	})
}

// LogPINOperation logs a PIN-related operation (verify, change, lock).
func (l *SlogLogger) LogPINOperation(op OperationType, backend string, success bool, err error, details map[string]any) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	l.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Backend:   backend,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}

// LogTPMOperation logs a TPM-related operation (provision, auth, seal).
func (l *SlogLogger) LogTPMOperation(op OperationType, success bool, err error, details map[string]any) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	l.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Backend:   "tpm2",
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}

// LogPasswordStoreOperation logs a password store operation (unlock, access, autofill).
func (l *SlogLogger) LogPasswordStoreOperation(op OperationType, source string, success bool, err error, details map[string]any) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	if details == nil {
		details = make(map[string]any)
	}
	details["source"] = source
	l.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}

// LogUserPresenceEvent logs a user presence/touch event.
func (l *SlogLogger) LogUserPresenceEvent(op OperationType, source string, success bool, details map[string]any) {
	if details == nil {
		details = make(map[string]any)
	}
	details["source"] = source
	l.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Details:   details,
	})
}
