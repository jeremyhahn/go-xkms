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

package audit

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestNewSlogLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	auditLogger := NewSlogLogger(logger)
	if auditLogger == nil {
		t.Fatal("expected non-nil SlogLogger")
	}
	if auditLogger.logger == nil {
		t.Fatal("expected non-nil internal logger")
	}
}

func TestSlogLogger_Log_Success(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditLogger := NewSlogLogger(logger)

	entry := Entry{
		Timestamp:  time.Date(2025, 2, 6, 12, 0, 0, 0, time.UTC),
		Operation:  OpSignRequest,
		Backend:    "tpm2",
		KeyID:      "test-key-123",
		DeviceID:   "device-abc",
		DeviceName: "Test Phone",
		Success:    true,
		DurationMs: 150,
		Details: map[string]any{
			"algorithm": "ES256",
		},
	}

	auditLogger.Log(entry)

	output := buf.String()
	if !strings.Contains(output, "audit") {
		t.Errorf("expected 'audit' in output, got: %s", output)
	}
	if !strings.Contains(output, "sign_request") {
		t.Errorf("expected 'sign_request' in output, got: %s", output)
	}
	if !strings.Contains(output, "tpm2") {
		t.Errorf("expected 'tpm2' in output, got: %s", output)
	}
	if !strings.Contains(output, "test-key-123") {
		t.Errorf("expected 'test-key-123' in output, got: %s", output)
	}
	if !strings.Contains(output, "device-abc") {
		t.Errorf("expected 'device-abc' in output, got: %s", output)
	}
	if !strings.Contains(output, "Test Phone") {
		t.Errorf("expected 'Test Phone' in output, got: %s", output)
	}
	if !strings.Contains(output, "INFO") {
		t.Errorf("expected INFO level for success, got: %s", output)
	}
}

func TestSlogLogger_Log_Failure(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditLogger := NewSlogLogger(logger)

	entry := Entry{
		Timestamp: time.Now(),
		Operation: OpDecryptRequest,
		Backend:   "software",
		KeyID:     "key-456",
		Success:   false,
		Error:     "decryption failed: invalid ciphertext",
	}

	auditLogger.Log(entry)

	output := buf.String()
	if !strings.Contains(output, "WARN") {
		t.Errorf("expected WARN level for failure, got: %s", output)
	}
	if !strings.Contains(output, "decryption failed") {
		t.Errorf("expected error message in output, got: %s", output)
	}
	if !strings.Contains(output, "decrypt_request") {
		t.Errorf("expected 'decrypt_request' in output, got: %s", output)
	}
}

func TestSlogLogger_Log_MinimalEntry(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditLogger := NewSlogLogger(logger)

	entry := Entry{
		Timestamp: time.Now(),
		Operation: OpServiceStarted,
		Success:   true,
	}

	auditLogger.Log(entry)

	output := buf.String()
	if !strings.Contains(output, "service_started") {
		t.Errorf("expected 'service_started' in output, got: %s", output)
	}
	// Verify optional fields are not present when empty
	if strings.Contains(output, "backend=") && !strings.Contains(output, "backend=\"\"") {
		t.Errorf("expected no backend field in output, got: %s", output)
	}
}

func TestSlogLogger_LogKeyOperation(t *testing.T) {
	testCases := []struct {
		name       string
		op         OperationType
		backend    string
		keyID      string
		success    bool
		err        error
		durationMs int64
		expectWarn bool
	}{
		{
			name:       "successful key creation",
			op:         OpKeyCreated,
			backend:    "tpm2",
			keyID:      "new-key-1",
			success:    true,
			err:        nil,
			durationMs: 250,
			expectWarn: false,
		},
		{
			name:       "failed key deletion",
			op:         OpKeyDeleted,
			backend:    "software",
			keyID:      "key-to-delete",
			success:    false,
			err:        errors.New("key not found"),
			durationMs: 10,
			expectWarn: true,
		},
		{
			name:       "key attestation",
			op:         OpKeyAttested,
			backend:    "phone",
			keyID:      "attested-key",
			success:    true,
			err:        nil,
			durationMs: 500,
			expectWarn: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			auditLogger := NewSlogLogger(logger)

			auditLogger.LogKeyOperation(tc.op, tc.backend, tc.keyID, tc.success, tc.err, tc.durationMs)

			output := buf.String()
			if !strings.Contains(output, string(tc.op)) {
				t.Errorf("expected operation '%s' in output, got: %s", tc.op, output)
			}
			if !strings.Contains(output, tc.backend) {
				t.Errorf("expected backend '%s' in output, got: %s", tc.backend, output)
			}
			if !strings.Contains(output, tc.keyID) {
				t.Errorf("expected keyID '%s' in output, got: %s", tc.keyID, output)
			}
			if tc.expectWarn && !strings.Contains(output, "WARN") {
				t.Errorf("expected WARN level, got: %s", output)
			}
			if !tc.expectWarn && !strings.Contains(output, "INFO") {
				t.Errorf("expected INFO level, got: %s", output)
			}
			if tc.err != nil && !strings.Contains(output, tc.err.Error()) {
				t.Errorf("expected error '%s' in output, got: %s", tc.err.Error(), output)
			}
		})
	}
}

func TestSlogLogger_LogCryptoOperation(t *testing.T) {
	testCases := []struct {
		name       string
		op         OperationType
		backend    string
		keyID      string
		deviceID   string
		deviceName string
		success    bool
		err        error
		durationMs int64
		expectWarn bool
	}{
		{
			name:       "successful sign request",
			op:         OpSignRequest,
			backend:    "tpm2",
			keyID:      "signing-key",
			deviceID:   "phone-123",
			deviceName: "Pixel 8",
			success:    true,
			err:        nil,
			durationMs: 120,
			expectWarn: false,
		},
		{
			name:       "failed decrypt request",
			op:         OpDecryptRequest,
			backend:    "software",
			keyID:      "decrypt-key",
			deviceID:   "phone-456",
			deviceName: "Samsung S24",
			success:    false,
			err:        errors.New("invalid ciphertext"),
			durationMs: 50,
			expectWarn: true,
		},
		{
			name:       "device attestation",
			op:         OpDeviceAttested,
			backend:    "phone",
			keyID:      "",
			deviceID:   "phone-789",
			deviceName: "OnePlus 12",
			success:    true,
			err:        nil,
			durationMs: 300,
			expectWarn: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			auditLogger := NewSlogLogger(logger)

			auditLogger.LogCryptoOperation(tc.op, tc.backend, tc.keyID, tc.deviceID, tc.deviceName, tc.success, tc.err, tc.durationMs)

			output := buf.String()
			if !strings.Contains(output, string(tc.op)) {
				t.Errorf("expected operation '%s' in output, got: %s", tc.op, output)
			}
			if tc.deviceID != "" && !strings.Contains(output, tc.deviceID) {
				t.Errorf("expected deviceID '%s' in output, got: %s", tc.deviceID, output)
			}
			if tc.deviceName != "" && !strings.Contains(output, tc.deviceName) {
				t.Errorf("expected deviceName '%s' in output, got: %s", tc.deviceName, output)
			}
			if tc.expectWarn && !strings.Contains(output, "WARN") {
				t.Errorf("expected WARN level, got: %s", output)
			}
		})
	}
}

func TestSlogLogger_LogConnectionEvent(t *testing.T) {
	testCases := []struct {
		name       string
		op         OperationType
		deviceID   string
		deviceName string
		details    map[string]any
	}{
		{
			name:       "connection established",
			op:         OpConnectionEstablished,
			deviceID:   "phone-123",
			deviceName: "Pixel 8 Pro",
			details: map[string]any{
				"protocol": "BLE",
				"mtu":      247,
			},
		},
		{
			name:       "connection closed",
			op:         OpConnectionClosed,
			deviceID:   "phone-123",
			deviceName: "Pixel 8 Pro",
			details:    nil,
		},
		{
			name:       "pairing approved",
			op:         OpPairingApproved,
			deviceID:   "phone-456",
			deviceName: "Galaxy S24",
			details: map[string]any{
				"pairedBy": "user",
			},
		},
		{
			name:       "pairing denied",
			op:         OpPairingDenied,
			deviceID:   "phone-789",
			deviceName: "Unknown Device",
			details: map[string]any{
				"reason": "user rejected",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			auditLogger := NewSlogLogger(logger)

			auditLogger.LogConnectionEvent(tc.op, tc.deviceID, tc.deviceName, tc.details)

			output := buf.String()
			if !strings.Contains(output, string(tc.op)) {
				t.Errorf("expected operation '%s' in output, got: %s", tc.op, output)
			}
			if !strings.Contains(output, tc.deviceID) {
				t.Errorf("expected deviceID '%s' in output, got: %s", tc.deviceID, output)
			}
			if !strings.Contains(output, tc.deviceName) {
				t.Errorf("expected deviceName '%s' in output, got: %s", tc.deviceName, output)
			}
			// Connection events are always success=true, so expect INFO level
			if !strings.Contains(output, "INFO") {
				t.Errorf("expected INFO level, got: %s", output)
			}
		})
	}
}

func TestSlogLogger_LogServiceEvent(t *testing.T) {
	testCases := []struct {
		name    string
		op      OperationType
		details map[string]any
	}{
		{
			name: "service started",
			op:   OpServiceStarted,
			details: map[string]any{
				"version": "1.0.0",
				"pid":     12345,
			},
		},
		{
			name: "service stopped",
			op:   OpServiceStopped,
			details: map[string]any{
				"reason":   "shutdown",
				"duration": "1h30m",
			},
		},
		{
			name:    "service started no details",
			op:      OpServiceStarted,
			details: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			auditLogger := NewSlogLogger(logger)

			auditLogger.LogServiceEvent(tc.op, tc.details)

			output := buf.String()
			if !strings.Contains(output, string(tc.op)) {
				t.Errorf("expected operation '%s' in output, got: %s", tc.op, output)
			}
			// Service events are always success=true, so expect INFO level
			if !strings.Contains(output, "INFO") {
				t.Errorf("expected INFO level, got: %s", output)
			}
			// Verify details are included if provided
			for k := range tc.details {
				if !strings.Contains(output, k) {
					t.Errorf("expected detail key '%s' in output, got: %s", k, output)
				}
			}
		})
	}
}

func TestSlogLogger_LogKeyOperation_NilError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditLogger := NewSlogLogger(logger)

	// Log with nil error should work and not include error field
	auditLogger.LogKeyOperation(OpKeyCreated, "tpm2", "test-key", true, nil, 100)

	output := buf.String()
	if strings.Contains(output, "error=") {
		t.Errorf("expected no error field when error is nil, got: %s", output)
	}
}

func TestSlogLogger_LogCryptoOperation_NilError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditLogger := NewSlogLogger(logger)

	// Log with nil error should work and not include error field
	auditLogger.LogCryptoOperation(OpSignRequest, "tpm2", "key-1", "device-1", "Phone", true, nil, 50)

	output := buf.String()
	if strings.Contains(output, "error=") {
		t.Errorf("expected no error field when error is nil, got: %s", output)
	}
}

func TestOperationType_Constants(t *testing.T) {
	// Verify all operation type constants are unique and non-empty
	ops := []OperationType{
		// Key operations.
		OpKeyCreated,
		OpKeyDeleted,
		OpKeyAccessed,
		OpKeyAttested,

		// Cryptographic operations.
		OpSignRequest,
		OpVerifyRequest,
		OpEncryptRequest,
		OpDecryptRequest,
		OpDeriveKey,

		// Connection operations.
		OpConnectionEstablished,
		OpConnectionClosed,
		OpPairingApproved,
		OpPairingDenied,

		// Device attestation.
		OpDeviceAttested,

		// Service operations.
		OpServiceStarted,
		OpServiceStopped,

		// Policy.
		OpPolicyDenied,

		// FIDO2 operations.
		OpFIDO2CredentialCreated,
		OpFIDO2CredentialDeleted,
		OpFIDO2CredentialAccessed,

		// FIDO2 RP policy operations.
		OpFIDO2RPPolicySet,
		OpFIDO2RPPolicyDeleted,
		OpFIDO2RPPolicyAccessed,

		// Import/export/rotate operations.
		OpKeyImported,
		OpKeyExported,
		OpKeyRotated,

		// PIN operations.
		OpPINVerified,
		OpPINFailed,
		OpPINChanged,
		OpPINLocked,
		OpSOPINVerified,
		OpSOPINFailed,
		OpSOPINChanged,
		OpPINSeeded,

		// TPM operations.
		OpTPMProvisioned,
		OpTPMAuthFailed,
		OpTPMHierarchyChanged,
		OpTPMSealFailed,
		OpTPMUnsealFailed,
		OpTPMReset,

		// Password store operations.
		OpPasswordStoreUnlocked,
		OpPasswordStoreLocked,
		OpPasswordAccessed,
		OpPasswordCreated,
		OpPasswordDeleted,
		OpPasswordUpdated,
		OpAutofillRequested,
		OpAutofillDenied,

		// User presence operations.
		OpUserPresenceRequested,
		OpUserPresenceConfirmed,
		OpUserPresenceTimedOut,
		OpUserPresenceCancelled,
		OpTouchEventReceived,

		// Browser extension / native messaging operations.
		OpExtensionHandshake,
		OpExtensionIdentityOK,
		OpExtensionRejected,
		OpExtensionRelay,
		OpExtensionDisconnected,

		// Pairing verification operations.
		OpPairingStarted,
		OpPairingCompleted,
		OpPairingFailed,
		OpPairingUnpaired,
		OpPairingIdentityOK,
		OpPairingIdentityFail,
		OpPairingRateLimited,
		OpPairingManifest,

		// OATH operations.
		OpOATHCredentialCreated,
		OpOATHCredentialAccessed,
		OpOATHCredentialUpdated,
		OpOATHCredentialDeleted,
		OpOATHCodeGenerated,
		OpOATHCodeValidated,
		OpOATHCodeInvalid,

		// IPC operations.
		OpIPCMessageDispatched,
		OpIPCMessageFailed,

		// SecretService (D-Bus) operations.
		OpSecretServiceSessionOpened,
		OpSecretServiceSessionClosed,
		OpSecretServiceSearch,
		OpSecretServiceSecretAccessed,
		OpSecretServiceUnlock,
		OpSecretServiceLock,

		// Barrier operations.
		OpBarrierInitialized,
		OpBarrierUnsealed,
		OpBarrierSealed,

		// Seal operations.
		OpSealData,
		OpUnsealData,
		OpSealBlobDeleted,

		// Configuration operations.
		OpConfigUpdated,
	}

	seen := make(map[OperationType]bool)
	for _, op := range ops {
		if op == "" {
			t.Error("found empty operation type constant")
		}
		if seen[op] {
			t.Errorf("duplicate operation type: %s", op)
		}
		seen[op] = true
	}
}

func TestSlogLogger_Log_ZeroDuration(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	auditLogger := NewSlogLogger(logger)

	entry := Entry{
		Timestamp:  time.Now(),
		Operation:  OpKeyAccessed,
		Success:    true,
		DurationMs: 0, // Zero duration should not be logged
	}

	auditLogger.Log(entry)

	output := buf.String()
	// Zero duration should not appear in output
	if strings.Contains(output, "durationMs") {
		t.Errorf("expected no durationMs field when duration is 0, got: %s", output)
	}
}

// TestLogger_Interface ensures SlogLogger implements Logger interface.
func TestLogger_Interface(t *testing.T) {
	var _ Logger = (*SlogLogger)(nil)
}
