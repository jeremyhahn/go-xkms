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

package services

import (
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// recordingAuditLogger is a test-only audit.Logger that records every call,
// shared by the PolicySection deny-switch table tests (#668) across this
// package's *_test.go files: app_service_test.go, pin_service_test.go,
// trust_service_test.go, audit_service_test.go, seal_service_test.go,
// api_explorer_service_test.go and autofill_service_test.go.
type recordingAuditLogger struct {
	entries []audit.Entry
}

func (r *recordingAuditLogger) Log(e audit.Entry) { r.entries = append(r.entries, e) }
func (r *recordingAuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) {
	r.entries = append(r.entries, audit.Entry{Operation: op, Backend: backend, KeyID: keyID, Success: success})
}
func (r *recordingAuditLogger) LogCryptoOperation(op audit.OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) {
	r.entries = append(r.entries, audit.Entry{Operation: op, Backend: backend, KeyID: keyID, DeviceID: deviceID, DeviceName: deviceName, Success: success})
}
func (r *recordingAuditLogger) LogConnectionEvent(op audit.OperationType, deviceID, deviceName string, details map[string]any) {
	r.entries = append(r.entries, audit.Entry{Operation: op, DeviceID: deviceID, DeviceName: deviceName, Details: details})
}
func (r *recordingAuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) {
	r.entries = append(r.entries, audit.Entry{Operation: op, Details: details})
}
func (r *recordingAuditLogger) LogPINOperation(op audit.OperationType, backend string, success bool, err error, details map[string]any) {
	r.entries = append(r.entries, audit.Entry{Operation: op, Backend: backend, Success: success, Details: details})
}
func (r *recordingAuditLogger) LogTPMOperation(op audit.OperationType, success bool, err error, details map[string]any) {
	r.entries = append(r.entries, audit.Entry{Operation: op, Success: success, Details: details})
}
func (r *recordingAuditLogger) LogPasswordStoreOperation(op audit.OperationType, source string, success bool, err error, details map[string]any) {
	r.entries = append(r.entries, audit.Entry{Operation: op, Backend: source, Success: success, Details: details})
}
func (r *recordingAuditLogger) LogUserPresenceEvent(op audit.OperationType, source string, success bool, details map[string]any) {
	r.entries = append(r.entries, audit.Entry{Operation: op, Backend: source, Success: success, Details: details})
}

var _ audit.Logger = (*recordingAuditLogger)(nil)

// hasPolicyDenial reports whether entries contains an OpPolicyDenied entry.
func (r *recordingAuditLogger) hasPolicyDenial() bool {
	for _, e := range r.entries {
		if e.Operation == audit.OpPolicyDenied {
			return true
		}
	}
	return false
}
