// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// fido2Backend is the backend name recorded for virtual FIDO2 authenticator
// events.
const fido2Backend = "fido2"

// FIDO2Logger records the virtual FIDO2 authenticator's security events
// (pkg/fido2/authenticator.AuditLogger) through an xkey audit Logger.
type FIDO2Logger struct {
	logger Logger
}

// NewFIDO2Logger returns a FIDO2Logger that writes through logger.
func NewFIDO2Logger(logger Logger) *FIDO2Logger {
	return &FIDO2Logger{logger: logger}
}

// LogCredentialCreated records OpFIDO2CredentialCreated for the credential.
// The operation is SeveritySecurity, so a failed write returns an error and
// the authenticator refuses to persist the credential.
func (l *FIDO2Logger) LogCredentialCreated(credentialID string) error {
	return l.logger.LogKeyOperation(OpFIDO2CredentialCreated, fido2Backend, credentialID, true, nil, 0)
}

// LogPINSeeded records OpPINSeeded. The operation is SeveritySecurity, so a
// failed write returns an error and the authenticator refuses to persist
// the PIN.
func (l *FIDO2Logger) LogPINSeeded() error {
	return l.logger.LogPINOperation(OpPINSeeded, fido2Backend, true, nil, nil)
}
