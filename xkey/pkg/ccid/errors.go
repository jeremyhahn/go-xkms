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

// Package ccid implements a virtual CCID (Chip Card Interface Device) smartcard
// device using Linux UHID. It bridges ISO 7816 APDU commands to the xKey
// PKCS#11 service, allowing the system to interact with xKey as if it were a
// hardware smartcard reader with an inserted card.
package ccid

import (
	"errors"
	"fmt"
)

// Sentinel errors for CCID operations.
var (
	// ErrDeviceNotAvailable indicates the virtual CCID device could not
	// be created because /dev/uhid is not available or accessible.
	ErrDeviceNotAvailable = errors.New("ccid: device not available")

	// ErrDeviceAlreadyRunning indicates the CCID device is already started.
	ErrDeviceAlreadyRunning = errors.New("ccid: device already running")

	// ErrDeviceNotRunning indicates the CCID device has not been started.
	ErrDeviceNotRunning = errors.New("ccid: device not running")

	// ErrAPDUTooLong indicates the APDU command exceeds the maximum
	// allowed length.
	ErrAPDUTooLong = errors.New("ccid: APDU too long")

	// ErrAPDUMalformed indicates the APDU command is structurally
	// invalid (too short, inconsistent lengths, etc).
	ErrAPDUMalformed = errors.New("ccid: APDU malformed")

	// ErrUnsupportedInstruction indicates the APDU instruction byte
	// is not recognized by the handler.
	ErrUnsupportedInstruction = errors.New("ccid: unsupported instruction")

	// ErrSessionNotFound indicates a referenced card session does
	// not exist or has been closed.
	ErrSessionNotFound = errors.New("ccid: session not found")

	// ErrNilHandler indicates a nil APDUHandler was provided.
	ErrNilHandler = errors.New("ccid: nil APDU handler")

	// ErrNilLogger indicates a nil logger was provided.
	ErrNilLogger = errors.New("ccid: nil logger")

	// ErrNilService indicates a nil PKCS#11 service was provided.
	ErrNilService = errors.New("ccid: nil PKCS#11 service")

	// ErrCCIDMessageTooShort indicates the received CCID message is
	// too short to contain a valid header.
	ErrCCIDMessageTooShort = errors.New("ccid: message too short")

	// ErrCCIDUnsupportedMessage indicates the CCID message type is
	// not supported by this implementation.
	ErrCCIDUnsupportedMessage = errors.New("ccid: unsupported message type")

	// ErrLoginFailed indicates PIN verification (C_Login) failed.
	ErrLoginFailed = errors.New("ccid: login failed")

	// ErrSignFailed indicates a signing operation failed.
	ErrSignFailed = errors.New("ccid: sign operation failed")

	// ErrVerifyFailed indicates a signature verification failed.
	ErrVerifyFailed = errors.New("ccid: verify operation failed")

	// ErrEncryptFailed indicates an encryption operation failed.
	ErrEncryptFailed = errors.New("ccid: encrypt operation failed")

	// ErrDecryptFailed indicates a decryption operation failed.
	ErrDecryptFailed = errors.New("ccid: decrypt operation failed")

	// ErrKeyGenerationFailed indicates key pair generation failed.
	ErrKeyGenerationFailed = errors.New("ccid: key generation failed")

	// ErrCertificateReadFailed indicates certificate retrieval failed.
	ErrCertificateReadFailed = errors.New("ccid: certificate read failed")

	// ErrAppletNotSelected indicates no applet has been selected
	// (SELECT command required before operations).
	ErrAppletNotSelected = errors.New("ccid: applet not selected")
)

// CCIDError provides structured error information for CCID operations.
// It wraps a sentinel error with the operation name for context.
type CCIDError struct {
	// Operation is the name of the operation that failed.
	Operation string

	// Err is the underlying error.
	Err error
}

// Error returns the formatted error message.
func (e *CCIDError) Error() string {
	return fmt.Sprintf("ccid: %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *CCIDError) Unwrap() error {
	return e.Err
}

// NewCCIDError creates a new CCIDError with the given operation and cause.
func NewCCIDError(operation string, err error) *CCIDError {
	return &CCIDError{
		Operation: operation,
		Err:       err,
	}
}
