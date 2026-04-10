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

//go:build smartcardhsm

package smartcardhsm

import "errors"

var (
	// ErrNotInitialized is returned when the backend is not initialized.
	ErrNotInitialized = errors.New("smartcardhsm: backend not initialized")

	// ErrPCSCNotAvailable is returned when PC/SC is not available.
	ErrPCSCNotAvailable = errors.New("smartcardhsm: PC/SC service not available")

	// ErrCardNotFound is returned when the SmartCard-HSM is not found.
	ErrCardNotFound = errors.New("smartcardhsm: card not found")

	// ErrCardConnectionFailed is returned when connecting to the card fails.
	ErrCardConnectionFailed = errors.New("smartcardhsm: failed to connect to card")

	// ErrDKEKNotInitialized is returned when DKEK operations are attempted
	// but DKEK has not been initialized on the device.
	ErrDKEKNotInitialized = errors.New("smartcardhsm: DKEK not initialized")

	// ErrDKEKAlreadyInitialized is returned when trying to initialize DKEK
	// on a device that already has DKEK configured.
	ErrDKEKAlreadyInitialized = errors.New("smartcardhsm: DKEK already initialized")

	// ErrDKEKShareInvalid is returned when a DKEK share is invalid.
	ErrDKEKShareInvalid = errors.New("smartcardhsm: invalid DKEK share")

	// ErrDKEKSharesIncomplete is returned when not enough DKEK shares have
	// been imported to reconstruct the DKEK.
	ErrDKEKSharesIncomplete = errors.New("smartcardhsm: insufficient DKEK shares imported")

	// ErrDKEKThresholdInvalid is returned when the threshold value is invalid.
	ErrDKEKThresholdInvalid = errors.New("smartcardhsm: invalid threshold (must be 1 <= threshold <= shares)")

	// ErrKeyNotFound is returned when a key is not found on the device.
	ErrKeyNotFound = errors.New("smartcardhsm: key not found")

	// ErrKeyWrapFailed is returned when key wrapping fails.
	ErrKeyWrapFailed = errors.New("smartcardhsm: key wrap failed")

	// ErrKeyUnwrapFailed is returned when key unwrapping fails.
	ErrKeyUnwrapFailed = errors.New("smartcardhsm: key unwrap failed")

	// ErrAPDUFailed is returned when an APDU command fails.
	ErrAPDUFailed = errors.New("smartcardhsm: APDU command failed")

	// ErrAuthenticationFailed is returned when authentication fails.
	ErrAuthenticationFailed = errors.New("smartcardhsm: authentication failed")

	// ErrAuthenticationBlocked is returned when authentication is blocked
	// due to too many failed attempts.
	ErrAuthenticationBlocked = errors.New("smartcardhsm: authentication blocked")

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("smartcardhsm: invalid configuration")

	// ErrDeviceNotSmartCardHSM is returned when the detected device is not
	// a SmartCard-HSM compatible device.
	ErrDeviceNotSmartCardHSM = errors.New("smartcardhsm: device is not a SmartCard-HSM")
)

// APDUError represents an error from an APDU command.
type APDUError struct {
	Command    string
	StatusWord uint16
	Message    string
}

func (e *APDUError) Error() string {
	return "smartcardhsm: " + e.Command + " failed: " + e.Message
}

// NewAPDUError creates a new APDUError from a status word.
func NewAPDUError(command string, sw uint16) *APDUError {
	return &APDUError{
		Command:    command,
		StatusWord: sw,
		Message:    statusWordToMessage(sw),
	}
}

// statusWordToMessage converts a status word to a human-readable message.
func statusWordToMessage(sw uint16) string {
	switch sw {
	case SW_SUCCESS:
		return "success"
	case SW_WRONG_LENGTH:
		return "wrong length"
	case SW_SECURITY_NOT_SAT:
		return "security conditions not satisfied"
	case SW_AUTH_BLOCKED:
		return "authentication blocked"
	case SW_CONDITIONS_NOT_SAT:
		return "conditions of use not satisfied"
	case SW_WRONG_DATA:
		return "wrong data"
	case SW_WRONG_P1P2:
		return "wrong P1/P2 parameters"
	case SW_INS_NOT_SUPPORTED:
		return "instruction not supported"
	case SW_CLA_NOT_SUPPORTED:
		return "class not supported"
	default:
		if sw&0xFF00 == 0x6100 {
			return "more data available"
		}
		if sw&0xFF00 == 0x6C00 {
			return "wrong Le field"
		}
		return "unknown error"
	}
}
