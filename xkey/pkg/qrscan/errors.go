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

package qrscan

import "errors"

// Scanner errors.
var (
	// ErrNoQRCodeFound indicates no QR code was found in the scanned image(s).
	ErrNoQRCodeFound = errors.New("qrscan: no QR code found on screen")

	// ErrInvalidQRContent indicates the QR code doesn't contain a URI matching the scan mode.
	ErrInvalidQRContent = errors.New("qrscan: QR code does not contain a valid URI for the selected scan mode")

	// ErrScreenCaptureUnavailable indicates screen capture is not available.
	ErrScreenCaptureUnavailable = errors.New("qrscan: screen capture not available")

	// ErrNoDisplaysFound indicates no displays were found.
	ErrNoDisplaysFound = errors.New("qrscan: no displays found")

	// ErrMultipleQRCodesFound indicates multiple QR codes were found (user should specify).
	ErrMultipleQRCodesFound = errors.New("qrscan: multiple QR codes found")

	// ErrScanCancelled indicates the scan was cancelled by the user.
	ErrScanCancelled = errors.New("qrscan: scan cancelled")

	// ErrDisplayIndexOutOfRange indicates the requested display index exceeds
	// the number of available displays.
	ErrDisplayIndexOutOfRange = errors.New("qrscan: display index out of range")

	// ErrScreenCaptureFailed indicates the screen capture operation failed.
	ErrScreenCaptureFailed = errors.New("qrscan: screen capture failed")

	// ErrBitmapCreationFailed indicates bitmap conversion from a captured image failed.
	ErrBitmapCreationFailed = errors.New("qrscan: bitmap creation failed")
)
