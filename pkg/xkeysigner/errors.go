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

// Package xkeysigner implements crypto.Signer via xkey IPC, enabling
// TLS client certificate authentication backed by hardware-protected
// PIV keys managed by the xkey daemon.
package xkeysigner

import "errors"

var (
	// ErrSocketNotFound is returned when the IPC socket does not exist.
	ErrSocketNotFound = errors.New("xkeysigner: IPC socket not found")

	// ErrSignFailed is returned when a signing operation fails.
	ErrSignFailed = errors.New("xkeysigner: signing operation failed")

	// ErrConnectionFailed is returned when the IPC connection cannot be established.
	ErrConnectionFailed = errors.New("xkeysigner: IPC connection failed")

	// ErrClosed is returned when an operation is attempted on a closed signer.
	ErrClosed = errors.New("xkeysigner: signer is closed")

	// ErrNilPublicKey is returned when the public key is nil.
	ErrNilPublicKey = errors.New("xkeysigner: public key is nil")

	// ErrInvalidSlot is returned when an invalid PIV slot is specified.
	ErrInvalidSlot = errors.New("xkeysigner: invalid PIV slot")

	// ErrNoCertificate is returned when no certificate is available in the slot.
	ErrNoCertificate = errors.New("xkeysigner: no certificate available")

	// ErrInvalidCertFormat is returned when the certificate format is invalid.
	ErrInvalidCertFormat = errors.New("xkeysigner: invalid certificate format")

	// ErrTLSConfigFailed is returned when TLS config creation fails.
	ErrTLSConfigFailed = errors.New("xkeysigner: TLS config creation failed")

	// ErrNilConfig is returned when a nil config is provided.
	ErrNilConfig = errors.New("xkeysigner: config is nil")
)
