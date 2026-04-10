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

package pairing

import "context"

// Transport defines the interface for communication transports between
// paired devices. Both BLETransport and TCPTransport implement this
// interface, allowing the Noise handshake and device backends to work
// with any transport.
type Transport interface {
	// Send transmits a message to the connected device.
	Send(ctx context.Context, message []byte) error

	// Receive waits for a complete response message from the device.
	Receive(ctx context.Context) ([]byte, error)

	// SendAndReceive sends a message and waits for the response.
	SendAndReceive(ctx context.Context, message []byte) ([]byte, error)

	// IsConnected returns true if the transport is currently connected.
	IsConnected() bool

	// Close closes the transport and releases all resources.
	Close() error
}
