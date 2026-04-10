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

package gadget

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
)

// readPollInterval is the timeout set on each UHID read cycle. Between
// cycles the transport checks for context cancellation, giving the caller
// responsive shutdown behaviour without busy-spinning.
const readPollInterval = 200 * time.Millisecond

// UHIDTransport adapts a uhid.Device to the Transport interface.
// It wraps the UHID read/write operations with context cancellation
// support by using short read timeouts and polling.
type UHIDTransport struct {
	dev    *uhid.Device
	closed atomic.Bool
	logger *slog.Logger
}

// Compile-time interface check.
var _ Transport = (*UHIDTransport)(nil)

// NewUHIDTransport creates a new UHIDTransport wrapping the given UHID device.
// The device must already be opened and created before use.
func NewUHIDTransport(dev *uhid.Device, logger *slog.Logger) (*UHIDTransport, error) {
	if dev == nil {
		return nil, ErrNilDevice
	}
	if logger == nil {
		return nil, ErrNilLogger
	}
	return &UHIDTransport{
		dev:    dev,
		logger: logger,
	}, nil
}

// Read blocks until a message is available from the host or the context
// is cancelled. It sets a short read timeout on the underlying UHID device
// and polls in a loop, checking for context cancellation between each
// attempt. Returns ErrTransportClosed if the transport has been closed.
func (t *UHIDTransport) Read(ctx context.Context) ([]byte, error) {
	if t.closed.Load() {
		return nil, ErrTransportClosed
	}

	t.dev.SetReadTimeout(readPollInterval)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if t.closed.Load() {
			return nil, ErrTransportClosed
		}

		data, err := t.dev.ReadOutput()
		if err != nil {
			if errors.Is(err, uhid.ErrTimeout) {
				continue
			}
			return nil, err
		}
		return data, nil
	}
}

// Write sends a response message to the host via the UHID device.
// Returns ErrTransportClosed if the transport has been closed.
func (t *UHIDTransport) Write(data []byte) error {
	if t.closed.Load() {
		return ErrTransportClosed
	}
	return t.dev.WriteInput(data)
}

// Close releases the transport by closing the underlying UHID device.
// Close is idempotent; calling it more than once returns nil.
func (t *UHIDTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.logger.Info("closing UHID transport")
	return t.dev.Close()
}

// Device returns the underlying uhid.Device for configuration access.
func (t *UHIDTransport) Device() *uhid.Device {
	return t.dev
}
