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

package cmd

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ccid"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pkcs11"
)

// blockingCCIDTransport is an in-memory gadget.Transport whose Read blocks
// until the caller's context ends, announcing each Read on reading so a test
// knows the CCID event loop is running without sleeping.
type blockingCCIDTransport struct {
	reading chan struct{}
}

func (b *blockingCCIDTransport) Read(ctx context.Context) ([]byte, error) {
	select {
	case b.reading <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (b *blockingCCIDTransport) Write([]byte) error { return nil }

func (b *blockingCCIDTransport) Close() error { return nil }

// newLoopTestDevice builds a CCID device and PKCS#11 bridge over an
// in-memory transport. The bridge's PKCS#11 transport is never connected:
// the loop under test only drives the CCID event loop and closes sessions.
func newLoopTestDevice(t *testing.T) (*ccid.CCIDDevice, *ccid.PKCS11Bridge, *blockingCCIDTransport) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bridge, err := ccid.NewPKCS11Bridge(pkcs11.NewIPCTransport(""), logger)
	require.NoError(t, err)
	transport := &blockingCCIDTransport{reading: make(chan struct{}, 1)}
	device, err := ccid.NewCCIDDevice(bridge, transport, logger)
	require.NoError(t, err)
	return device, bridge, transport
}

// TestRunUSBDeviceLoop_StopsCleanlyOnShutdown proves a shutdown signal (the
// context ending) is a clean stop, not a device error: the loop returns nil
// once the running device sees the cancellation.
func TestRunUSBDeviceLoop_StopsCleanlyOnShutdown(t *testing.T) {
	device, bridge, transport := newLoopTestDevice(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- runUSBDeviceLoop(ctx, device, bridge, logger) }()

	<-transport.reading
	require.True(t, device.IsRunning(), "the device must be serving before shutdown")
	cancel()

	require.NoError(t, <-done)
	require.False(t, device.IsRunning(), "the device must stop with the loop")
}

// TestRunUSBDeviceLoop_ReportsAStartFailure proves a device that cannot
// start is reported as ErrUSBDeviceStartFailed carrying the CCID cause,
// rather than mistaken for a shutdown: here the device is already serving
// another loop, so the second Start is refused.
func TestRunUSBDeviceLoop_ReportsAStartFailure(t *testing.T) {
	device, bridge, transport := newLoopTestDevice(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	firstCtx, stopFirst := context.WithCancel(context.Background())
	defer stopFirst()

	first := make(chan error, 1)
	go func() { first <- device.Start(firstCtx) }()
	<-transport.reading

	err := runUSBDeviceLoop(context.Background(), device, bridge, logger)
	require.ErrorIs(t, err, ErrUSBDeviceStartFailed)
	require.ErrorIs(t, err, ccid.ErrDeviceAlreadyRunning)

	stopFirst()
	require.NoError(t, <-first)
}
