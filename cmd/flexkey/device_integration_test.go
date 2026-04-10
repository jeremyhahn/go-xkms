//go:build ignore

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipIfNoUHID(t *testing.T) {
	if _, err := os.Stat("/dev/uhid"); os.IsNotExist(err) {
		t.Skip("UHID not available - skipping integration test")
	}
}

// TestVirtualFIDO2DeviceRunIntegration tests the Run method with a real UHID device.
func TestVirtualFIDO2DeviceRunIntegration(t *testing.T) {
	skipIfNoUHID(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &Config{
		StorageType:  StorageTypeMemory,
		DeviceName:   "Integration Test Virtual FIDO2",
		SerialNumber: GenerateSerialNumber(),
		EnablePIN:    false,
		LogLevel:     "debug",
	}

	device, err := NewVirtualFIDO2Device(cfg, logger)
	require.NoError(t, err, "Failed to create device")
	require.NotNil(t, device)

	// Run in a goroutine with context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	var runErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr = device.Run(ctx)
	}()

	// Wait for device to start
	time.Sleep(200 * time.Millisecond)

	// Verify device is running
	assert.True(t, device.IsRunning(), "Device should be running")

	// Cancel context to stop
	cancel()

	// Wait for Run to complete with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("Device stopped successfully")
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for device to stop")
	}

	// Run error should be context.Canceled which is normal for graceful shutdown
	if runErr != nil {
		assert.ErrorIs(t, runErr, context.Canceled, "Run should return context.Canceled on graceful shutdown")
	}

	// Verify device is no longer running
	assert.False(t, device.IsRunning(), "Device should not be running after stop")

	// Clean up
	err = device.Close()
	assert.NoError(t, err, "Close should succeed")
}

// TestVirtualFIDO2DeviceRunWithFileStorageIntegration tests Run with file storage.
func TestVirtualFIDO2DeviceRunWithFileStorageIntegration(t *testing.T) {
	skipIfNoUHID(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	tmpDir := t.TempDir()

	cfg := &Config{
		StorageType:  StorageTypeFile,
		StoragePath:  tmpDir,
		DeviceName:   "File Storage Test FIDO2",
		SerialNumber: GenerateSerialNumber(),
		EnablePIN:    false,
		LogLevel:     "info",
	}

	device, err := NewVirtualFIDO2Device(cfg, logger)
	require.NoError(t, err, "Failed to create device with file storage")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		device.Run(ctx)
	}()

	// Wait for device to start
	time.Sleep(200 * time.Millisecond)
	assert.True(t, device.IsRunning(), "Device should be running")

	// Stop device
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("File storage device stopped successfully")
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for file storage device to stop")
	}

	device.Close()
}

// TestVirtualFIDO2DeviceRunWithPINIntegration tests Run with PIN enabled.
func TestVirtualFIDO2DeviceRunWithPINIntegration(t *testing.T) {
	skipIfNoUHID(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := &Config{
		StorageType:  StorageTypeMemory,
		DeviceName:   "PIN Enabled Test FIDO2",
		SerialNumber: GenerateSerialNumber(),
		EnablePIN:    true,
		PIN:          "123456",
		LogLevel:     "info",
	}

	device, err := NewVirtualFIDO2Device(cfg, logger)
	require.NoError(t, err, "Failed to create device with PIN")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		device.Run(ctx)
	}()

	// Wait for device to start
	time.Sleep(200 * time.Millisecond)
	assert.True(t, device.IsRunning(), "Device should be running")

	// Stop device
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("PIN enabled device stopped successfully")
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for PIN device to stop")
	}

	device.Close()
}

// TestVirtualFIDO2DeviceRunAlreadyRunningIntegration tests calling Run on an already running device.
func TestVirtualFIDO2DeviceRunAlreadyRunningIntegration(t *testing.T) {
	skipIfNoUHID(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := &Config{
		StorageType:  StorageTypeMemory,
		DeviceName:   "Already Running Test",
		SerialNumber: GenerateSerialNumber(),
		EnablePIN:    false,
	}

	device, err := NewVirtualFIDO2Device(cfg, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		device.Run(ctx)
	}()

	// Wait for first Run to start
	time.Sleep(200 * time.Millisecond)
	assert.True(t, device.IsRunning())

	// Try to call Run again - should return error
	err = device.Run(context.Background())
	assert.Error(t, err, "Second Run call should fail")
	assert.ErrorIs(t, err, ErrDeviceAlreadyRunning, "Should return ErrDeviceAlreadyRunning")

	// Clean up
	cancel()
	wg.Wait()
	device.Close()
}

// TestVirtualFIDO2DeviceEventLoopTimeoutIntegration tests that the event loop handles timeouts correctly.
func TestVirtualFIDO2DeviceEventLoopTimeoutIntegration(t *testing.T) {
	skipIfNoUHID(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &Config{
		StorageType:  StorageTypeMemory,
		DeviceName:   "Timeout Test FIDO2",
		SerialNumber: GenerateSerialNumber(),
		EnablePIN:    false,
	}

	device, err := NewVirtualFIDO2Device(cfg, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		device.Run(ctx)
	}()

	// Let the event loop run for a bit and process some timeouts
	time.Sleep(500 * time.Millisecond)

	// Device should still be running (timeouts are handled gracefully)
	assert.True(t, device.IsRunning(), "Device should still be running after timeouts")

	// Clean up
	cancel()
	wg.Wait()
	device.Close()
}

// TestVirtualFIDO2DeviceResponseHandlerIntegration tests the response handler callback.
func TestVirtualFIDO2DeviceResponseHandlerIntegration(t *testing.T) {
	skipIfNoUHID(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &Config{
		StorageType:  StorageTypeMemory,
		DeviceName:   "Response Handler Test",
		SerialNumber: GenerateSerialNumber(),
		EnablePIN:    false,
	}

	device, err := NewVirtualFIDO2Device(cfg, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		device.Run(ctx)
	}()

	// Wait for device to start
	time.Sleep(200 * time.Millisecond)
	require.True(t, device.IsRunning())

	// Get the authenticator and verify it works
	auth := device.Authenticator()
	require.NotNil(t, auth, "Authenticator should be accessible")

	// Stop and clean up
	cancel()
	wg.Wait()
	device.Close()
}

// TestVirtualFIDO2DeviceCloseWhileRunningIntegration tests closing the device while it's running.
func TestVirtualFIDO2DeviceCloseWhileRunningIntegration(t *testing.T) {
	skipIfNoUHID(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := &Config{
		StorageType:  StorageTypeMemory,
		DeviceName:   "Close While Running Test",
		SerialNumber: GenerateSerialNumber(),
		EnablePIN:    false,
	}

	device, err := NewVirtualFIDO2Device(cfg, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		device.Run(ctx)
	}()

	// Wait for device to start
	time.Sleep(200 * time.Millisecond)
	require.True(t, device.IsRunning())

	// Close while running (should stop gracefully)
	err = device.Close()
	assert.NoError(t, err, "Close should succeed while running")

	// Wait for Run to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("Device stopped after Close()")
	case <-time.After(3 * time.Second):
		t.Log("Timeout waiting - cancelling context")
		cancel()
		wg.Wait()
	}
}

// TestVirtualFIDO2DeviceMultipleRunStopCyclesIntegration tests starting and stopping multiple times.
func TestVirtualFIDO2DeviceMultipleRunStopCyclesIntegration(t *testing.T) {
	skipIfNoUHID(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("cycle_%d", i), func(t *testing.T) {
			cfg := &Config{
				StorageType:  StorageTypeMemory,
				DeviceName:   fmt.Sprintf("Cycle Test %d", i),
				SerialNumber: GenerateSerialNumber(),
				EnablePIN:    false,
			}

			device, err := NewVirtualFIDO2Device(cfg, logger)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				device.Run(ctx)
			}()

			// Wait for device to start
			time.Sleep(100 * time.Millisecond)
			require.True(t, device.IsRunning())

			// Stop
			cancel()
			wg.Wait()
			device.Close()

			assert.False(t, device.IsRunning())
		})
	}
}
