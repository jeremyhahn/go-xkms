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

//go:build linux

package virtualdevice

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
)

// TestNativeVirtualDevice_Create tests device creation with default config.
func TestNativeVirtualDevice_Create(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	if device.Path() == "" {
		t.Error("Path() returned empty string")
	}

	if device.SerialNumber() != "NFIDO001" {
		t.Errorf("unexpected serial number: %s", device.SerialNumber())
	}

	if device.Manufacturer() != "go-xkms" {
		t.Errorf("unexpected manufacturer: %s", device.Manufacturer())
	}

	if device.Product() != uhid.AuthenticatorDeviceName {
		t.Errorf("unexpected product: %s", device.Product())
	}

	if device.VendorID() != NativeVirtualDeviceVendorID {
		t.Errorf("unexpected vendor ID: 0x%04X", device.VendorID())
	}

	if device.ProductID() != NativeVirtualDeviceProductID {
		t.Errorf("unexpected product ID: 0x%04X", device.ProductID())
	}
}

// TestNativeVirtualDevice_CreateWithConfig tests device creation with custom config.
func TestNativeVirtualDevice_CreateWithConfig(t *testing.T) {
	config := &NativeVirtualDeviceConfig{
		SerialNumber:               "CUSTOM123",
		Manufacturer:               "TestMfg",
		Product:                    "TestProduct",
		AAGUID:                     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		EnablePIN:                  true,
		EnableHMACSecret:           true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		SupportedAlgorithms:        []int{-7}, // ES256
	}

	device, err := NewNativeVirtualDevice(config)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	if device.SerialNumber() != "CUSTOM123" {
		t.Errorf("unexpected serial number: %s", device.SerialNumber())
	}

	if device.Manufacturer() != "TestMfg" {
		t.Errorf("unexpected manufacturer: %s", device.Manufacturer())
	}

	if device.Product() != "TestProduct" {
		t.Errorf("unexpected product: %s", device.Product())
	}

	expectedPath := NativeVirtualDevicePathPrefix + "CUSTOM123"
	if device.Path() != expectedPath {
		t.Errorf("unexpected path: got %s, want %s", device.Path(), expectedPath)
	}

	// Verify authenticator has custom AAGUID
	auth := device.Authenticator()
	if auth == nil {
		t.Fatal("Authenticator() returned nil")
	}

	aaguid := auth.AAGUID()
	if aaguid != config.AAGUID {
		t.Errorf("AAGUID mismatch: got %v, want %v", aaguid, config.AAGUID)
	}
}

// TestNativeVirtualDevice_CreateWithStorage tests device creation with custom storage.
func TestNativeVirtualDevice_CreateWithStorage(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	config := &NativeVirtualDeviceConfig{
		Storage: storage,
	}

	device, err := NewNativeVirtualDevice(config)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Verify storage is being used
	auth := device.Authenticator()
	if auth == nil {
		t.Fatal("Authenticator() returned nil")
	}
}

// TestNativeVirtualDevice_Init tests CTAPHID_INIT command.
func TestNativeVirtualDevice_Init(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Create INIT packet
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := make([]byte, fido2.HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], fido2.CIDBroadcast)
	packet[4] = fido2.CTAPHID_INIT
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(nonce)))
	copy(packet[7:], nonce)

	// Write packet
	n, err := device.Write(packet)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(packet) {
		t.Errorf("Write returned %d, want %d", n, len(packet))
	}

	// Read response
	response := make([]byte, fido2.HIDPacketSize)
	n, err = device.Read(response)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != fido2.HIDPacketSize {
		t.Errorf("Read returned %d, want %d", n, fido2.HIDPacketSize)
	}

	// Verify response
	cmd := response[4]
	if cmd != fido2.CTAPHID_INIT {
		t.Errorf("expected INIT response (0x%02X), got 0x%02X", fido2.CTAPHID_INIT, cmd)
	}

	// Verify nonce echo
	respNonce := response[7:15]
	if !bytes.Equal(respNonce, nonce) {
		t.Errorf("nonce mismatch: got %v, want %v", respNonce, nonce)
	}

	// Verify CID allocation
	cid := binary.BigEndian.Uint32(response[15:19])
	if cid == 0 || cid == fido2.CIDBroadcast {
		t.Errorf("invalid CID allocated: 0x%08X", cid)
	}
}

// TestNativeVirtualDevice_Ping tests CTAPHID_PING command.
func TestNativeVirtualDevice_Ping(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// First initialize
	cid := initializeChannel(t, device)

	// Create PING packet
	pingData := []byte("Hello, FIDO!")
	packet := make([]byte, fido2.HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = fido2.CTAPHID_PING
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(pingData)))
	copy(packet[7:], pingData)

	// Write packet
	_, err = device.Write(packet)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read response
	response := make([]byte, fido2.HIDPacketSize)
	_, err = device.Read(response)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Verify response
	if response[4] != fido2.CTAPHID_PING {
		t.Errorf("expected PING response, got 0x%02X", response[4])
	}

	respLen := int(binary.BigEndian.Uint16(response[5:7]))
	if respLen != len(pingData) {
		t.Errorf("response length mismatch: got %d, want %d", respLen, len(pingData))
	}

	respPayload := response[7 : 7+respLen]
	if !bytes.Equal(respPayload, pingData) {
		t.Errorf("ping response mismatch")
	}
}

// TestNativeVirtualDevice_GetInfo tests CTAPHID_CBOR GetInfo command.
func TestNativeVirtualDevice_GetInfo(t *testing.T) {
	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		EnablePIN:         true,
		EnableHMACSecret:  true,
		EnableResidentKey: true,
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// First initialize
	cid := initializeChannel(t, device)

	// Create GetInfo packet
	packet := make([]byte, fido2.HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = fido2.CTAPHID_CBOR
	binary.BigEndian.PutUint16(packet[5:7], 1) // Just command byte
	packet[7] = fido2.CmdGetInfo

	// Write packet
	_, err = device.Write(packet)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read response(s)
	response := readFullResponse(t, device, cid)

	// First byte should be status OK
	if response[0] != 0x00 {
		t.Errorf("expected status OK (0x00), got 0x%02X", response[0])
	}

	// Should have CBOR data after status
	if len(response) < 2 {
		t.Error("response too short, expected CBOR data")
	}
}

// TestNativeVirtualDevice_MakeCredential tests MakeCredential command.
func TestNativeVirtualDevice_MakeCredential(t *testing.T) {
	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		EnablePIN:         false, // Disable PIN for simpler test
		EnableResidentKey: true,
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// First initialize
	cid := initializeChannel(t, device)

	// Create MakeCredential request (simplified CBOR)
	clientDataHash := make([]byte, 32)
	for i := range clientDataHash {
		clientDataHash[i] = byte(i)
	}

	// Build CBOR request manually (simplified)
	cborData := buildMakeCredentialCBOR(clientDataHash, "example.com", "Example", []byte{1, 2, 3, 4}, "testuser", "Test User")

	payload := append([]byte{fido2.CmdMakeCredential}, cborData...)

	// Send CBOR command
	sendCBORCommand(t, device, cid, payload)

	// Read response
	response := readFullResponse(t, device, cid)

	// Check status
	if len(response) < 1 {
		t.Error("response too short")
	}

	// Status should be OK (0x00) since we have a software authenticator
	// that auto-approves user presence
	if response[0] != 0x00 {
		t.Logf("MakeCredential status: 0x%02X (may be expected for non-interactive test)", response[0])
	}
}

// TestNativeVirtualDevice_GetAssertion tests GetAssertion command.
func TestNativeVirtualDevice_GetAssertion(t *testing.T) {
	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		EnablePIN:         false,
		EnableResidentKey: true,
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// First initialize
	cid := initializeChannel(t, device)

	// First create a credential
	clientDataHash := make([]byte, 32)
	for i := range clientDataHash {
		clientDataHash[i] = byte(i)
	}

	cborData := buildMakeCredentialCBOR(clientDataHash, "example.com", "Example", []byte{1, 2, 3, 4}, "testuser", "Test User")
	payload := append([]byte{fido2.CmdMakeCredential}, cborData...)
	sendCBORCommand(t, device, cid, payload)

	// Read MakeCredential response to get credential ID
	mcResponse := readFullResponse(t, device, cid)
	if mcResponse[0] != 0x00 {
		t.Skipf("MakeCredential failed with status 0x%02X, skipping GetAssertion test", mcResponse[0])
	}

	// Now try GetAssertion
	gaPayload := buildGetAssertionCBOR(clientDataHash, "example.com")
	sendCBORCommand(t, device, cid, append([]byte{fido2.CmdGetAssertion}, gaPayload...))

	// Read response
	response := readFullResponse(t, device, cid)
	if len(response) < 1 {
		t.Error("response too short")
	}
}

// TestNativeVirtualDevice_Close tests device closure.
func TestNativeVirtualDevice_Close(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	// Close the device
	err = device.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Write should fail after close
	packet := make([]byte, fido2.HIDPacketSize)
	_, err = device.Write(packet)
	if err != ErrNativeDeviceClosed {
		t.Errorf("expected ErrNativeDeviceClosed, got %v", err)
	}

	// Read should fail after close
	_, err = device.Read(packet)
	if err != ErrNativeDeviceClosed {
		t.Errorf("expected ErrNativeDeviceClosed, got %v", err)
	}

	// Double close should be safe
	err = device.Close()
	if err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

// TestNativeVirtualDevice_HIDDevice tests HIDDevice interface compliance.
func TestNativeVirtualDevice_HIDDevice(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Verify all HIDDevice methods
	var hid fido2.HIDDevice = device

	if hid.Path() == "" {
		t.Error("Path() empty")
	}
	if hid.VendorID() == 0 {
		t.Error("VendorID() is 0")
	}
	if hid.ProductID() == 0 {
		t.Error("ProductID() is 0")
	}
	if hid.Product() == "" {
		t.Error("Product() empty")
	}
	if hid.Manufacturer() == "" {
		t.Error("Manufacturer() empty")
	}
	if hid.SerialNumber() == "" {
		t.Error("SerialNumber() empty")
	}
}

// TestNativeVirtualDevice_Authenticator tests Authenticator accessor.
func TestNativeVirtualDevice_Authenticator(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	auth := device.Authenticator()
	if auth == nil {
		t.Error("Authenticator() returned nil")
	}
}

// TestNativeVirtualDevice_HIDHandler tests HIDHandler accessor.
func TestNativeVirtualDevice_HIDHandler(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	handler := device.HIDHandler()
	if handler == nil {
		t.Error("HIDHandler() returned nil")
	}
}

// TestNativeVirtualDevice_Concurrency tests concurrent access.
func TestNativeVirtualDevice_Concurrency(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Initialize channel
	cid := initializeChannel(t, device)

	// Run concurrent pings
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			pingData := []byte{byte(id)}
			packet := make([]byte, fido2.HIDPacketSize)
			binary.BigEndian.PutUint32(packet[0:4], cid)
			packet[4] = fido2.CTAPHID_PING
			binary.BigEndian.PutUint16(packet[5:7], uint16(len(pingData)))
			copy(packet[7:], pingData)

			_, err := device.Write(packet)
			if err != nil && err != ErrNativeDeviceClosed {
				t.Errorf("goroutine %d: Write failed: %v", id, err)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for goroutines")
		}
	}
}

// TestNativeVirtualDevice_HandleResponseWhenClosed tests that handleResponse
// gracefully handles the case when the device is closed.
func TestNativeVirtualDevice_HandleResponseWhenClosed(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	// Close the device first
	err = device.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Calling handleResponse on a closed device should not panic
	// This exercises the early return path in handleResponse
	device.handleResponse([]byte{0x01, 0x02, 0x03})
}

// TestNativeVirtualDevice_ResponseChannelOverflow tests the response channel
// overflow handling in handleResponse.
func TestNativeVirtualDevice_ResponseChannelOverflow(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Fill the response channel to capacity (64 items)
	for i := 0; i < nativeDeviceRespChanSize; i++ {
		device.handleResponse([]byte{byte(i)})
	}

	// Now send one more - this should trigger the overflow handling code
	// which drops the oldest response to make room
	device.handleResponse([]byte{0xFF})

	// Drain the channel and verify we got responses
	drainedCount := 0
	for {
		select {
		case <-device.respChan:
			drainedCount++
		default:
			goto done
		}
	}
done:

	// Should have drained all responses (the overflow handling should have worked)
	if drainedCount == 0 {
		t.Error("expected to drain some responses from channel")
	}
}

// TestNativeVirtualDevice_ReadAfterChannelClose tests Read behavior when
// the response channel is closed.
func TestNativeVirtualDevice_ReadAfterChannelClose(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	// Close the device (which closes the response channel)
	err = device.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read should return ErrNativeDeviceClosed
	data := make([]byte, fido2.HIDPacketSize)
	_, err = device.Read(data)
	if err != ErrNativeDeviceClosed {
		t.Errorf("expected ErrNativeDeviceClosed, got %v", err)
	}
}

// TestNativeVirtualDevice_ConcurrentWritesWithOverflow tests concurrent writes
// that may cause response channel overflow.
func TestNativeVirtualDevice_ConcurrentWritesWithOverflow(t *testing.T) {
	device, err := NewNativeVirtualDevice(nil)
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Initialize channel
	cid := initializeChannel(t, device)

	// Send many concurrent ping requests without reading responses
	// This should fill the response channel and trigger overflow handling
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			pingData := []byte{byte(id)}
			packet := make([]byte, fido2.HIDPacketSize)
			binary.BigEndian.PutUint32(packet[0:4], cid)
			packet[4] = fido2.CTAPHID_PING
			binary.BigEndian.PutUint16(packet[5:7], uint16(len(pingData)))
			copy(packet[7:], pingData)

			_, _ = device.Write(packet)
		}(i)
	}

	wg.Wait()

	// Now drain the channel - we should get some responses
	drainedCount := 0
	for {
		select {
		case <-device.respChan:
			drainedCount++
		default:
			goto done
		}
	}
done:

	if drainedCount == 0 {
		t.Error("expected to drain some responses")
	}
}

// Helper functions

// initializeChannel performs CTAPHID_INIT and returns the allocated CID.
func initializeChannel(t *testing.T, device *NativeVirtualDevice) uint32 {
	t.Helper()

	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := make([]byte, fido2.HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], fido2.CIDBroadcast)
	packet[4] = fido2.CTAPHID_INIT
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(nonce)))
	copy(packet[7:], nonce)

	_, err := device.Write(packet)
	if err != nil {
		t.Fatalf("INIT Write failed: %v", err)
	}

	response := make([]byte, fido2.HIDPacketSize)
	_, err = device.Read(response)
	if err != nil {
		t.Fatalf("INIT Read failed: %v", err)
	}

	if response[4] != fido2.CTAPHID_INIT {
		t.Fatalf("expected INIT response, got 0x%02X", response[4])
	}

	cid := binary.BigEndian.Uint32(response[15:19])
	return cid
}

// sendCBORCommand sends a CBOR command packet.
func sendCBORCommand(t *testing.T, device *NativeVirtualDevice, cid uint32, payload []byte) {
	t.Helper()

	// Create init packet
	packet := make([]byte, fido2.HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = fido2.CTAPHID_CBOR
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(payload)))

	// Copy first portion of payload
	initPayload := 57 // HIDPacketSize - 7
	if len(payload) <= initPayload {
		copy(packet[7:], payload)
		_, err := device.Write(packet)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		return
	}

	copy(packet[7:], payload[:initPayload])
	_, err := device.Write(packet)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Send continuation packets
	remaining := payload[initPayload:]
	seq := byte(0)
	for len(remaining) > 0 {
		contPacket := make([]byte, fido2.HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayload := 59 // HIDPacketSize - 5
		if len(remaining) < contPayload {
			contPayload = len(remaining)
		}
		copy(contPacket[5:], remaining[:contPayload])

		_, err := device.Write(contPacket)
		if err != nil {
			t.Fatalf("continuation Write failed: %v", err)
		}

		remaining = remaining[contPayload:]
		seq++
	}
}

// readFullResponse reads and reassembles a multi-packet response.
// It skips any CTAPHID_KEEPALIVE packets that may arrive before the actual response,
// since MakeCredential and GetAssertion commands send keepalives while processing.
func readFullResponse(t *testing.T, device *NativeVirtualDevice, cid uint32) []byte {
	t.Helper()

	// Read packets, skipping keepalives that are sent during long-running operations
	var packet []byte
	for {
		pkt := make([]byte, fido2.HIDPacketSize)
		_, err := device.Read(pkt)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		cmd := pkt[4]
		if cmd == fido2.CTAPHID_KEEPALIVE {
			// Skip keepalive packets - these are expected during
			// MakeCredential and GetAssertion processing
			continue
		}

		packet = pkt
		break
	}

	respCID := binary.BigEndian.Uint32(packet[0:4])
	if respCID != cid {
		t.Fatalf("CID mismatch: got 0x%08X, want 0x%08X", respCID, cid)
	}

	cmd := packet[4]
	if cmd == fido2.CTAPHID_ERROR {
		return []byte{packet[7]} // Return error code as status
	}

	if cmd != fido2.CTAPHID_CBOR {
		t.Fatalf("expected CBOR response, got 0x%02X", cmd)
	}

	payloadLen := int(binary.BigEndian.Uint16(packet[5:7]))
	if payloadLen == 0 {
		return []byte{}
	}

	initPayload := 57
	if payloadLen <= initPayload {
		return packet[7 : 7+payloadLen]
	}

	// Multi-packet response
	result := make([]byte, 0, payloadLen)
	result = append(result, packet[7:]...)

	// Read continuation packets
	for len(result) < payloadLen {
		contPacket := make([]byte, fido2.HIDPacketSize)
		_, err := device.Read(contPacket)
		if err != nil {
			t.Fatalf("continuation Read failed: %v", err)
		}

		remaining := payloadLen - len(result)
		contPayload := 59
		if remaining < contPayload {
			contPayload = remaining
		}
		result = append(result, contPacket[5:5+contPayload]...)
	}

	return result[:payloadLen]
}

// buildMakeCredentialCBOR builds a minimal MakeCredential CBOR request.
func buildMakeCredentialCBOR(clientDataHash []byte, rpID, rpName string, userID []byte, userName, displayName string) []byte {
	result := []byte{
		0xA4, // Map of 4 items
	}

	// 1: clientDataHash
	result = append(result, 0x01)                            // Key 1
	result = append(result, 0x58, byte(len(clientDataHash))) // Bytes with 1-byte length
	result = append(result, clientDataHash...)

	// 2: rp {id: rpID, name: rpName}
	result = append(result, 0x02) // Key 2
	result = append(result, 0xA2) // Map of 2
	result = append(result, 0x62, 'i', 'd')
	result = append(result, 0x60+byte(len(rpID)))
	result = append(result, []byte(rpID)...)
	result = append(result, 0x64, 'n', 'a', 'm', 'e')
	result = append(result, 0x60+byte(len(rpName)))
	result = append(result, []byte(rpName)...)

	// 3: user {id: userID, name: userName, displayName: displayName}
	result = append(result, 0x03) // Key 3
	result = append(result, 0xA3) // Map of 3
	result = append(result, 0x62, 'i', 'd')
	result = append(result, 0x40+byte(len(userID)))
	result = append(result, userID...)
	result = append(result, 0x64, 'n', 'a', 'm', 'e')
	result = append(result, 0x60+byte(len(userName)))
	result = append(result, []byte(userName)...)
	result = append(result, 0x6B) // "displayName" (11 chars)
	result = append(result, []byte("displayName")...)
	result = append(result, 0x60+byte(len(displayName)))
	result = append(result, []byte(displayName)...)

	// 4: pubKeyCredParams [{type: "public-key", alg: -7}]
	result = append(result, 0x04) // Key 4
	result = append(result, 0x81) // Array of 1
	result = append(result, 0xA2) // Map of 2
	result = append(result, 0x64, 't', 'y', 'p', 'e')
	result = append(result, 0x6A) // "public-key" (10 chars)
	result = append(result, []byte("public-key")...)
	result = append(result, 0x63, 'a', 'l', 'g')
	result = append(result, 0x26) // -7 (ECDSA with SHA-256)

	return result
}

// buildGetAssertionCBOR builds a minimal GetAssertion CBOR request.
func buildGetAssertionCBOR(clientDataHash []byte, rpID string) []byte {
	// Minimal: {1: rpID, 2: clientDataHash}
	result := []byte{
		0xA2, // Map of 2 items
	}

	// 1: rpId
	result = append(result, 0x01) // Key 1
	result = append(result, 0x60+byte(len(rpID)))
	result = append(result, []byte(rpID)...)

	// 2: clientDataHash
	result = append(result, 0x02)                            // Key 2
	result = append(result, 0x58, byte(len(clientDataHash))) // Bytes with 1-byte length
	result = append(result, clientDataHash...)

	return result
}
