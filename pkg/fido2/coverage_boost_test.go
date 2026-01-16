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

//go:build linux

package fido2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSelectDevice_WithAllowedVendors tests vendor filtering in selectDevice.
func TestSelectDevice_WithAllowedVendors(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0x1234} // Only allow this vendor

	// Create device with matching vendor
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.vendorID = 0x1234

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Should select the device with matching vendor
	device, err := handler.selectDevice()
	require.NoError(t, err)
	assert.NotNil(t, device)
}

// TestSelectDevice_FilterOutNonAllowedVendor tests filtering out non-allowed vendors.
func TestSelectDevice_FilterOutNonAllowedVendor(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0x9999} // Only allow this vendor

	// Create device with non-matching vendor
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.vendorID = 0x1234 // Different vendor

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Should not find any device
	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Equal(t, ErrNoDeviceFound, err)
	assert.Nil(t, device)
}

// TestSelectDevice_WithAllowedProducts tests product filtering in selectDevice.
func TestSelectDevice_WithAllowedProducts(t *testing.T) {
	config := DefaultConfig
	config.AllowedProducts = []uint16{0x5678} // Only allow this product

	// Create device with matching product
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.productID = 0x5678

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	assert.NotNil(t, device)
}

// TestSelectDevice_FilterOutNonAllowedProduct tests filtering out non-allowed products.
func TestSelectDevice_FilterOutNonAllowedProduct(t *testing.T) {
	config := DefaultConfig
	config.AllowedProducts = []uint16{0x9999} // Only allow this product

	// Create device with non-matching product
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.productID = 0x5678 // Different product

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Equal(t, ErrNoDeviceFound, err)
	assert.Nil(t, device)
}

// TestSelectDevice_WithVendorAndProductFilters tests combined vendor/product filtering.
func TestSelectDevice_WithVendorAndProductFilters(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0x1234}
	config.AllowedProducts = []uint16{0x5678}

	// Create device with matching both
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.vendorID = 0x1234
	mockDev.productID = 0x5678

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	assert.NotNil(t, device)
}

// TestSelectDevice_VendorMatchProductMismatch tests vendor match but product mismatch.
func TestSelectDevice_VendorMatchProductMismatch(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0x1234}
	config.AllowedProducts = []uint16{0x9999}

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.vendorID = 0x1234
	mockDev.productID = 0x5678 // Doesn't match

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Equal(t, ErrNoDeviceFound, err)
	assert.Nil(t, device)
}

// TestListDevices_CloseError tests error handling when closing devices during list.
func TestListDevices_CloseError(t *testing.T) {
	config := DefaultConfig

	mockDev := &CloseErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleCloseErrorEnumeratorCB{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Should still return devices even if close fails
	devices, err := handler.ListDevices()
	require.NoError(t, err)
	assert.NotEmpty(t, devices)
}

// CloseErrorDeviceCB returns an error on Close.
type CloseErrorDeviceCB struct {
	*MockHIDDevice
}

func (d *CloseErrorDeviceCB) Close() error {
	return errors.New("close failed")
}

// SingleCloseErrorEnumeratorCB returns a device that fails on close.
type SingleCloseErrorEnumeratorCB struct {
	device *CloseErrorDeviceCB
}

func (e *SingleCloseErrorEnumeratorCB) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return []HIDDevice{e.device}, nil
}

func (e *SingleCloseErrorEnumeratorCB) Open(path string) (HIDDevice, error) {
	return e.device, nil
}

// TestWaitForDevice_ContextCanceled tests context cancellation.
func TestWaitForDevice_ContextCanceled(t *testing.T) {
	config := DefaultConfig

	// Empty enumerator - no devices
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Equal(t, context.DeadlineExceeded, err)
}

// TestMakeCredential_SendCBORError tests error handling when SendCBOR fails.
func TestMakeCredential_SendCBORError(t *testing.T) {
	config := DefaultConfig
	mockDev := &SendCBORErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		failOnCmd:     CmdMakeCredential,
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash: make([]byte, 32),
		RP:             RelyingParty{ID: "test.com", Name: "Test"},
		User:           User{ID: make([]byte, 32), Name: "test", DisplayName: "Test"},
		PubKeyCredParams: []PublicKeyCredentialParameter{
			{Type: "public-key", Alg: COSEAlgES256},
		},
	}

	_, err = auth.MakeCredential(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MakeCredential command failed")
}

// SendCBORErrorDeviceCB fails on specific CBOR commands.
type SendCBORErrorDeviceCB struct {
	*MockHIDDevice
	failOnCmd byte
	initDone  bool
}

func (d *SendCBORErrorDeviceCB) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitRespCB(data[7:])
	case CTAPHID_CBOR:
		if len(data) > 7 && data[7] == d.failOnCmd {
			d.generateErrorRespCB()
		} else {
			d.generateCBORRespCB(data[7:])
		}
	}

	return len(data), nil
}

func (d *SendCBORErrorDeviceCB) generateInitRespCB(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
	d.initDone = true
}

func (d *SendCBORErrorDeviceCB) generateErrorRespCB() {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 1)
	response[7] = StatusInvalidParameter

	d.readBuf.Write(response)
}

func (d *SendCBORErrorDeviceCB) generateCBORRespCB(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoRspCB()
	}
}

func (d *SendCBORErrorDeviceCB) generateGetInfoRspCB() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPktsCB(0x12345678, fullPayload)
}

func (d *SendCBORErrorDeviceCB) writeHIDPktsCB(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	if payloadLen <= HIDPacketSize-7 {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:HIDPacketSize-7])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[HIDPacketSize-7:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		n := HIDPacketSize - 5
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *SendCBORErrorDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestEnrollKey_NoHMACSecretSupport tests EnrollKey when device doesn't support hmac-secret.
func TestEnrollKey_NoHMACSecretSupport(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoExtensionDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	_, err = handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hmac-secret")
}

// NoExtensionDeviceCB returns GetInfo without hmac-secret support.
type NoExtensionDeviceCB struct {
	*MockHIDDevice
}

func (d *NoExtensionDeviceCB) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.genInitRespCB(data[7:])
	case CTAPHID_CBOR:
		d.genCBORRespCB(data[7:])
	}

	return len(data), nil
}

func (d *NoExtensionDeviceCB) genInitRespCB(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *NoExtensionDeviceCB) genCBORRespCB(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		// Return GetInfo WITHOUT hmac-secret extension
		info := map[int]interface{}{
			0x01: []string{"FIDO_2_0"},
			0x02: []string{}, // Empty extensions - no hmac-secret
			0x03: make([]byte, 16),
			0x04: map[string]bool{"up": true},
		}

		encoded, _ := cbor.Marshal(info)
		fullPayload := append([]byte{StatusOK}, encoded...)
		d.writePktsCB(0x12345678, fullPayload)
	}
}

func (d *NoExtensionDeviceCB) writePktsCB(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	if payloadLen <= HIDPacketSize-7 {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:HIDPacketSize-7])
	d.readBuf.Write(firstPacket)
}

func (d *NoExtensionDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestEnrollKey_CustomTimeout tests EnrollKey with custom timeout.
func TestEnrollKey_CustomTimeout(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Timeout = 5 * time.Second // Custom timeout

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// TestUnlockWithKey_CustomTimeout tests UnlockWithKey with custom timeout.
func TestUnlockWithKey_CustomTimeout(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))
	authConfig.Timeout = 5 * time.Second // Custom timeout

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	assert.NotNil(t, derivedKey)
}

// TestDeriveSecret_WithProvidedChallengeNotEmpty tests DeriveSecret with non-empty challenge.
func TestDeriveSecret_WithProvidedChallengeNotEmpty(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	authConfig := &AuthenticationConfig{
		RelyingPartyID: "test.com",
		CredentialID:   make([]byte, 32),
		Salt:           make([]byte, 32),
		Challenge:      []byte("custom-challenge-12345678901234"), // 32 bytes
	}

	result, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.HMACSecret)
}

// TestVerifyHMACSecret_EmptySecret tests VerifyHMACSecret with empty secret.
func TestVerifyHMACSecret_EmptySecret(t *testing.T) {
	err := VerifyHMACSecret([]byte{})
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidHMACSecret, err)
}

// TestVerifyHMACSecret_64ByteSecret tests VerifyHMACSecret with 64-byte secret.
func TestVerifyHMACSecret_64ByteSecret(t *testing.T) {
	secret := make([]byte, 64)
	err := VerifyHMACSecret(secret)
	assert.NoError(t, err)
}

// TestVerifyHMACSecret_WrongLength tests VerifyHMACSecret with wrong length.
func TestVerifyHMACSecret_WrongLength(t *testing.T) {
	// Test with 16 bytes (not 32 or 64)
	secret := make([]byte, 16)
	err := VerifyHMACSecret(secret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HMAC secret length")
}

// TestHandler_SelectDevice_WithDevicePath tests selectDevice when DevicePath is configured.
func TestHandler_SelectDevice_WithDevicePath(t *testing.T) {
	config := DefaultConfig
	config.DevicePath = "/dev/hidraw0"

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	assert.NotNil(t, device)
	assert.Equal(t, "/dev/hidraw0", device.Path())
}

// TestHandler_SelectDevice_DevicePathOpenError tests selectDevice error when configured path fails.
func TestHandler_SelectDevice_DevicePathOpenError(t *testing.T) {
	config := DefaultConfig
	config.DevicePath = "/dev/nonexistent"

	enum := NewMockHIDDeviceEnumerator() // Empty - device doesn't exist

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to open configured device")
}

// TestVirtualDeviceRead_ClosedDevice tests reading from a closed virtual device.
func TestVirtualDeviceRead_ClosedDevice(t *testing.T) {
	client := NewMockFIDOClient()

	deviceConfig := &VirtualDeviceConfig{
		FIDOClient: client,
	}

	device, err := NewVirtualFIDO2Device(deviceConfig)
	require.NoError(t, err)

	// Close the device
	err = device.Close()
	require.NoError(t, err)

	// Try to read - should return error
	buf := make([]byte, 64)
	_, err = device.Read(buf)
	assert.Error(t, err)
	assert.Equal(t, ErrVirtualDeviceClosed, err)
}

// TestVirtualDeviceWrite_ClosedDevice tests writing to a closed virtual device.
func TestVirtualDeviceWrite_ClosedDevice(t *testing.T) {
	client := NewMockFIDOClient()

	deviceConfig := &VirtualDeviceConfig{
		FIDOClient: client,
	}

	device, err := NewVirtualFIDO2Device(deviceConfig)
	require.NoError(t, err)

	err = device.Close()
	require.NoError(t, err)

	// Try to write - should return error
	_, err = device.Write([]byte("test"))
	assert.Error(t, err)
	assert.Equal(t, ErrVirtualDeviceClosed, err)
}

// TestVirtualDeviceDoubleClose tests closing a device twice.
func TestVirtualDeviceDoubleClose(t *testing.T) {
	client := NewMockFIDOClient()

	deviceConfig := &VirtualDeviceConfig{
		FIDOClient: client,
	}

	device, err := NewVirtualFIDO2Device(deviceConfig)
	require.NoError(t, err)

	// First close should succeed
	err = device.Close()
	assert.NoError(t, err)

	// Second close should also succeed (idempotent)
	err = device.Close()
	assert.NoError(t, err)
}

// TestCombinedEnumerator_NoEnumerators tests combined enumerator with no underlying enumerators.
func TestCombinedEnumerator_NoEnumerators(t *testing.T) {
	combined := NewCombinedEnumerator()

	devices, err := combined.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Empty(t, devices)
}

// TestCombinedEnumerator_MultipleSources tests combined enumerator with devices from multiple sources.
func TestCombinedEnumerator_MultipleSources(t *testing.T) {
	enum1 := NewMockHIDDeviceEnumerator()
	enum1.AddDevice(NewMockHIDDevice("/dev/hidraw0"))

	enum2 := NewVirtualDeviceEnumerator()
	vDevice, _ := NewVirtualFIDO2Device(&VirtualDeviceConfig{FIDOClient: NewMockFIDOClient()})
	_ = enum2.RegisterDevice(vDevice)

	combined := NewCombinedEnumerator(enum1, enum2)

	devices, err := combined.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 2)
}

// TestVirtualEnumerator_EnumerateWithFilter tests Enumerate with vendor/product filters.
func TestVirtualEnumerator_EnumerateWithFilter(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, _ := NewVirtualFIDO2Device(&VirtualDeviceConfig{FIDOClient: NewMockFIDOClient()})
	_ = enum.RegisterDevice(device)

	// Enumerate with matching vendor ID
	devices, err := enum.Enumerate(VirtualFIDOVendorID, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Enumerate with non-matching vendor ID
	devices, err = enum.Enumerate(0x1234, 0)
	require.NoError(t, err)
	assert.Empty(t, devices)

	// Enumerate with matching product ID
	devices, err = enum.Enumerate(0, VirtualFIDOProductID)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Enumerate with non-matching product ID
	devices, err = enum.Enumerate(0, 0x9999)
	require.NoError(t, err)
	assert.Empty(t, devices)
}

// TestVirtualEnumerator_CloseAll tests closing all devices.
func TestVirtualEnumerator_CloseAll(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device1, _ := NewVirtualFIDO2Device(&VirtualDeviceConfig{FIDOClient: NewMockFIDOClient(), SerialNumber: "001"})
	device2, _ := NewVirtualFIDO2Device(&VirtualDeviceConfig{FIDOClient: NewMockFIDOClient(), SerialNumber: "002"})

	_ = enum.RegisterDevice(device1)
	_ = enum.RegisterDevice(device2)

	assert.Equal(t, 2, enum.DeviceCount())

	err := enum.Close()
	require.NoError(t, err)

	assert.Equal(t, 0, enum.DeviceCount())
}

// TestVirtualEnumerator_OpenNonVirtualPath tests opening a non-virtual path.
func TestVirtualEnumerator_OpenNonVirtualPath(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, _ := NewVirtualFIDO2Device(&VirtualDeviceConfig{FIDOClient: NewMockFIDOClient()})
	_ = enum.RegisterDevice(device)

	// Try to open a path that doesn't exist
	_, err := enum.Open("/dev/hidraw0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestHandler_EnrollKey_CloseDeviceError tests close error handling in EnrollKey.
func TestHandler_EnrollKey_CloseDeviceError(t *testing.T) {
	config := DefaultConfig
	mockDev := &CloseErrorMockDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	// Should still succeed even if close fails
	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// CloseErrorMockDeviceCB is a mock device that returns an error on Close.
type CloseErrorMockDeviceCB struct {
	*MockHIDDevice
	closeCount int
	muCB       sync.Mutex
}

func (d *CloseErrorMockDeviceCB) Close() error {
	d.muCB.Lock()
	defer d.muCB.Unlock()
	d.closeCount++
	return errors.New("close error")
}

// TestHandler_UnlockWithKey_CloseDeviceError tests close error handling in UnlockWithKey.
func TestHandler_UnlockWithKey_CloseDeviceError(t *testing.T) {
	config := DefaultConfig
	mockDev := &CloseErrorMockDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	// Should still succeed even if close fails
	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	assert.NotNil(t, derivedKey)
}

// TestReadResponseSync_ContinuationReadError tests error when reading continuation packet fails.
func TestReadResponseSync_ContinuationReadError(t *testing.T) {
	config := DefaultConfig
	mockDev := &ContinuationReadErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	_, err := NewCTAPHIDDevice(mockDev, &config)
	// The init should fail because it requires multiple packets
	assert.Error(t, err)
}

// ContinuationReadErrorDeviceCB fails on continuation packet reads.
type ContinuationReadErrorDeviceCB struct {
	*MockHIDDevice
	readCount int
}

func (d *ContinuationReadErrorDeviceCB) Write(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Generate an init response that requires continuation packets
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	// Indicate large payload that would need continuation
	binary.BigEndian.PutUint16(response[5:7], 100)
	d.readBuf.Write(response)

	return len(data), nil
}

func (d *ContinuationReadErrorDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.readCount++
	if d.readCount > 1 {
		// Fail on continuation packet read
		return 0, errors.New("read error")
	}

	return d.readBuf.Read(data)
}

// TestLoggerPrintf tests the Printf method via handler logger.
func TestLoggerPrintf(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	var buf bytes.Buffer
	logger := &testLoggerCB{buf: &buf}

	handler, err := NewHandlerWithLogger(&config, enum, logger)
	require.NoError(t, err)
	assert.NotNil(t, handler)
}

// testLoggerCB is a simple test logger.
type testLoggerCB struct {
	buf *bytes.Buffer
}

func (l *testLoggerCB) Printf(format string, v ...interface{}) {
	fmt.Fprintf(l.buf, format, v...)
}

// TestNewHandlerWithLogger_NilLoggerParam tests handler creation with nil logger.
func TestNewHandlerWithLogger_NilLoggerParam(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandlerWithLogger(&config, enum, nil)
	require.NoError(t, err)
	assert.NotNil(t, handler)
}

// TestNewHandlerWithLogger_EmptyConfigDefaults tests handler creation with empty config using defaults.
func TestNewHandlerWithLogger_EmptyConfigDefaults(t *testing.T) {
	config := Config{} // Empty config should get defaults
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandlerWithLogger(&config, enum, nil)
	require.NoError(t, err)
	assert.NotNil(t, handler)
	// Verify defaults were applied
	assert.Equal(t, DefaultTimeout, config.Timeout)
}

// TestHandlerClose tests closing the handler.
func TestHandlerClose(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	err = handler.Close()
	assert.NoError(t, err)
}

// TestCombinedEnumerator_OpenFromSecondEnumerator tests Open finding device in second enumerator.
func TestCombinedEnumerator_OpenFromSecondEnumerator(t *testing.T) {
	enum1 := NewMockHIDDeviceEnumerator() // Empty
	enum2 := NewMockHIDDeviceEnumerator()
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum2.AddDevice(mockDev)

	combined := NewCombinedEnumerator(enum1, enum2)

	device, err := combined.Open("/dev/hidraw0")
	require.NoError(t, err)
	assert.Equal(t, "/dev/hidraw0", device.Path())
}

// TestEnrollKey_HMACExtensionWithSalt tests EnrollKey with provided salt.
func TestEnrollKey_HMACExtensionWithSalt(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Salt = make([]byte, 32) // Provide salt

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.Salt)
}

// TestParseAuthDataExtensions_EdgeCases tests edge cases in ParseAuthDataExtensions.
func TestParseAuthDataExtensions_EdgeCases(t *testing.T) {
	// Test with short data
	_, err := ParseAuthDataExtensions(make([]byte, 10))
	assert.Error(t, err)

	// Test with no extensions included (flags bit not set)
	authData := make([]byte, 37)
	authData[32] = 0x00 // No extensions
	result, err := ParseAuthDataExtensions(authData)
	assert.NoError(t, err)
	assert.Nil(t, result)

	// Test with extensions included but no attested credential data
	authData[32] = 0x80 // Extensions included
	result, err = ParseAuthDataExtensions(authData)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

// TestParseAuthDataExtensions_WithInvalidAttestedCredData tests invalid attested credential data.
func TestParseAuthDataExtensions_WithInvalidAttestedCredData(t *testing.T) {
	// Create auth data with attested credential data flag but not enough data
	authData := make([]byte, 40)
	authData[32] = 0xC0 // Extensions + attested credential data flags

	_, err := ParseAuthDataExtensions(authData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid attested credential data")
}

// TestParseAuthDataExtensions_WithInvalidCredIDLength tests invalid credential ID length.
func TestParseAuthDataExtensions_WithInvalidCredIDLength(t *testing.T) {
	// Create auth data with attested credential data but invalid credential ID length
	authData := make([]byte, 56)
	authData[32] = 0xC0 // Extensions + attested credential data flags
	// AAGUID at offset 37 (16 bytes)
	// Credential ID length at offset 53 = 999 (too large)
	authData[53] = 0x03
	authData[54] = 0xE7 // 999 in big endian

	_, err := ParseAuthDataExtensions(authData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credential ID length")
}

// TestGenerateDerivedKey_ValidSecret tests GenerateDerivedKey with valid input.
func TestGenerateDerivedKey_ValidSecret(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	key, err := GenerateDerivedKey(secret)
	require.NoError(t, err)
	assert.Len(t, key, 64)
	assert.NotEqual(t, make([]byte, 64), key)
}

// TestGenerateDerivedKey_InvalidLength tests GenerateDerivedKey with invalid length.
func TestGenerateDerivedKey_InvalidSecretLength(t *testing.T) {
	secret := make([]byte, 16) // Wrong length
	_, err := GenerateDerivedKey(secret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HMAC secret length")
}

// TestGenerateLUKSKey_Alias tests the GenerateLUKSKey alias.
func TestGenerateLUKSKey_AliasFunction(t *testing.T) {
	secret := make([]byte, 32)

	key1, err1 := GenerateDerivedKey(secret)
	key2, err2 := GenerateLUKSKey(secret)

	assert.Equal(t, err1, err2)
	assert.Equal(t, key1, key2)
}

// TestNewHMACSecretExtension_NoSupport tests creating extension on device without hmac-secret.
func TestNewHMACSecretExtension_NoSupport(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoExtensionDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	_, err = NewHMACSecretExtension(auth)
	assert.Error(t, err)
	assert.Equal(t, ErrUnsupportedExtension, err)
}

// TestEnrollCredential_MakeCredentialError tests EnrollCredential when MakeCredential fails.
func TestEnrollCredential_MakeCredentialError(t *testing.T) {
	config := DefaultConfig
	mockDev := &SendCBORErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		failOnCmd:     CmdMakeCredential,
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{ID: "test.com", Name: "Test"},
		User:         User{Name: "test", DisplayName: "Test"},
	}

	_, err = hmacExt.EnrollCredential(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create credential")
}

// TestDeriveSecret_GetAssertionError tests DeriveSecret when GetAssertion fails.
func TestDeriveSecret_GetAssertionError(t *testing.T) {
	config := DefaultConfig
	mockDev := &GetAssertionErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	authConfig := &AuthenticationConfig{
		RelyingPartyID: "test.com",
		CredentialID:   make([]byte, 32),
		Salt:           make([]byte, 32),
	}

	_, err = hmacExt.DeriveSecret(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get assertion")
}

// GetAssertionErrorDeviceCB fails on GetAssertion.
type GetAssertionErrorDeviceCB struct {
	*MockHIDDevice
}

func (d *GetAssertionErrorDeviceCB) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.gaeInitResp(data[7:])
	case CTAPHID_CBOR:
		d.gaeCBORResp(data[7:])
	}

	return len(data), nil
}

func (d *GetAssertionErrorDeviceCB) gaeInitResp(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *GetAssertionErrorDeviceCB) gaeCBORResp(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		info := map[int]interface{}{
			0x01: []string{"FIDO_2_0"},
			0x02: []string{"hmac-secret"},
			0x03: make([]byte, 16),
			0x04: map[string]bool{"up": true},
		}
		encoded, _ := cbor.Marshal(info)
		d.gaeWritePkts(0x12345678, append([]byte{StatusOK}, encoded...))
	case CmdGetAssertion:
		// Return error status
		d.gaeWritePkts(0x12345678, []byte{StatusNoCredentials})
	}
}

func (d *GetAssertionErrorDeviceCB) gaeWritePkts(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	if payloadLen <= HIDPacketSize-7 {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:HIDPacketSize-7])
	d.readBuf.Write(firstPacket)
}

func (d *GetAssertionErrorDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestUnlockWithKey_CTAPInitError tests error when CTAP init fails.
func TestUnlockWithKey_CTAPInitError(t *testing.T) {
	config := DefaultConfig

	mockDev := &CTAPInitFailDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize CTAP device")
}

// CTAPInitFailDeviceCB fails during CTAP initialization.
type CTAPInitFailDeviceCB struct {
	*MockHIDDevice
}

func (d *CTAPInitFailDeviceCB) Write(data []byte) (int, error) {
	// Return an invalid response that will cause CTAP init to fail
	d.mu.Lock()
	defer d.mu.Unlock()

	// Write garbage response
	d.readBuf.Write(make([]byte, HIDPacketSize))
	return len(data), nil
}

func (d *CTAPInitFailDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestUnlockWithKey_HMACSecretNotSupported tests error when device doesn't support hmac-secret.
func TestUnlockWithKey_HMACSecretNotSupported(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoExtensionDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hmac-secret")
}

// TestWaitForDevice_DeviceFoundImmediately tests WaitForDevice when device exists.
func TestWaitForDevice_DeviceFoundImmediately(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	require.NoError(t, err)
	assert.NotNil(t, device)
}

// TestDiscardLoggerPrintf tests the discard logger Printf method.
func TestDiscardLoggerPrintf(t *testing.T) {
	logger := &discardLogger{}
	// Should not panic and should do nothing
	logger.Printf("test %s %d", "arg", 123)
}

// TestSelectDevice_MultipleDevicesFirstMatch tests selecting a matching device
// when multiple devices are available.
func TestSelectDevice_MultipleDevicesFirstMatch(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0x1234}

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev1.vendorID = 0x9999 // No match

	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev2.vendorID = 0x1234 // Match

	mockDev3 := NewMockHIDDevice("/dev/hidraw2")
	mockDev3.vendorID = 0x1234 // Also match

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)
	enum.AddDevice(mockDev3)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	// Should select a matching device (either hidraw1 or hidraw2)
	// Note: map iteration order is non-deterministic, so we can't
	// guarantee which matching device is selected first
	validPaths := []string{"/dev/hidraw1", "/dev/hidraw2"}
	assert.Contains(t, validPaths, device.Path())
}

// TestIsFIDO2Device tests the FIDO2 device detection.
func TestIsFIDO2Device(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Mock device should be detected as FIDO2
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	assert.True(t, handler.isFIDO2Device(mockDev))
}

// TestEnrollKey_CTAPInitError tests error when CTAP init fails during enrollment.
func TestEnrollKey_CTAPInitError(t *testing.T) {
	config := DefaultConfig

	mockDev := &CTAPInitFailDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	_, err = handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize CTAP device")
}

// TestListDevices_EnumerateError tests error when enumeration fails.
func TestListDevices_EnumerateError(t *testing.T) {
	config := DefaultConfig

	enum := &ErrorEnumeratorCB{}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	_, err = handler.ListDevices()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to enumerate devices")
}

// ErrorEnumeratorCB returns an error on Enumerate.
type ErrorEnumeratorCB struct{}

func (e *ErrorEnumeratorCB) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return nil, errors.New("enumeration failed")
}

func (e *ErrorEnumeratorCB) Open(path string) (HIDDevice, error) {
	return nil, errors.New("open failed")
}

// TestSelectDevice_EnumerateError tests error when enumeration fails during select.
func TestSelectDevice_EnumerateError(t *testing.T) {
	config := DefaultConfig

	enum := &ErrorEnumeratorCB{}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to enumerate devices")
}
