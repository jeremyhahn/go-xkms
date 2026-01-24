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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// virtualDeviceMu protects the global virtual device enumerator.
var virtualDeviceMu sync.Mutex

// globalNativeVirtualEnumerator is the global native virtual device enumerator for CLI use.
// Uses NativeVirtualDevice which supports hmac-secret extension.
var globalNativeVirtualEnumerator *NativeVirtualDeviceEnumerator

// virtualStorageDir is the directory for virtual device credential storage.
// Can be overridden via FIDO2_VIRTUAL_STORAGE_DIR environment variable.
const defaultVirtualStorageDir = "/tmp/go-keychain-fido2-virtual"

// GetVirtualEnumerator returns a singleton virtual device enumerator
// with a pre-registered virtual device. This is used by the CLI when
// FIDO2_USE_VIRTUAL=true environment variable is set.
// Uses NativeVirtualDevice which supports hmac-secret extension for key derivation.
//
// Credentials are persisted to disk so they survive across CLI invocations.
// The storage location can be customized via FIDO2_VIRTUAL_STORAGE_DIR.
func GetVirtualEnumerator() (HIDDeviceEnumerator, error) {
	virtualDeviceMu.Lock()
	defer virtualDeviceMu.Unlock()

	if globalNativeVirtualEnumerator != nil {
		return globalNativeVirtualEnumerator, nil
	}

	enumerator := NewNativeVirtualDeviceEnumerator()

	// Determine storage directory
	storageDir := os.Getenv("FIDO2_VIRTUAL_STORAGE_DIR")
	if storageDir == "" {
		storageDir = defaultVirtualStorageDir
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("fido2: failed to create virtual device storage directory: %w", err)
	}

	// Create file-based storage for credential persistence
	fileStorage, err := file.New(filepath.Join(storageDir, "credentials"))
	if err != nil {
		return nil, fmt.Errorf("fido2: failed to create file storage: %w", err)
	}

	// Wrap with BackendStorage adapter
	credStorage, err := authenticator.NewBackendStorage(fileStorage, "fido2/virtual/")
	if err != nil {
		return nil, fmt.Errorf("fido2: failed to create credential storage: %w", err)
	}

	// Create NativeVirtualDevice with hmac-secret support for key derivation
	config := &NativeVirtualDeviceConfig{
		SerialNumber:     "VFIDO-CLI-001",
		Manufacturer:     "go-keychain",
		Product:          "VirtualFIDO CLI",
		EnablePIN:        true,
		EnableHMACSecret: true, // Required for EnrollKey/UnlockWithKey
		Storage:          credStorage,
	}

	device, err := NewNativeVirtualDevice(config)
	if err != nil {
		return nil, fmt.Errorf("fido2: failed to create native virtual device: %w", err)
	}

	if err := enumerator.RegisterDevice(device); err != nil {
		return nil, fmt.Errorf("fido2: failed to register native virtual device: %w", err)
	}

	globalNativeVirtualEnumerator = enumerator
	return globalNativeVirtualEnumerator, nil
}

// CreateDefaultVirtualDevice creates a virtual FIDO2 device with
// default attestation credentials. This is useful for testing and
// development without hardware.
func CreateDefaultVirtualDevice() (*VirtualFIDO2Device, error) {
	return CreateVirtualDeviceWithSerial("VFIDO-CLI-001")
}

// CreateVirtualDeviceWithSerial creates a virtual FIDO2 device with
// the specified serial number and default attestation credentials.
func CreateVirtualDeviceWithSerial(serialNumber string) (*VirtualFIDO2Device, error) {
	// Generate attestation credentials
	fidoClient, err := createDefaultFIDOClient()
	if err != nil {
		return nil, fmt.Errorf("fido2: failed to create FIDO client: %w", err)
	}

	config := &VirtualDeviceConfig{
		SerialNumber: serialNumber,
		Manufacturer: "go-keychain",
		Product:      "VirtualFIDO CLI",
		FIDOClient:   fidoClient,
	}

	return NewVirtualFIDO2Device(config)
}

// createDefaultFIDOClient creates a virtual-fido client with
// self-signed attestation credentials for testing.
func createDefaultFIDOClient() (*fido_client.DefaultFIDOClient, error) {
	// Generate P-256 private key for attestation
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation key: %w", err)
	}

	// Generate self-signed attestation certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "go-keychain VirtualFIDO Attestation",
			Organization: []string{"go-keychain"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(25, 0, 0), // 25 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation certificate: %w", err)
	}

	// Generate 32-byte encryption key
	var encryptionKey [32]byte
	if _, err := rand.Read(encryptionKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Wrap ECDSA private key in COSE format
	cosePrivKey := &cose.SupportedCOSEPrivateKey{ECDSA: privKey}

	// Create the virtual FIDO client
	client := fido_client.NewDefaultClient(
		cert,                 // Attestation certificate
		cosePrivKey,          // Attestation private key
		encryptionKey,        // 32-byte encryption key
		true,                 // Enable PIN
		&autoApprover{},      // ClientRequestApprover interface
		&inMemoryDataSaver{}, // ClientDataSaver interface
	)

	return client, nil
}

// autoApprover implements virtual-fido's ClientRequestApprover interface.
// It automatically approves all FIDO2 operations for testing purposes.
type autoApprover struct{}

// ApproveClientAction automatically approves all FIDO2 operations.
func (a *autoApprover) ApproveClientAction(_ fido_client.ClientAction, _ fido_client.ClientActionRequestParams) bool {
	return true
}

// inMemoryDataSaver implements virtual-fido's ClientDataSaver interface.
// It stores FIDO2 credentials in memory for the session.
type inMemoryDataSaver struct {
	mu   sync.Mutex
	data []byte
}

// SaveData saves the FIDO2 client data.
func (s *inMemoryDataSaver) SaveData(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make([]byte, len(data))
	copy(s.data, data)
}

// RetrieveData retrieves the saved FIDO2 client data.
func (s *inMemoryDataSaver) RetrieveData() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return nil
	}
	result := make([]byte, len(s.data))
	copy(result, s.data)
	return result
}

// Passphrase returns the passphrase for encryption.
// Returns empty string since we don't encrypt in-memory data.
func (s *inMemoryDataSaver) Passphrase() string {
	return ""
}
