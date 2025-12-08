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

//go:build integration

package storage_test

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

// tryInitTPM2Simulator attempts to initialize TPM2 storage via simulator.
// Returns nil if TPM2 simulator is not available in the test environment.
func tryInitTPM2Simulator(t *testing.T) hardware.HardwareCertStorage {
	// Check for TPM simulator environment variables
	tpmHost := os.Getenv("TPM2_SIMULATOR_HOST")
	tpmPort := os.Getenv("TPM2_SIMULATOR_PORT")

	var tpmConn transport.TPMCloser
	var err error

	if tpmHost != "" && tpmPort != "" {
		// Connect to remote TPM simulator (Docker environment)
		tpmConn, err = openRemoteTPM2(tpmHost, tpmPort)
		if err != nil {
			t.Logf("Failed to connect to remote TPM2 simulator at %s:%s: %v", tpmHost, tpmPort, err)
			return nil
		}
	} else {
		// Try to use local TPM simulator (e.g., ibmswtpm or socat)
		tpmConn, err = openLocalTPM2()
		if err != nil {
			t.Logf("No TPM2 simulator available: %v", err)
			return nil
		}
	}

	// Create storage with default config
	config := hardware.DefaultTPM2CertStorageConfig()
	hwStorage, err := hardware.NewTPM2CertStorage(tpmConn, config)
	if err != nil {
		t.Logf("Failed to create TPM2 cert storage: %v", err)
		tpmConn.Close()
		return nil
	}

	// Wrap storage with cleanup information
	return &tpm2StorageWrapper{
		storage: hwStorage,
		conn:    tpmConn,
	}
}

// openRemoteTPM2 connects to a remote TPM2 simulator via TCP socket
func openRemoteTPM2(host, port string) (transport.TPMCloser, error) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to TPM simulator at %s: %w", addr, err)
	}

	// Wrap the connection with TPM transport
	return &tcpTPMCloser{
		conn:      conn,
		transport: transport.FromReadWriter(conn),
	}, nil
}

// openLocalTPM2 attempts to open a local TPM2 device
func openLocalTPM2() (transport.TPMCloser, error) {
	// Try common TPM2 device paths
	devPaths := []string{
		"/dev/tpm0",
		"/dev/tpmrm0",
	}

	for _, path := range devPaths {
		if file, err := os.Open(path); err == nil {
			return &fileTPMCloser{
				file:      file,
				transport: transport.FromReadWriter(file),
			}, nil
		}
	}

	return nil, fmt.Errorf("no local TPM2 device found")
}

// tpm2StorageWrapper wraps TPM2 storage with cleanup logic
type tpm2StorageWrapper struct {
	storage hardware.HardwareCertStorage
	conn    transport.TPMCloser
}

func (w *tpm2StorageWrapper) SaveCert(id string, cert *x509.Certificate) error {
	return w.storage.SaveCert(id, cert)
}

func (w *tpm2StorageWrapper) GetCert(id string) (*x509.Certificate, error) {
	return w.storage.GetCert(id)
}

func (w *tpm2StorageWrapper) DeleteCert(id string) error {
	return w.storage.DeleteCert(id)
}

func (w *tpm2StorageWrapper) CertExists(id string) (bool, error) {
	return w.storage.CertExists(id)
}

func (w *tpm2StorageWrapper) ListCerts() ([]string, error) {
	return w.storage.ListCerts()
}

func (w *tpm2StorageWrapper) SaveCertChain(id string, chain []*x509.Certificate) error {
	return w.storage.SaveCertChain(id, chain)
}

func (w *tpm2StorageWrapper) GetCertChain(id string) ([]*x509.Certificate, error) {
	return w.storage.GetCertChain(id)
}

func (w *tpm2StorageWrapper) GetCapacity() (total int, available int, err error) {
	return w.storage.GetCapacity()
}

func (w *tpm2StorageWrapper) SupportsChains() bool {
	return w.storage.SupportsChains()
}

func (w *tpm2StorageWrapper) IsHardwareBacked() bool {
	return w.storage.IsHardwareBacked()
}

func (w *tpm2StorageWrapper) Compact() error {
	return w.storage.Compact()
}

func (w *tpm2StorageWrapper) Close() error {
	// Close the storage
	_ = w.storage.Close()

	// Close the connection
	return w.conn.Close()
}

// tcpTPMCloser wraps a TCP connection for TPM2 communication
type tcpTPMCloser struct {
	conn      net.Conn
	transport transport.TPM
}

func (t *tcpTPMCloser) Send(input []byte) ([]byte, error) {
	return t.transport.Send(input)
}

func (t *tcpTPMCloser) Close() error {
	return t.conn.Close()
}

// fileTPMCloser wraps a file descriptor for TPM2 communication
type fileTPMCloser struct {
	file      *os.File
	transport transport.TPM
}

func (f *fileTPMCloser) Send(input []byte) ([]byte, error) {
	return f.transport.Send(input)
}

func (f *fileTPMCloser) Close() error {
	return f.file.Close()
}
