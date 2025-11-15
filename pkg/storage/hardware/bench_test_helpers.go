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

//go:build (tpm2 || pkcs11) && !integration

package hardware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// Benchmark-specific mock implementations
// These are simplified versions optimized for benchmarking

// benchMockPKCS11Storage - simplified PKCS11 mock for benchmarks
type benchMockPKCS11Storage struct {
	certs map[string]*x509.Certificate
	mu    sync.RWMutex
}

func newBenchMockPKCS11Storage() *benchMockPKCS11Storage {
	return &benchMockPKCS11Storage{
		certs: make(map[string]*x509.Certificate),
	}
}

func (m *benchMockPKCS11Storage) SaveCert(id string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[id] = cert
	return nil
}

func (m *benchMockPKCS11Storage) GetCert(id string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cert, nil
}

func (m *benchMockPKCS11Storage) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certs, id)
	return nil
}

func (m *benchMockPKCS11Storage) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.certs))
	for id := range m.certs {
		ids = append(ids, id)
	}
	return ids, nil
}

// benchMockTPM2Storage - simplified TPM2 mock for benchmarks
type benchMockTPM2Storage struct {
	nvIndices map[uint32][]byte
	baseIndex uint32
	maxSize   int
	mu        sync.RWMutex
}

func newBenchMockTPM2Storage() *benchMockTPM2Storage {
	return &benchMockTPM2Storage{
		nvIndices: make(map[uint32][]byte),
		baseIndex: 0x01800000,
		maxSize:   8192, // Increased for benchmarking with properly-encoded certificates
	}
}

func (m *benchMockTPM2Storage) SaveCert(id string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if len(pemData) > m.maxSize {
		return ErrCertificateTooLarge
	}

	index := m.baseIndex + uint32(len(id))%0x00400000
	m.nvIndices[index] = pemData
	return nil
}

func (m *benchMockTPM2Storage) GetCert(id string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	index := m.baseIndex + uint32(len(id))%0x00400000
	pemData, ok := m.nvIndices[index]
	if !ok {
		return nil, storage.ErrNotFound
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidCertificate
	}

	return x509.ParseCertificate(block.Bytes)
}

func (m *benchMockTPM2Storage) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	index := m.baseIndex + uint32(len(id))%0x00400000
	delete(m.nvIndices, index)
	return nil
}

func (m *benchMockTPM2Storage) SaveCertChain(id string, chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var pemData []byte
	for _, cert := range chain {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		pemData = append(pemData, pemBlock...)
	}

	if len(pemData) > m.maxSize {
		return ErrCertificateTooLarge
	}

	index := m.baseIndex + uint32(len(id))%0x00400000
	m.nvIndices[index] = pemData
	return nil
}

func (m *benchMockTPM2Storage) GetCertChain(id string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	index := m.baseIndex + uint32(len(id))%0x00400000
	pemData, ok := m.nvIndices[index]
	if !ok {
		return nil, storage.ErrNotFound
	}

	var chain []*x509.Certificate
	remaining := pemData
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		chain = append(chain, cert)
		remaining = rest
	}

	return chain, nil
}

func (m *benchMockTPM2Storage) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.nvIndices))
	for index := range m.nvIndices {
		ids = append(ids, fmt.Sprintf("0x%08x", index))
	}
	return ids, nil
}

// benchMockExternalStorage - simplified external storage mock for benchmarks
type benchMockExternalStorage struct {
	certs map[string]*x509.Certificate
	mu    sync.RWMutex
}

func newBenchMockExternalStorage() *benchMockExternalStorage {
	return &benchMockExternalStorage{
		certs: make(map[string]*x509.Certificate),
	}
}

func (m *benchMockExternalStorage) SaveCert(id string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[id] = cert
	return nil
}

func (m *benchMockExternalStorage) GetCert(id string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cert, nil
}

func (m *benchMockExternalStorage) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certs[id]; !ok {
		return storage.ErrNotFound
	}
	delete(m.certs, id)
	return nil
}

func (m *benchMockExternalStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(chain) > 0 {
		m.certs[id] = chain[0]
	}
	return nil
}

func (m *benchMockExternalStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return []*x509.Certificate{cert}, nil
}

func (m *benchMockExternalStorage) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.certs))
	for id := range m.certs {
		ids = append(ids, id)
	}
	return ids, nil
}

func (m *benchMockExternalStorage) CertExists(id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.certs[id]
	return ok, nil
}

func (m *benchMockExternalStorage) Close() error {
	return nil
}

func (m *benchMockExternalStorage) GetCapacity() (total int, available int, err error) {
	return 0, 0, ErrNotSupported
}

func (m *benchMockExternalStorage) SupportsChains() bool {
	return true
}

func (m *benchMockExternalStorage) IsHardwareBacked() bool {
	return false
}

func (m *benchMockExternalStorage) Compact() error {
	return ErrNotSupported
}

// benchMockHardwareStorage - hardware mock that can simulate capacity errors
type benchMockHardwareStorage struct {
	certs    map[string]*x509.Certificate
	capacity int
	mu       sync.RWMutex
}

func newBenchMockHardwareStorage(capacity int) *benchMockHardwareStorage {
	return &benchMockHardwareStorage{
		certs:    make(map[string]*x509.Certificate),
		capacity: capacity,
	}
}

func (m *benchMockHardwareStorage) SaveCert(id string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.certs) >= m.capacity {
		return ErrTokenFull
	}
	m.certs[id] = cert
	return nil
}

func (m *benchMockHardwareStorage) GetCert(id string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cert, nil
}

func (m *benchMockHardwareStorage) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certs[id]; !ok {
		return storage.ErrNotFound
	}
	delete(m.certs, id)
	return nil
}

func (m *benchMockHardwareStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.certs) >= m.capacity {
		return ErrTokenFull
	}
	if len(chain) > 0 {
		m.certs[id] = chain[0]
	}
	return nil
}

func (m *benchMockHardwareStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return []*x509.Certificate{cert}, nil
}

func (m *benchMockHardwareStorage) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.certs))
	for id := range m.certs {
		ids = append(ids, id)
	}
	return ids, nil
}

func (m *benchMockHardwareStorage) CertExists(id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.certs[id]
	return ok, nil
}

func (m *benchMockHardwareStorage) Close() error {
	return nil
}

func (m *benchMockHardwareStorage) GetCapacity() (total int, available int, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.capacity, m.capacity - len(m.certs), nil
}

func (m *benchMockHardwareStorage) SupportsChains() bool {
	return true
}

func (m *benchMockHardwareStorage) IsHardwareBacked() bool {
	return true
}

func (m *benchMockHardwareStorage) Compact() error {
	return ErrNotSupported
}

// Benchmark helper: generate certificate of specific size
func generateBenchCert(sizeKB int) (*x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Create padding data using base64 encoding to ensure valid UTF-8
	// Base64 encoding increases size by ~4/3, so we generate less random data
	paddingBytes := make([]byte, (sizeKB*1024-500)*3/4)
	rand.Read(paddingBytes)
	paddingStr := base64.StdEncoding.EncodeToString(paddingBytes)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "benchmark-cert",
			Organization:       []string{"Benchmark Org"},
			OrganizationalUnit: []string{paddingStr},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}
