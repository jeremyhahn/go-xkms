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

package file

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// errMockBackend is a typed error for mock backend failures.
var errMockBackend = errors.New("mock backend error")

// mockErrorBackend implements storage.Backend and allows injecting errors
// for specific operations.
type mockErrorBackend struct {
	storage.Backend
	inner       storage.Backend
	existsErr   error
	getErr      error
	putErr      error
	deleteErr   error
	existsVal   *bool // if set, overrides inner.Exists result
	getVal      []byte
	getOverride bool
}

func newMockErrorBackend(inner storage.Backend) *mockErrorBackend {
	return &mockErrorBackend{inner: inner}
}

func (m *mockErrorBackend) Get(_ context.Context, key string) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.getOverride {
		return m.getVal, nil
	}
	return m.inner.Get(context.Background(), key)
}

func (m *mockErrorBackend) Put(_ context.Context, key string, value []byte) error {
	if m.putErr != nil {
		return m.putErr
	}
	return m.inner.Put(context.Background(), key, value)
}

func (m *mockErrorBackend) Delete(_ context.Context, key string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return m.inner.Delete(context.Background(), key)
}

func (m *mockErrorBackend) List(_ context.Context, prefix string) ([]string, error) {
	return m.inner.List(context.Background(), prefix)
}

func (m *mockErrorBackend) Exists(_ context.Context, key string) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	if m.existsVal != nil {
		return *m.existsVal, nil
	}
	return m.inner.Exists(context.Background(), key)
}

func (m *mockErrorBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	return m.inner.Scan(ctx, prefix, fn)
}
func (m *mockErrorBackend) Close() error {
	return m.inner.Close()
}

// generateTestCertificate creates a self-signed test certificate with ECDSA P-256.
func generateTestCertificate(t *testing.T, subject string) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subject,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// generateRSACertificate creates a self-signed test certificate with RSA-2048.
func generateRSACertificate(t *testing.T, subject string) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subject,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create RSA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse RSA certificate: %v", err)
	}

	return cert
}

// generateEd25519Certificate creates a self-signed test certificate with Ed25519.
func generateEd25519Certificate(t *testing.T, subject string) *x509.Certificate {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subject,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatalf("failed to create Ed25519 certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse Ed25519 certificate: %v", err)
	}

	return cert
}

// generateLargeCertificate creates a certificate that exceeds the maximum file storage size.
func generateLargeCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	// Create a large extension to make the certificate exceed 16KB
	largeExtension := make([]byte, pivcert.MaxCertSizeFile+1024)
	for i := range largeExtension {
		largeExtension[i] = byte(i % 256)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "large-cert",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, // Arbitrary OID
				Critical: false,
				Value:    largeExtension,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create large certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse large certificate: %v", err)
	}

	return cert
}

// createValidConfig creates a valid FileStorageConfig with a memory backend.
func createValidConfig() *pivcert.FileStorageConfig {
	return &pivcert.FileStorageConfig{
		Backend:    storage.NewMemory(),
		DEREnabled: true,
		PEMEnabled: true,
	}
}

func TestNewFileBackend(t *testing.T) {
	t.Run("valid config creates backend", func(t *testing.T) {
		config := createValidConfig()

		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		if backend == nil {
			t.Fatal("NewFileBackend() returned nil backend")
		}
		defer func() { _ = backend.Close() }()

		// Verify metadata was initialized
		exists, err := config.Backend.Exists(context.Background(), "metadata/slots.json")
		if err != nil {
			t.Fatalf("failed to check metadata existence: %v", err)
		}
		if !exists {
			t.Error("slots.json metadata was not created")
		}
	})

	t.Run("nil config returns error", func(t *testing.T) {
		backend, err := NewFileBackend(nil)
		if err == nil {
			t.Error("NewFileBackend(nil) expected error, got nil")
			if backend != nil {
				_ = backend.Close()
			}
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidConfig) {
			t.Errorf("NewFileBackend(nil) error = %v, want %v", err, pivcert.ErrInvalidConfig)
		}
	})

	t.Run("nil backend returns error", func(t *testing.T) {
		config := &pivcert.FileStorageConfig{
			Backend:    nil,
			DEREnabled: true,
		}

		backend, err := NewFileBackend(config)
		if err == nil {
			t.Error("NewFileBackend() with nil backend expected error, got nil")
			if backend != nil {
				_ = backend.Close()
			}
			return
		}
		if !errors.Is(err, pivcert.ErrMissingBackend) {
			t.Errorf("NewFileBackend() error = %v, want %v", err, pivcert.ErrMissingBackend)
		}
	})

	t.Run("no format enabled returns error", func(t *testing.T) {
		config := &pivcert.FileStorageConfig{
			Backend:    storage.NewMemory(),
			DEREnabled: false,
			PEMEnabled: false,
		}

		backend, err := NewFileBackend(config)
		if err == nil {
			t.Error("NewFileBackend() with no format enabled expected error, got nil")
			if backend != nil {
				_ = backend.Close()
			}
			return
		}
		if !errors.Is(err, pivcert.ErrNoFormatEnabled) {
			t.Errorf("NewFileBackend() error = %v, want %v", err, pivcert.ErrNoFormatEnabled)
		}
	})

	t.Run("DER only config is valid", func(t *testing.T) {
		config := &pivcert.FileStorageConfig{
			Backend:    storage.NewMemory(),
			DEREnabled: true,
			PEMEnabled: false,
		}

		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()
	})

	t.Run("PEM only config is valid", func(t *testing.T) {
		config := &pivcert.FileStorageConfig{
			Backend:    storage.NewMemory(),
			DEREnabled: false,
			PEMEnabled: true,
		}

		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()
	})

	t.Run("metadata initialization error propagates", func(t *testing.T) {
		mock := newMockErrorBackend(storage.NewMemory())
		mock.existsErr = errMockBackend

		config := &pivcert.FileStorageConfig{
			Backend:    mock,
			DEREnabled: true,
			PEMEnabled: true,
		}

		backend, err := NewFileBackend(config)
		if err == nil {
			t.Error("NewFileBackend() expected error from Exists failure, got nil")
			if backend != nil {
				_ = backend.Close()
			}
			return
		}
		if !errors.Is(err, errMockBackend) {
			t.Errorf("NewFileBackend() error = %v, want %v", err, errMockBackend)
		}
	})
}

func TestFileBackend_Store(t *testing.T) {
	t.Run("store valid certificate", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-store")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Errorf("Store() error = %v", err)
		}

		// Verify DER was stored
		exists, err := config.Backend.Exists(context.Background(), "certificates/9a.der")
		if err != nil {
			t.Fatalf("failed to check DER existence: %v", err)
		}
		if !exists {
			t.Error("DER file was not created")
		}

		// Verify PEM was stored
		exists, err = config.Backend.Exists(context.Background(), "certificates/9a.pem")
		if err != nil {
			t.Fatalf("failed to check PEM existence: %v", err)
		}
		if !exists {
			t.Error("PEM file was not created")
		}
	})

	t.Run("store updates metadata", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-metadata")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Errorf("Store() error = %v", err)
		}

		// Verify metadata contains slot information
		slots, err := backend.List()
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(slots) != 1 {
			t.Errorf("expected 1 slot, got %d", len(slots))
		}
		if len(slots) > 0 && slots[0].Slot != pivcert.PIVSlotAuthentication {
			t.Errorf("expected slot 9a, got %s", slots[0].Slot)
		}
	})

	t.Run("store invalid slot returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-invalid-slot")
		err = backend.Store(pivcert.PIVSlot("invalid"), cert)
		if err == nil {
			t.Error("Store() with invalid slot expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidSlot) {
			t.Errorf("Store() error = %v, want %v", err, pivcert.ErrInvalidSlot)
		}
	})

	t.Run("store nil certificate returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		err = backend.Store(pivcert.PIVSlotAuthentication, nil)
		if err == nil {
			t.Error("Store() with nil certificate expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Errorf("Store() error = %v, want %v", err, pivcert.ErrInvalidCertificate)
		}
	})

	t.Run("store on closed backend returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}

		_ = backend.Close()

		cert := generateTestCertificate(t, "test-closed")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err == nil {
			t.Error("Store() on closed backend expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrStorageClosed) {
			t.Errorf("Store() error = %v, want %v", err, pivcert.ErrStorageClosed)
		}
	})

	t.Run("store large certificate returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateLargeCertificate(t)
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err == nil {
			t.Error("Store() with large certificate expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrCertificateTooLarge) {
			t.Errorf("Store() error = %v, want %v", err, pivcert.ErrCertificateTooLarge)
		}
	})

	t.Run("store DER only", func(t *testing.T) {
		memBackend := storage.NewMemory()
		config := &pivcert.FileStorageConfig{
			Backend:    memBackend,
			DEREnabled: true,
			PEMEnabled: false,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-der-only")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Errorf("Store() error = %v", err)
		}

		// Verify DER was stored
		exists, err := memBackend.Exists(context.Background(), "certificates/9a.der")
		if err != nil {
			t.Fatalf("failed to check DER existence: %v", err)
		}
		if !exists {
			t.Error("DER file was not created")
		}

		// Verify PEM was NOT stored
		exists, err = memBackend.Exists(context.Background(), "certificates/9a.pem")
		if err != nil {
			t.Fatalf("failed to check PEM existence: %v", err)
		}
		if exists {
			t.Error("PEM file should not have been created")
		}
	})

	t.Run("store PEM only", func(t *testing.T) {
		memBackend := storage.NewMemory()
		config := &pivcert.FileStorageConfig{
			Backend:    memBackend,
			DEREnabled: false,
			PEMEnabled: true,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-pem-only")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Errorf("Store() error = %v", err)
		}

		// Verify PEM was stored
		exists, err := memBackend.Exists(context.Background(), "certificates/9a.pem")
		if err != nil {
			t.Fatalf("failed to check PEM existence: %v", err)
		}
		if !exists {
			t.Error("PEM file was not created")
		}

		// Verify DER was NOT stored
		exists, err = memBackend.Exists(context.Background(), "certificates/9a.der")
		if err != nil {
			t.Fatalf("failed to check DER existence: %v", err)
		}
		if exists {
			t.Error("DER file should not have been created")
		}
	})

	t.Run("store DER put error propagates", func(t *testing.T) {
		inner := storage.NewMemory()
		mock := newMockErrorBackend(inner)

		config := &pivcert.FileStorageConfig{
			Backend:    mock,
			DEREnabled: true,
			PEMEnabled: false,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Enable error after initialization
		mock.putErr = errMockBackend

		cert := generateTestCertificate(t, "test-put-err")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err == nil {
			t.Error("Store() expected error from Put failure, got nil")
			return
		}
		if !errors.Is(err, errMockBackend) {
			t.Errorf("Store() error = %v, want %v", err, errMockBackend)
		}
	})
}

func TestFileBackend_Retrieve(t *testing.T) {
	t.Run("retrieve stored certificate", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-retrieve")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		retrieved, err := backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err != nil {
			t.Errorf("Retrieve() error = %v", err)
		}
		if retrieved == nil {
			t.Fatal("Retrieve() returned nil certificate")
		}
		if !bytes.Equal(retrieved.Raw, cert.Raw) {
			t.Error("retrieved certificate does not match stored certificate")
		}
	})

	t.Run("retrieve non-existent certificate returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		_, err = backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Retrieve() non-existent certificate expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrCertificateNotFound) {
			t.Errorf("Retrieve() error = %v, want %v", err, pivcert.ErrCertificateNotFound)
		}
	})

	t.Run("retrieve with invalid slot returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		_, err = backend.Retrieve(pivcert.PIVSlot("invalid"))
		if err == nil {
			t.Error("Retrieve() with invalid slot expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidSlot) {
			t.Errorf("Retrieve() error = %v, want %v", err, pivcert.ErrInvalidSlot)
		}
	})

	t.Run("retrieve on closed backend returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}

		cert := generateTestCertificate(t, "test-closed")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		_ = backend.Close()

		_, err = backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Retrieve() on closed backend expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrStorageClosed) {
			t.Errorf("Retrieve() error = %v, want %v", err, pivcert.ErrStorageClosed)
		}
	})

	t.Run("retrieve from PEM only storage", func(t *testing.T) {
		memBackend := storage.NewMemory()
		config := &pivcert.FileStorageConfig{
			Backend:    memBackend,
			DEREnabled: false,
			PEMEnabled: true,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-pem-retrieve")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		retrieved, err := backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err != nil {
			t.Errorf("Retrieve() error = %v", err)
		}
		if retrieved == nil {
			t.Fatal("Retrieve() returned nil certificate")
		}
		if !bytes.Equal(retrieved.Raw, cert.Raw) {
			t.Error("retrieved certificate does not match stored certificate")
		}
	})

	t.Run("retrieve invalid DER returns error", func(t *testing.T) {
		memBackend := storage.NewMemory()
		config := &pivcert.FileStorageConfig{
			Backend:    memBackend,
			DEREnabled: true,
			PEMEnabled: false,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Store invalid DER data directly
		err = memBackend.Put(context.Background(), "certificates/9a.der", []byte("invalid-der-data"))
		if err != nil {
			t.Fatalf("failed to write invalid DER: %v", err)
		}

		_, err = backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Retrieve() with invalid DER expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Errorf("Retrieve() error = %v, want %v", err, pivcert.ErrInvalidCertificate)
		}
	})

	t.Run("retrieve invalid PEM returns error", func(t *testing.T) {
		memBackend := storage.NewMemory()
		config := &pivcert.FileStorageConfig{
			Backend:    memBackend,
			DEREnabled: false,
			PEMEnabled: true,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Store invalid PEM data directly
		err = memBackend.Put(context.Background(), "certificates/9a.pem", []byte("invalid-pem-data"))
		if err != nil {
			t.Fatalf("failed to write invalid PEM: %v", err)
		}

		_, err = backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Retrieve() with invalid PEM expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidFormat) {
			t.Errorf("Retrieve() error = %v, want %v", err, pivcert.ErrInvalidFormat)
		}
	})

	t.Run("retrieve PEM with wrong block type returns error", func(t *testing.T) {
		memBackend := storage.NewMemory()
		config := &pivcert.FileStorageConfig{
			Backend:    memBackend,
			DEREnabled: false,
			PEMEnabled: true,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Store PEM with wrong block type
		wrongPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("some-data"),
		})
		err = memBackend.Put(context.Background(), "certificates/9a.pem", wrongPEM)
		if err != nil {
			t.Fatalf("failed to write wrong PEM: %v", err)
		}

		_, err = backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Retrieve() with wrong PEM type expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidFormat) {
			t.Errorf("Retrieve() error = %v, want %v", err, pivcert.ErrInvalidFormat)
		}
	})

	t.Run("retrieve PEM with invalid cert bytes returns error", func(t *testing.T) {
		memBackend := storage.NewMemory()
		config := &pivcert.FileStorageConfig{
			Backend:    memBackend,
			DEREnabled: false,
			PEMEnabled: true,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Store PEM with correct type but invalid cert bytes
		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not-valid-der-cert-data"),
		})
		err = memBackend.Put(context.Background(), "certificates/9a.pem", invalidPEM)
		if err != nil {
			t.Fatalf("failed to write invalid PEM cert: %v", err)
		}

		_, err = backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Retrieve() with invalid PEM cert data expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Errorf("Retrieve() error = %v, want %v", err, pivcert.ErrInvalidCertificate)
		}
	})

	t.Run("retrieve PEM fallback non-ErrNotFound error propagates", func(t *testing.T) {
		inner := storage.NewMemory()
		mock := newMockErrorBackend(inner)

		config := &pivcert.FileStorageConfig{
			Backend:    mock,
			DEREnabled: true,
			PEMEnabled: true,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Make all Gets fail with a non-ErrNotFound error
		mock.getErr = errMockBackend

		_, err = backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Retrieve() expected error from Get failure, got nil")
			return
		}
		if !errors.Is(err, errMockBackend) {
			t.Errorf("Retrieve() error = %v, want %v", err, errMockBackend)
		}
	})
}

func TestFileBackend_Delete(t *testing.T) {
	t.Run("delete stored certificate", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-delete")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		err = backend.Delete(pivcert.PIVSlotAuthentication)
		if err != nil {
			t.Errorf("Delete() error = %v", err)
		}

		// Verify certificate was deleted
		_, err = backend.Retrieve(pivcert.PIVSlotAuthentication)
		if !errors.Is(err, pivcert.ErrCertificateNotFound) {
			t.Errorf("expected ErrCertificateNotFound after delete, got %v", err)
		}
	})

	t.Run("delete updates metadata", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-delete-metadata")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		err = backend.Delete(pivcert.PIVSlotAuthentication)
		if err != nil {
			t.Errorf("Delete() error = %v", err)
		}

		// Verify metadata was updated
		slots, err := backend.List()
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(slots) != 0 {
			t.Errorf("expected 0 slots after delete, got %d", len(slots))
		}
	})

	t.Run("delete non-existent certificate returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		err = backend.Delete(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Delete() non-existent certificate expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrCertificateNotFound) {
			t.Errorf("Delete() error = %v, want %v", err, pivcert.ErrCertificateNotFound)
		}
	})

	t.Run("delete with invalid slot returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		err = backend.Delete(pivcert.PIVSlot("invalid"))
		if err == nil {
			t.Error("Delete() with invalid slot expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidSlot) {
			t.Errorf("Delete() error = %v, want %v", err, pivcert.ErrInvalidSlot)
		}
	})

	t.Run("delete on closed backend returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}

		cert := generateTestCertificate(t, "test-closed")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		_ = backend.Close()

		err = backend.Delete(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Delete() on closed backend expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrStorageClosed) {
			t.Errorf("Delete() error = %v, want %v", err, pivcert.ErrStorageClosed)
		}
	})

	t.Run("delete DER backend error propagates", func(t *testing.T) {
		inner := storage.NewMemory()
		mock := newMockErrorBackend(inner)

		config := &pivcert.FileStorageConfig{
			Backend:    mock,
			DEREnabled: true,
			PEMEnabled: true,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Store a cert first (before error injection)
		cert := generateTestCertificate(t, "test-delete-err")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		// Enable delete error
		mock.deleteErr = errMockBackend

		err = backend.Delete(pivcert.PIVSlotAuthentication)
		if err == nil {
			t.Error("Delete() expected error from backend Delete failure, got nil")
			return
		}
		if !errors.Is(err, errMockBackend) {
			t.Errorf("Delete() error = %v, want %v", err, errMockBackend)
		}
	})
}

func TestFileBackend_List(t *testing.T) {
	t.Run("list empty storage", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		slots, err := backend.List()
		if err != nil {
			t.Errorf("List() error = %v", err)
		}
		if len(slots) != 0 {
			t.Errorf("expected 0 slots, got %d", len(slots))
		}
	})

	t.Run("list multiple certificates", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Store certificates in multiple slots
		slots := []pivcert.PIVSlot{
			pivcert.PIVSlotAuthentication,
			pivcert.PIVSlotDigitalSignature,
			pivcert.PIVSlotKeyManagement,
		}

		for i, slot := range slots {
			cert := generateTestCertificate(t, "test-list-"+string(slot))
			err = backend.Store(slot, cert)
			if err != nil {
				t.Fatalf("Store() slot %s error = %v", slot, err)
			}

			// Verify count increases
			result, err := backend.List()
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if len(result) != i+1 {
				t.Errorf("expected %d slots, got %d", i+1, len(result))
			}
		}
	})

	t.Run("list on closed backend returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}

		_ = backend.Close()

		_, err = backend.List()
		if err == nil {
			t.Error("List() on closed backend expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrStorageClosed) {
			t.Errorf("List() error = %v, want %v", err, pivcert.ErrStorageClosed)
		}
	})

	t.Run("list contains correct metadata", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateRSACertificate(t, "test-list-metadata")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		slots, err := backend.List()
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(slots) != 1 {
			t.Fatalf("expected 1 slot, got %d", len(slots))
		}

		slotInfo := slots[0]
		if slotInfo.Slot != pivcert.PIVSlotAuthentication {
			t.Errorf("expected slot 9a, got %s", slotInfo.Slot)
		}
		if slotInfo.Algorithm != "RSA" {
			t.Errorf("expected algorithm RSA, got %s", slotInfo.Algorithm)
		}
		if slotInfo.KeySize != 2048 {
			t.Errorf("expected key size 2048, got %d", slotInfo.KeySize)
		}
		if slotInfo.Fingerprint == "" {
			t.Error("expected non-empty fingerprint")
		}
	})

	t.Run("list with backend Get error propagates", func(t *testing.T) {
		inner := storage.NewMemory()
		mock := newMockErrorBackend(inner)

		config := &pivcert.FileStorageConfig{
			Backend:    mock,
			DEREnabled: true,
			PEMEnabled: true,
		}
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Make Get fail with non-ErrNotFound error
		mock.getErr = errMockBackend

		_, err = backend.List()
		if err == nil {
			t.Error("List() expected error from Get failure, got nil")
			return
		}
		if !errors.Is(err, errMockBackend) {
			t.Errorf("List() error = %v, want %v", err, errMockBackend)
		}
	})
}

func TestFileBackend_Import(t *testing.T) {
	t.Run("import DER format", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-import-der")

		err = backend.Import(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.FormatDER)
		if err != nil {
			t.Errorf("Import() error = %v", err)
		}

		retrieved, err := backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err != nil {
			t.Fatalf("Retrieve() error = %v", err)
		}
		if !bytes.Equal(retrieved.Raw, cert.Raw) {
			t.Error("imported certificate does not match original")
		}
	})

	t.Run("import PEM format", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-import-pem")
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		err = backend.Import(pivcert.PIVSlotAuthentication, pemData, pivcert.FormatPEM)
		if err != nil {
			t.Errorf("Import() error = %v", err)
		}

		retrieved, err := backend.Retrieve(pivcert.PIVSlotAuthentication)
		if err != nil {
			t.Fatalf("Retrieve() error = %v", err)
		}
		if !bytes.Equal(retrieved.Raw, cert.Raw) {
			t.Error("imported certificate does not match original")
		}
	})

	t.Run("import empty data returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		err = backend.Import(pivcert.PIVSlotAuthentication, []byte{}, pivcert.FormatDER)
		if err == nil {
			t.Error("Import() with empty data expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Errorf("Import() error = %v, want %v", err, pivcert.ErrInvalidCertificate)
		}
	})

	t.Run("import invalid DER returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		err = backend.Import(pivcert.PIVSlotAuthentication, []byte("invalid-der"), pivcert.FormatDER)
		if err == nil {
			t.Error("Import() with invalid DER expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Errorf("Import() error = %v, want %v", err, pivcert.ErrInvalidCertificate)
		}
	})

	t.Run("import invalid PEM returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		err = backend.Import(pivcert.PIVSlotAuthentication, []byte("invalid-pem"), pivcert.FormatPEM)
		if err == nil {
			t.Error("Import() with invalid PEM expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidFormat) {
			t.Errorf("Import() error = %v, want %v", err, pivcert.ErrInvalidFormat)
		}
	})

	t.Run("import unknown format returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-import-unknown")
		err = backend.Import(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.CertFormat(99))
		if err == nil {
			t.Error("Import() with unknown format expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidFormat) {
			t.Errorf("Import() error = %v, want %v", err, pivcert.ErrInvalidFormat)
		}
	})

	t.Run("import PEM with invalid cert bytes returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		// Valid PEM block but invalid certificate DER inside
		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not-valid-cert-data"),
		})

		err = backend.Import(pivcert.PIVSlotAuthentication, invalidPEM, pivcert.FormatPEM)
		if err == nil {
			t.Error("Import() with invalid PEM cert expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Errorf("Import() error = %v, want %v", err, pivcert.ErrInvalidCertificate)
		}
	})
}

func TestFileBackend_Export(t *testing.T) {
	t.Run("export DER format", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-export-der")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		data, err := backend.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER)
		if err != nil {
			t.Errorf("Export() error = %v", err)
		}
		if !bytes.Equal(data, cert.Raw) {
			t.Error("exported DER does not match certificate")
		}
	})

	t.Run("export PEM format", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-export-pem")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		data, err := backend.Export(pivcert.PIVSlotAuthentication, pivcert.FormatPEM)
		if err != nil {
			t.Errorf("Export() error = %v", err)
		}

		// Decode PEM and verify
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Error("exported PEM is invalid")
		}
		if !bytes.Equal(block.Bytes, cert.Raw) {
			t.Error("exported PEM content does not match certificate")
		}
	})

	t.Run("export non-existent certificate returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		_, err = backend.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER)
		if err == nil {
			t.Error("Export() non-existent certificate expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrCertificateNotFound) {
			t.Errorf("Export() error = %v, want %v", err, pivcert.ErrCertificateNotFound)
		}
	})

	t.Run("export unknown format returns error", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "test-export-unknown")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		_, err = backend.Export(pivcert.PIVSlotAuthentication, pivcert.CertFormat(99))
		if err == nil {
			t.Error("Export() with unknown format expected error, got nil")
			return
		}
		if !errors.Is(err, pivcert.ErrInvalidFormat) {
			t.Errorf("Export() error = %v, want %v", err, pivcert.ErrInvalidFormat)
		}
	})
}

func TestFileBackend_Type(t *testing.T) {
	config := createValidConfig()
	backend, err := NewFileBackend(config)
	if err != nil {
		t.Fatalf("NewFileBackend() error = %v", err)
	}
	defer func() { _ = backend.Close() }()

	if backend.Type() != pivcert.StorageTypeFile {
		t.Errorf("Type() = %v, want %v", backend.Type(), pivcert.StorageTypeFile)
	}
}

func TestFileBackend_Close(t *testing.T) {
	t.Run("close marks backend as closed", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}

		err = backend.Close()
		if err != nil {
			t.Errorf("Close() error = %v", err)
		}

		// Verify operations fail after close
		cert := generateTestCertificate(t, "test-closed")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if !errors.Is(err, pivcert.ErrStorageClosed) {
			t.Errorf("Store() after Close() error = %v, want %v", err, pivcert.ErrStorageClosed)
		}
	})
}

func TestFileBackend_ConcurrentAccess(t *testing.T) {
	config := createValidConfig()
	backend, err := NewFileBackend(config)
	if err != nil {
		t.Fatalf("NewFileBackend() error = %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Create test certificates for different slots
	slots := []pivcert.PIVSlot{
		pivcert.PIVSlotAuthentication,
		pivcert.PIVSlotDigitalSignature,
		pivcert.PIVSlotKeyManagement,
		pivcert.PIVSlotCardAuthentication,
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(slots)*3)

	// Concurrent stores
	for _, slot := range slots {
		wg.Add(1)
		go func(s pivcert.PIVSlot) {
			defer wg.Done()
			cert := generateTestCertificate(t, "concurrent-"+string(s))
			if err := backend.Store(s, cert); err != nil {
				errChan <- err
			}
		}(slot)
	}

	wg.Wait()

	// Concurrent retrieves
	for _, slot := range slots {
		wg.Add(1)
		go func(s pivcert.PIVSlot) {
			defer wg.Done()
			if _, err := backend.Retrieve(s); err != nil {
				errChan <- err
			}
		}(slot)
	}

	wg.Wait()

	// Concurrent list
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := backend.List(); err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent operation error: %v", err)
	}
}

func TestFileBackend_AllSlots(t *testing.T) {
	config := createValidConfig()
	backend, err := NewFileBackend(config)
	if err != nil {
		t.Fatalf("NewFileBackend() error = %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Test all primary slots
	primarySlots := pivcert.PrimarySlots()
	for _, slot := range primarySlots {
		t.Run("primary_slot_"+string(slot), func(t *testing.T) {
			cert := generateTestCertificate(t, "primary-"+string(slot))
			err := backend.Store(slot, cert)
			if err != nil {
				t.Errorf("Store() error = %v", err)
				return
			}

			retrieved, err := backend.Retrieve(slot)
			if err != nil {
				t.Errorf("Retrieve() error = %v", err)
				return
			}

			if !bytes.Equal(retrieved.Raw, cert.Raw) {
				t.Error("retrieved certificate does not match stored certificate")
			}

			err = backend.Delete(slot)
			if err != nil {
				t.Errorf("Delete() error = %v", err)
			}
		})
	}
}

func TestFileBackend_KeyAlgorithms(t *testing.T) {
	t.Run("ECDSA certificate", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateTestCertificate(t, "ecdsa-cert")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		slots, err := backend.List()
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(slots) != 1 {
			t.Fatalf("expected 1 slot, got %d", len(slots))
		}
		if slots[0].Algorithm != "ECDSA" {
			t.Errorf("expected algorithm ECDSA, got %s", slots[0].Algorithm)
		}
	})

	t.Run("RSA certificate", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateRSACertificate(t, "rsa-cert")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		slots, err := backend.List()
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(slots) != 1 {
			t.Fatalf("expected 1 slot, got %d", len(slots))
		}
		if slots[0].Algorithm != "RSA" {
			t.Errorf("expected algorithm RSA, got %s", slots[0].Algorithm)
		}
		if slots[0].KeySize != 2048 {
			t.Errorf("expected key size 2048, got %d", slots[0].KeySize)
		}
	})

	t.Run("Ed25519 certificate", func(t *testing.T) {
		config := createValidConfig()
		backend, err := NewFileBackend(config)
		if err != nil {
			t.Fatalf("NewFileBackend() error = %v", err)
		}
		defer func() { _ = backend.Close() }()

		cert := generateEd25519Certificate(t, "ed25519-cert")
		err = backend.Store(pivcert.PIVSlotAuthentication, cert)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}

		slots, err := backend.List()
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(slots) != 1 {
			t.Fatalf("expected 1 slot, got %d", len(slots))
		}
		if slots[0].Algorithm != "Ed25519" {
			t.Errorf("expected algorithm Ed25519, got %s", slots[0].Algorithm)
		}
		if slots[0].KeySize != 256 {
			t.Errorf("expected key size 256, got %d", slots[0].KeySize)
		}
	})
}

func TestFileBackend_OverwriteCertificate(t *testing.T) {
	config := createValidConfig()
	backend, err := NewFileBackend(config)
	if err != nil {
		t.Fatalf("NewFileBackend() error = %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Store first certificate
	cert1 := generateTestCertificate(t, "cert-1")
	err = backend.Store(pivcert.PIVSlotAuthentication, cert1)
	if err != nil {
		t.Fatalf("Store() first cert error = %v", err)
	}

	// Store second certificate in same slot
	cert2 := generateTestCertificate(t, "cert-2")
	err = backend.Store(pivcert.PIVSlotAuthentication, cert2)
	if err != nil {
		t.Fatalf("Store() second cert error = %v", err)
	}

	// Retrieve should return second certificate
	retrieved, err := backend.Retrieve(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if !bytes.Equal(retrieved.Raw, cert2.Raw) {
		t.Error("retrieved certificate should be the second one")
	}

	// List should only show one slot
	slots, err := backend.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(slots) != 1 {
		t.Errorf("expected 1 slot, got %d", len(slots))
	}
}

// TestKeyAlgorithmName_DSA verifies that a DSA key returns "DSA".
func TestKeyAlgorithmName_DSA(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.DSA,
	}
	name := keyAlgorithmName(cert)
	if name != "DSA" {
		t.Errorf("keyAlgorithmName() = %q, want %q", name, "DSA")
	}
}

// TestKeyAlgorithmName_Unknown verifies that an unknown algorithm returns "Unknown".
func TestKeyAlgorithmName_Unknown(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(99),
	}
	name := keyAlgorithmName(cert)
	if name != "Unknown" {
		t.Errorf("keyAlgorithmName() = %q, want %q", name, "Unknown")
	}
}

// TestKeySize_UnknownAlgorithm verifies that an unknown key type returns 0
// when the algorithm is not Ed25519.
func TestKeySize_UnknownAlgorithm(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(99),
		PublicKey:          "not-a-real-key", // string has no Size() or Params() method
	}
	size := keySize(cert)
	if size != 0 {
		t.Errorf("keySize() = %d, want 0", size)
	}
}

// TestKeySize_Ed25519 verifies that an Ed25519 key returns 256 bits.
func TestKeySize_Ed25519(t *testing.T) {
	cert := generateEd25519Certificate(t, "ed25519-keysize")
	size := keySize(cert)
	if size != 256 {
		t.Errorf("keySize() = %d, want 256", size)
	}
}

// TestKeySize_RSA verifies that an RSA-2048 key returns 2048 bits via Size()*8.
func TestKeySize_RSA(t *testing.T) {
	cert := generateRSACertificate(t, "rsa-keysize")
	size := keySize(cert)
	if size != 2048 {
		t.Errorf("keySize() = %d, want 2048", size)
	}
}

// mockParamsKey implements the interface { Params() interface{ BitSize() int } }
// to test the Params()-based key size detection branch in keySize().
type mockParamsKey struct {
	bitSize int
}

type mockParams struct {
	bits int
}

func (p *mockParams) BitSize() int {
	return p.bits
}

func (k *mockParamsKey) Params() interface{ BitSize() int } {
	if k.bitSize == 0 {
		return nil
	}
	return &mockParams{bits: k.bitSize}
}

// TestKeySize_ECDSA verifies that standard library ECDSA keys fall through
// to the default branch (Params() method doesn't match the expected interface).
func TestKeySize_ECDSA(t *testing.T) {
	cert := generateTestCertificate(t, "ecdsa-keysize")
	size := keySize(cert)
	// Standard library ECDSA keys don't satisfy the Params() interface
	// (BitSize is a field, not a method), so they fall through to default.
	if size != 0 {
		t.Errorf("keySize() = %d, want 0 for standard ECDSA key", size)
	}
}

// TestKeySize_MockParamsKey verifies that a key satisfying the Params() interface
// with a BitSize() method returns the correct key size.
func TestKeySize_MockParamsKey(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          &mockParamsKey{bitSize: 384},
	}
	size := keySize(cert)
	if size != 384 {
		t.Errorf("keySize() = %d, want 384", size)
	}
}

// TestKeySize_MockParamsKeyNilParams verifies that a key whose Params() returns
// nil results in key size 0.
func TestKeySize_MockParamsKeyNilParams(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          &mockParamsKey{bitSize: 0}, // Params() returns nil
	}
	size := keySize(cert)
	if size != 0 {
		t.Errorf("keySize() = %d, want 0", size)
	}
}

// TestLoadMetadata_CorruptedJSON verifies that corrupted JSON in the metadata
// file returns an error.
func TestLoadMetadata_CorruptedJSON(t *testing.T) {
	memBackend := storage.NewMemory()
	config := &pivcert.FileStorageConfig{
		Backend:    memBackend,
		DEREnabled: true,
		PEMEnabled: true,
	}
	backend, err := NewFileBackend(config)
	if err != nil {
		t.Fatalf("NewFileBackend() error = %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Corrupt the metadata file
	err = memBackend.Put(context.Background(), "metadata/slots.json", []byte("{invalid json"))
	if err != nil {
		t.Fatalf("failed to corrupt metadata: %v", err)
	}

	// Try to list - should fail when loading metadata
	_, err = backend.List()
	if err == nil {
		t.Error("List() with corrupted metadata expected error, got nil")
	}
}

// TestLoadMetadata_NilSlotsMap verifies that loadMetadata initializes a nil
// Slots map to an empty map.
func TestLoadMetadata_NilSlotsMap(t *testing.T) {
	memBackend := storage.NewMemory()
	config := &pivcert.FileStorageConfig{
		Backend:    memBackend,
		DEREnabled: true,
		PEMEnabled: true,
	}
	backend, err := NewFileBackend(config)
	if err != nil {
		t.Fatalf("NewFileBackend() error = %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Write metadata with null slots field
	err = memBackend.Put(context.Background(), "metadata/slots.json", []byte(`{"version":"1.0","slots":null}`))
	if err != nil {
		t.Fatalf("failed to write metadata with null slots: %v", err)
	}

	// List should still work and return empty
	slots, err := backend.List()
	if err != nil {
		t.Fatalf("List() with null slots error = %v", err)
	}
	if len(slots) != 0 {
		t.Errorf("expected 0 slots, got %d", len(slots))
	}
}

// TestEnsureMetadataInitialized_PutError verifies that a Put error during
// metadata initialization is propagated.
func TestEnsureMetadataInitialized_PutError(t *testing.T) {
	inner := storage.NewMemory()
	mock := newMockErrorBackend(inner)
	// Make Put fail (metadata initialization calls Put)
	mock.putErr = errMockBackend

	config := &pivcert.FileStorageConfig{
		Backend:    mock,
		DEREnabled: true,
		PEMEnabled: true,
	}

	_, err := NewFileBackend(config)
	if err == nil {
		t.Error("NewFileBackend() expected error from Put failure, got nil")
		return
	}
	if !errors.Is(err, errMockBackend) {
		t.Errorf("NewFileBackend() error = %v, want %v", err, errMockBackend)
	}
}

// TestRemoveMetadata_LoadError verifies that removeMetadata propagates
// a loadMetadata error.
func TestRemoveMetadata_LoadError(t *testing.T) {
	inner := storage.NewMemory()
	mock := newMockErrorBackend(inner)

	config := &pivcert.FileStorageConfig{
		Backend:    mock,
		DEREnabled: true,
		PEMEnabled: true,
	}
	backend, err := NewFileBackend(config)
	if err != nil {
		t.Fatalf("NewFileBackend() error = %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Store a cert
	cert := generateTestCertificate(t, "test-rm-meta-err")
	err = backend.Store(pivcert.PIVSlotAuthentication, cert)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Now inject metadata load error on Get
	mock.getErr = errMockBackend

	// Delete will try to removeMetadata which calls loadMetadata
	err = backend.Delete(pivcert.PIVSlotAuthentication)
	if err == nil {
		t.Error("Delete() expected error from metadata load failure, got nil")
		return
	}
	if !errors.Is(err, errMockBackend) {
		t.Errorf("Delete() error = %v, want %v", err, errMockBackend)
	}
}

// TestUpdateMetadata_LoadError verifies that updateMetadata propagates
// a loadMetadata error.
func TestUpdateMetadata_LoadError(t *testing.T) {
	inner := storage.NewMemory()
	mock := newMockErrorBackend(inner)

	config := &pivcert.FileStorageConfig{
		Backend:    mock,
		DEREnabled: true,
		PEMEnabled: true,
	}
	backend, err := NewFileBackend(config)
	if err != nil {
		t.Fatalf("NewFileBackend() error = %v", err)
	}
	defer func() { _ = backend.Close() }()

	// Inject error so loadMetadata fails during Store
	mock.getErr = errMockBackend

	cert := generateTestCertificate(t, "test-update-meta-err")
	err = backend.Store(pivcert.PIVSlotAuthentication, cert)
	if err == nil {
		t.Error("Store() expected error from metadata load failure, got nil")
		return
	}
	if !errors.Is(err, errMockBackend) {
		t.Errorf("Store() error = %v, want %v", err, errMockBackend)
	}
}
