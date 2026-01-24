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

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend"
)

// mockTPM implements TPMInterface for testing.
type mockTPM struct {
	generateErr error
	signErr     error
	closeErr    error
	closed      bool
}

func (m *mockTPM) GenerateECDSAKey(curve elliptic.Curve) (crypto.PrivateKey, error) {
	if m.generateErr != nil {
		return nil, m.generateErr
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func (m *mockTPM) Sign(privateKey crypto.PrivateKey, digest []byte) ([]byte, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}
	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key type")
	}
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest)
	if err != nil {
		return nil, err
	}
	// Return fixed-size signature
	keySize := (ecKey.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, keySize*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[keySize*2-len(sBytes):], sBytes)
	return sig, nil
}

func (m *mockTPM) Close() error {
	m.closed = true
	return m.closeErr
}

func TestNewTPM2KeyBackend(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		_, err := NewTPM2KeyBackend(nil)
		if err != keybackend.ErrInvalidKeyHandle {
			t.Errorf("expected ErrInvalidKeyHandle, got %v", err)
		}
	})

	t.Run("valid config with mock TPM", func(t *testing.T) {
		backend, err := NewTPM2KeyBackend(&TPM2Config{
			DevicePath: "/dev/tpmrm0",
			TPM:        &mockTPM{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if backend == nil {
			t.Fatal("expected non-nil backend")
		}
		if backend.devicePath != "/dev/tpmrm0" {
			t.Errorf("expected device path /dev/tpmrm0, got %s", backend.devicePath)
		}
	})

	t.Run("valid config without TPM", func(t *testing.T) {
		backend, err := NewTPM2KeyBackend(&TPM2Config{
			DevicePath: "/dev/tpmrm0",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if backend == nil {
			t.Fatal("expected non-nil backend")
		}
	})
}

func TestTPM2KeyBackend_Type(t *testing.T) {
	backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
	if backend.Type() != keybackend.BackendTypeTPM2 {
		t.Errorf("expected type %s, got %s", keybackend.BackendTypeTPM2, backend.Type())
	}
}

func TestTPM2KeyBackend_Capabilities(t *testing.T) {
	backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
	caps := backend.Capabilities()

	if caps.SupportsExport {
		t.Error("TPM backend should not support export")
	}
	if caps.SupportsImport {
		t.Error("TPM backend should not support import")
	}
	if !caps.SupportsAttestation {
		t.Error("TPM backend should support attestation")
	}
	if !caps.HardwareBacked {
		t.Error("TPM backend should be hardware backed")
	}
	if len(caps.SupportedAlgorithms) < 2 {
		t.Error("TPM backend should support at least ES256 and ES384")
	}
}

func TestTPM2KeyBackend_GenerateCredentialKey(t *testing.T) {
	t.Run("ES256 key generation", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		credentialID := []byte("test-credential-id")

		handle, publicKey, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if handle == nil {
			t.Fatal("expected non-nil handle")
		}
		if len(publicKey) == 0 {
			t.Fatal("expected non-empty public key")
		}
		if handle.Algorithm() != COSEAlgES256 {
			t.Errorf("expected algorithm %d, got %d", COSEAlgES256, handle.Algorithm())
		}
		if string(handle.CredentialID()) != string(credentialID) {
			t.Errorf("credential ID mismatch")
		}
	})

	t.Run("ES384 key generation", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		credentialID := []byte("test-credential-id-384")

		handle, publicKey, err := backend.GenerateCredentialKey(COSEAlgES384, credentialID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if handle == nil {
			t.Fatal("expected non-nil handle")
		}
		if len(publicKey) == 0 {
			t.Fatal("expected non-empty public key")
		}
		if handle.Algorithm() != COSEAlgES384 {
			t.Errorf("expected algorithm %d, got %d", COSEAlgES384, handle.Algorithm())
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		_, _, err := backend.GenerateCredentialKey(-999, []byte("cred"))
		if err != keybackend.ErrUnsupportedAlgorithm {
			t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
		}
	})

	t.Run("empty credential ID", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		_, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte{})
		if err != keybackend.ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("nil TPM", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{DevicePath: "/dev/tpmrm0"})
		_, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))
		if err != keybackend.ErrKeyGenerationFailed {
			t.Errorf("expected ErrKeyGenerationFailed, got %v", err)
		}
	})

	t.Run("TPM generation error", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{
			TPM: &mockTPM{generateErr: errors.New("tpm error")},
		})
		_, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))
		if err != keybackend.ErrKeyGenerationFailed {
			t.Errorf("expected ErrKeyGenerationFailed, got %v", err)
		}
	})

	t.Run("closed backend", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		_ = backend.Close()
		_, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))
		if err != keybackend.ErrBackendClosed {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestTPM2KeyBackend_Sign(t *testing.T) {
	t.Run("successful ES256 signing", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}

		data := []byte("test data to sign")
		sig, err := backend.Sign(handle, COSEAlgES256, data)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		if len(sig) == 0 {
			t.Fatal("signature is empty")
		}

		// Verify ASN.1/DER signature
		tpmHandle := handle.(*tpm2KeyHandle)
		ecPubKey := tpmHandle.publicKey.(*ecdsa.PublicKey)
		digest := sha256.Sum256(data)
		if !ecdsa.VerifyASN1(ecPubKey, digest[:], sig) {
			t.Error("ASN.1/DER signature verification failed")
		}
	})

	t.Run("successful ES384 signing", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		handle, _, err := backend.GenerateCredentialKey(COSEAlgES384, []byte("cred"))
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}

		data := []byte("test data to sign")
		sig, err := backend.Sign(handle, COSEAlgES384, data)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		if len(sig) == 0 {
			t.Fatal("signature is empty")
		}

		// Verify ASN.1/DER signature
		tpmHandle := handle.(*tpm2KeyHandle)
		ecPubKey := tpmHandle.publicKey.(*ecdsa.PublicKey)
		digest := sha512.Sum384(data)
		if !ecdsa.VerifyASN1(ecPubKey, digest[:], sig) {
			t.Error("ASN.1/DER signature verification failed")
		}
	})

	t.Run("invalid handle type", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		_, err := backend.Sign(&invalidHandle{}, COSEAlgES256, []byte("data"))
		if err != keybackend.ErrInvalidKeyHandle {
			t.Errorf("expected ErrInvalidKeyHandle, got %v", err)
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		handle, _, _ := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))
		_, err := backend.Sign(handle, -999, []byte("data"))
		if err != keybackend.ErrUnsupportedAlgorithm {
			t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
		}
	})

	t.Run("nil TPM", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{DevicePath: "/dev/tpmrm0"})
		handle := &tpm2KeyHandle{credentialID: []byte("cred"), algorithm: COSEAlgES256}
		backend.keys["6372656"] = handle
		_, err := backend.Sign(handle, COSEAlgES256, []byte("data"))
		if err != keybackend.ErrSigningFailed {
			t.Errorf("expected ErrSigningFailed, got %v", err)
		}
	})

	t.Run("TPM signing error", func(t *testing.T) {
		mockTpm := &mockTPM{signErr: errors.New("sign error")}
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: mockTpm})
		handle, _, _ := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))
		_, err := backend.Sign(handle, COSEAlgES256, []byte("data"))
		if err != keybackend.ErrSigningFailed {
			t.Errorf("expected ErrSigningFailed, got %v", err)
		}
	})

	t.Run("closed backend", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		handle, _, _ := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))
		_ = backend.Close()
		_, err := backend.Sign(handle, COSEAlgES256, []byte("data"))
		if err != keybackend.ErrBackendClosed {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestTPM2KeyBackend_LoadKey(t *testing.T) {
	t.Run("successful load", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		credentialID := []byte("test-cred")
		origHandle, _, _ := backend.GenerateCredentialKey(COSEAlgES256, credentialID)

		loadedHandle, err := backend.LoadKey(credentialID, COSEAlgES256)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if loadedHandle != origHandle {
			t.Error("loaded handle should be same as original")
		}
	})

	t.Run("key not found", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		_, err := backend.LoadKey([]byte("nonexistent"), COSEAlgES256)
		if err != keybackend.ErrKeyNotFound {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		credentialID := []byte("test-cred")
		_, _, _ = backend.GenerateCredentialKey(COSEAlgES256, credentialID)

		_, err := backend.LoadKey(credentialID, COSEAlgES384)
		if err != keybackend.ErrUnsupportedAlgorithm {
			t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
		}
	})

	t.Run("closed backend", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		credentialID := []byte("test-cred")
		_, _, _ = backend.GenerateCredentialKey(COSEAlgES256, credentialID)
		_ = backend.Close()
		_, err := backend.LoadKey(credentialID, COSEAlgES256)
		if err != keybackend.ErrBackendClosed {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestTPM2KeyBackend_DeleteKey(t *testing.T) {
	t.Run("successful delete", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		credentialID := []byte("test-cred")
		handle, _, _ := backend.GenerateCredentialKey(COSEAlgES256, credentialID)

		err := backend.DeleteKey(handle)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = backend.LoadKey(credentialID, COSEAlgES256)
		if err != keybackend.ErrKeyNotFound {
			t.Errorf("expected key to be deleted, got error: %v", err)
		}
	})

	t.Run("invalid handle type", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		err := backend.DeleteKey(&invalidHandle{})
		if err != keybackend.ErrInvalidKeyHandle {
			t.Errorf("expected ErrInvalidKeyHandle, got %v", err)
		}
	})

	t.Run("closed backend", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
		handle, _, _ := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))
		_ = backend.Close()
		err := backend.DeleteKey(handle)
		if err != keybackend.ErrBackendClosed {
			t.Errorf("expected ErrBackendClosed, got %v", err)
		}
	})
}

func TestTPM2KeyBackend_ExportPrivateKey(t *testing.T) {
	backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
	handle, _, _ := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))

	_, err := backend.ExportPrivateKey(handle)
	if err != keybackend.ErrExportNotSupported {
		t.Errorf("expected ErrExportNotSupported, got %v", err)
	}
}

func TestTPM2KeyBackend_ImportPrivateKey(t *testing.T) {
	backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})

	_, err := backend.ImportPrivateKey([]byte("cred"), COSEAlgES256, []byte("pkcs8"))
	if err != keybackend.ErrImportNotSupported {
		t.Errorf("expected ErrImportNotSupported, got %v", err)
	}
}

func TestTPM2KeyBackend_Close(t *testing.T) {
	t.Run("close with TPM", func(t *testing.T) {
		mockTpm := &mockTPM{}
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: mockTpm})
		_, _, _ = backend.GenerateCredentialKey(COSEAlgES256, []byte("cred"))

		err := backend.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !mockTpm.closed {
			t.Error("TPM should be closed")
		}
	})

	t.Run("close without TPM", func(t *testing.T) {
		backend, _ := NewTPM2KeyBackend(&TPM2Config{DevicePath: "/dev/tpmrm0"})
		err := backend.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("close with TPM error", func(t *testing.T) {
		mockTpm := &mockTPM{closeErr: errors.New("close error")}
		backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: mockTpm})
		err := backend.Close()
		if err == nil {
			t.Error("expected error from TPM close")
		}
	})
}

func TestEncodeCOSEEC2Key(t *testing.T) {
	t.Run("encode P-256 key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		encoded, err := encodeCOSEEC2Key(&key.PublicKey, COSEAlgES256)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(encoded) == 0 {
			t.Error("expected non-empty COSE encoding")
		}
	})

	t.Run("encode P-384 key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		encoded, err := encodeCOSEEC2Key(&key.PublicKey, COSEAlgES384)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(encoded) == 0 {
			t.Error("expected non-empty COSE encoding")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, err := encodeCOSEEC2Key(&key.PublicKey, -999)
		if err != keybackend.ErrUnsupportedAlgorithm {
			t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
		}
	})
}

// invalidHandle is a mock handle that doesn't implement tpm2KeyHandle.
type invalidHandle struct{}

func (h *invalidHandle) CredentialID() []byte { return []byte("invalid") }
func (h *invalidHandle) Algorithm() int       { return COSEAlgES256 }

func TestTPM2KeyHandle(t *testing.T) {
	handle := &tpm2KeyHandle{
		credentialID: []byte("test-cred"),
		algorithm:    COSEAlgES256,
	}

	if string(handle.CredentialID()) != "test-cred" {
		t.Errorf("unexpected credential ID: %s", handle.CredentialID())
	}
	if handle.Algorithm() != COSEAlgES256 {
		t.Errorf("unexpected algorithm: %d", handle.Algorithm())
	}
}

func TestTPM2KeyBackend_ConcurrentAccess(t *testing.T) {
	backend, _ := NewTPM2KeyBackend(&TPM2Config{TPM: &mockTPM{}})
	done := make(chan bool)

	// Concurrent key generation
	for i := 0; i < 10; i++ {
		go func(i int) {
			credentialID := make([]byte, 16)
			_, err := rand.Read(credentialID)
			if err != nil {
				t.Errorf("rand.Read failed: %v", err)
			}
			_, _, _ = backend.GenerateCredentialKey(COSEAlgES256, credentialID)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestTPM2Config(t *testing.T) {
	cfg := &TPM2Config{
		DevicePath: "/dev/tpmrm0",
		TPM:        &mockTPM{},
	}

	if cfg.DevicePath != "/dev/tpmrm0" {
		t.Errorf("unexpected device path: %s", cfg.DevicePath)
	}
	if cfg.TPM == nil {
		t.Error("TPM should not be nil")
	}
}
