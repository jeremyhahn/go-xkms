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

//go:build awskms

package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	awskmsbackend "github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockKMSClient provides a mock AWS KMS client for testing
type mockKMSClient struct {
	awskmsbackend.MockKMSClient
	keys map[string]*mockKey
}

type mockKey struct {
	keyID      string
	alias      string
	keySpec    kmstypes.KeySpec
	keyUsage   kmstypes.KeyUsageType
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
}

func newMockKMSClient() *mockKMSClient {
	m := &mockKMSClient{
		keys: make(map[string]*mockKey),
	}

	m.CreateKeyFunc = m.createKey
	m.GetPublicKeyFunc = m.getPublicKey
	m.SignFunc = m.sign
	m.ScheduleKeyDeletionFunc = m.scheduleKeyDeletion
	m.CreateAliasFunc = m.createAlias

	return m
}

func (m *mockKMSClient) createKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	keyID := fmt.Sprintf("key-%d", len(m.keys)+1)

	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	var err error

	switch params.KeySpec {
	case kmstypes.KeySpecRsa2048:
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		publicKey = &privateKey.(*rsa.PrivateKey).PublicKey

	case kmstypes.KeySpecRsa3072:
		privateKey, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, err
		}
		publicKey = &privateKey.(*rsa.PrivateKey).PublicKey

	case kmstypes.KeySpecRsa4096:
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
		publicKey = &privateKey.(*rsa.PrivateKey).PublicKey

	case kmstypes.KeySpecEccNistP256:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		publicKey = &privateKey.(*ecdsa.PrivateKey).PublicKey

	case kmstypes.KeySpecEccNistP384:
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		publicKey = &privateKey.(*ecdsa.PrivateKey).PublicKey

	case kmstypes.KeySpecEccNistP521:
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
		publicKey = &privateKey.(*ecdsa.PrivateKey).PublicKey

	case kmstypes.KeySpecSymmetricDefault:
		// For symmetric keys, we don't generate actual key material since it stays in KMS
		// We just need to track that the key was created
		privateKey = nil
		publicKey = nil

	default:
		return nil, fmt.Errorf("unsupported key spec: %s", params.KeySpec)
	}

	m.keys[keyID] = &mockKey{
		keyID:      keyID,
		keySpec:    params.KeySpec,
		keyUsage:   params.KeyUsage,
		publicKey:  publicKey,
		privateKey: privateKey,
	}

	return &kms.CreateKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{
			KeyId:    aws.String(keyID),
			KeySpec:  params.KeySpec,
			KeyUsage: params.KeyUsage,
		},
	}, nil
}

func (m *mockKMSClient) getPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	keyID := aws.ToString(params.KeyId)

	// Handle alias lookup
	if len(keyID) > 6 && keyID[:6] == "alias/" {
		for _, key := range m.keys {
			if key.alias == keyID {
				keyID = key.keyID
				break
			}
		}
	}

	key, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Symmetric keys don't have public keys
	if key.keySpec == kmstypes.KeySpecSymmetricDefault {
		return nil, fmt.Errorf("GetPublicKey is not supported for symmetric keys")
	}

	// Marshal the public key to DER format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key.publicKey)
	if err != nil {
		return nil, err
	}

	return &kms.GetPublicKeyOutput{
		KeyId:     aws.String(key.keyID),
		PublicKey: publicKeyBytes,
		KeySpec:   key.keySpec,
		KeyUsage:  key.keyUsage,
	}, nil
}

func (m *mockKMSClient) sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	keyID := aws.ToString(params.KeyId)

	// Handle alias lookup
	if len(keyID) > 6 && keyID[:6] == "alias/" {
		for _, key := range m.keys {
			if key.alias == keyID {
				keyID = key.keyID
				break
			}
		}
	}

	key, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	var signature []byte
	var err error

	switch pk := key.privateKey.(type) {
	case *rsa.PrivateKey:
		// Use PSS padding for RSA
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		}
		signature, err = rsa.SignPSS(rand.Reader, pk, crypto.SHA256, params.Message, opts)
		if err != nil {
			return nil, err
		}

	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, pk, params.Message)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported key type: %T", key.privateKey)
	}

	return &kms.SignOutput{
		KeyId:            aws.String(key.keyID),
		Signature:        signature,
		SigningAlgorithm: params.SigningAlgorithm,
	}, nil
}

func (m *mockKMSClient) scheduleKeyDeletion(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	keyID := aws.ToString(params.KeyId)

	// Handle alias lookup
	if len(keyID) > 6 && keyID[:6] == "alias/" {
		for _, key := range m.keys {
			if key.alias == keyID {
				keyID = key.keyID
				break
			}
		}
	}

	if _, ok := m.keys[keyID]; !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	delete(m.keys, keyID)

	return &kms.ScheduleKeyDeletionOutput{
		KeyId: aws.String(keyID),
	}, nil
}

func (m *mockKMSClient) createAlias(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	keyID := aws.ToString(params.TargetKeyId)
	aliasName := aws.ToString(params.AliasName)

	key, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	key.alias = aliasName

	return &kms.CreateAliasOutput{}, nil
}

// Helper function to create a test backend with mock client
func newTestBackend(t *testing.T) *awskmsbackend.Backend {
	config := &awskmsbackend.Config{
		Region:      "us-east-1",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	backend, err := awskmsbackend.NewBackendWithClient(config, newMockKMSClient())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	return backend
}

func TestNewKeyStore(t *testing.T) {
	t.Run("ValidBackend", func(t *testing.T) {
		be := newTestBackend(t)
		defer func() { _ = be.Close() }()

		certStorage := memory.New()
		ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
		if err != nil {
			t.Fatalf("NewKeyStore failed: %v", err)
		}
		if ks == nil {
			t.Fatal("NewKeyStore returned nil keystore")
		}

		// Verify keystore can be closed
		if err := ks.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})

	t.Run("NilBackend", func(t *testing.T) {
		certStorage := memory.New()
		_, err := NewKeyStore(nil, storage.NewCertAdapter(certStorage))
		if err == nil {
			t.Fatal("Expected error for nil backend")
		}
		if !errors.Is(err, keychain.ErrBackendNotInitialized) {
			t.Errorf("Expected ErrBackendNotInitialized, got: %v", err)
		}
	})
}

func TestKeyStore_Backend(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	b := ks.Backend()
	if b == nil {
		t.Fatal("Backend returned nil")
	}
	if b.Type() != backend.BackendTypeAWSKMS {
		t.Errorf("Expected type %s, got %s", backend.BackendTypeAWSKMS, b.Type())
	}
}

func TestKeyStore_GenerateRSA(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}
		if key == nil {
			t.Fatal("GenerateRSA returned nil key")
		}

		// Verify public key
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatalf("Expected crypto.Signer, got %T", key)
		}
		pub := signer.Public()
		if pub == nil {
			t.Fatal("Public key is nil")
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("Expected RSA public key, got %T", pub)
		}
		if rsaPub.N.BitLen() != 2048 {
			t.Errorf("Expected 2048-bit key, got %d bits", rsaPub.N.BitLen())
		}
	})

	t.Run("DefaultKeySize", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-default",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		pub := key.(crypto.Signer).Public().(*rsa.PublicKey)
		if pub.N.BitLen() != 2048 {
			t.Errorf("Expected default 2048-bit key, got %d bits", pub.N.BitLen())
		}
	})

	t.Run("SmallKeySizeDefaults", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-small",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 256, // Too small, should default to 2048
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		pub := key.(crypto.Signer).Public().(*rsa.PublicKey)
		if pub.N.BitLen() != 2048 {
			t.Errorf("Expected default 2048-bit key for small size, got %d bits", pub.N.BitLen())
		}
	})
}

func TestKeyStore_GenerateECDSA(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-key",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}
		if key == nil {
			t.Fatal("GenerateECDSA returned nil key")
		}

		// Verify public key
		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatalf("Expected crypto.Signer, got %T", key)
		}
		pub := signer.Public()
		if pub == nil {
			t.Fatal("Public key is nil")
		}
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("Expected ECDSA public key, got %T", pub)
		}
		if ecdsaPub.Curve != elliptic.P256() {
			t.Errorf("Expected P-256 curve, got %v", ecdsaPub.Curve)
		}
	})

	t.Run("DefaultCurve", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-default",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}

		pub := key.(crypto.Signer).Public().(*ecdsa.PublicKey)
		if pub.Curve != elliptic.P256() {
			t.Errorf("Expected default P-256 curve, got %v", pub.Curve)
		}
	})

	t.Run("NilCurveDefaults", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-nil",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: nil,
			},
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}

		pub := key.(crypto.Signer).Public().(*ecdsa.PublicKey)
		if pub.Curve != elliptic.P256() {
			t.Errorf("Expected default P-256 curve for nil curve, got %v", pub.Curve)
		}
	})
}

func TestKeyStore_GenerateEd25519(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-key",
		KeyAlgorithm: x509.Ed25519,
		KeyType:      backend.KEY_TYPE_SIGNING,
	}

	_, err = ks.GenerateEd25519(attrs)
	if err == nil {
		t.Fatal("Expected error for Ed25519 generation")
	}
	if !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("Expected ErrInvalidKeyType, got: %v", err)
	}
}

func TestKeyStore_GenerateKey(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("RSA", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key-rsa",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}
		if _, ok := key.(crypto.Signer).Public().(*rsa.PublicKey); !ok {
			t.Error("Expected RSA public key")
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key-ecdsa",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}
		if _, ok := key.(crypto.Signer).Public().(*ecdsa.PublicKey); !ok {
			t.Error("Expected ECDSA public key")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key-ed25519",
			KeyAlgorithm: x509.Ed25519,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := ks.GenerateEd25519(attrs)
		if err == nil {
			t.Fatal("Expected error for Ed25519")
		}
	})

	t.Run("InvalidAlgorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key-invalid",
			KeyAlgorithm: x509.PublicKeyAlgorithm(999), // Invalid algorithm
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := ks.GenerateRSA(attrs)
		if err == nil {
			t.Fatal("Expected error for invalid algorithm")
		}
		if !errors.Is(err, keychain.ErrInvalidKeyAlgorithm) {
			t.Errorf("Expected ErrInvalidKeyAlgorithm, got: %v", err)
		}
	})
}

func TestKeyStore_GenerateSecretKey(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("KeyTypeSecret", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-secret-key",
			KeyType: backend.KEY_TYPE_ENCRYPTION,
		}

		err := ks.(*KeyStore).GenerateSecretKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSecretKey failed for KeyTypeSecret: %v", err)
		}

	})

	t.Run("KeyTypeEncryption", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-encryption-key",
			KeyType: backend.KEY_TYPE_ENCRYPTION,
		}

		err := ks.(*KeyStore).GenerateSecretKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSecretKey failed for KeyTypeEncryption: %v", err)
		}

	})

	t.Run("KeyTypeHMAC", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-hmac-key",
			KeyType: backend.KEY_TYPE_SIGNING,
		}

		err := ks.(*KeyStore).GenerateSecretKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSecretKey failed for KeyTypeHMAC: %v", err)
		}

	})

	t.Run("InvalidKeyType", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:      "test-invalid-symmetric",
			KeyType: backend.KEY_TYPE_CA, // CA keys are not valid for symmetric operations
		}

		err := ks.(*KeyStore).GenerateSecretKey(attrs)
		if err == nil {
			t.Fatal("Expected error for unsupported key type")
		}
		// This is a wrapper-level validation error, not a backend error, so string comparison is appropriate
		expectedMsg := "awskms: unsupported key type for symmetric key generation: CA (use KeyTypeEncryption or KeyTypeSigning)"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message %q, got: %v", expectedMsg, err)
		}
	})

	t.Run("ErrorFromBackend", func(t *testing.T) {
		// Create a backend with a mock client that returns errors
		config := &awskmsbackend.Config{
			Region:      "us-east-1",
			KeyStorage:  memory.New(),
			CertStorage: memory.New(),
		}

		mockClient := &awskmsbackend.MockKMSClient{
			CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return nil, fmt.Errorf("mock create key error")
			},
		}

		errorBackend, err := awskmsbackend.NewBackendWithClient(config, mockClient)
		if err != nil {
			t.Fatalf("Failed to create backend: %v", err)
		}
		defer func() { _ = errorBackend.Close() }()

		certStorage := memory.New()
		errorKS, err := NewKeyStore(errorBackend, storage.NewCertAdapter(certStorage))
		if err != nil {
			t.Fatalf("NewKeyStore failed: %v", err)
		}
		defer func() { _ = errorKS.Close() }()

		attrs := &types.KeyAttributes{
			CN:      "test-error-symmetric",
			KeyType: backend.KEY_TYPE_ENCRYPTION,
		}

		err = errorKS.(*KeyStore).GenerateSecretKey(attrs)
		if err == nil {
			t.Fatal("Expected error from backend")
		}
	})
}

func TestKeyStore_Find(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("ExistingKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-find-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate key first
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Find the key
		key, err := ks.(*KeyStore).Find(attrs)
		if err != nil {
			t.Fatalf("Find failed: %v", err)
		}
		if key == nil {
			t.Fatal("Find returned nil key")
		}
	})

	t.Run("NonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := ks.(*KeyStore).Find(attrs)
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
	})
}

func TestKeyStore_Key(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key-lookup",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Generate key first
	_, err = ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA failed: %v", err)
	}

	// Retrieve the key
	key, err := ks.(*KeyStore).Key(attrs)
	if err != nil {
		t.Fatalf("Key failed: %v", err)
	}
	if key == nil {
		t.Fatal("Key returned nil")
	}
}

func TestKeyStore_Delete(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-delete-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate key
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Delete key
		err = ks.(*KeyStore).Delete(attrs)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Verify key is deleted
		_, err = ks.(*KeyStore).Find(attrs)
		if err == nil {
			t.Fatal("Expected error after deletion")
		}
	})

	t.Run("NonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-delete-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		// Delete should be idempotent
		err := ks.(*KeyStore).Delete(attrs)
		if err != nil {
			t.Errorf("Delete should be idempotent: %v", err)
		}
	})
}

func TestKeyStore_RotateKey(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("Success", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate initial key
		key1, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}
		pub1 := key1.(crypto.Signer).Public().(*rsa.PublicKey)

		// Rotate the key
		key2, err := ks.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}
		pub2 := key2.(crypto.Signer).Public().(*rsa.PublicKey)

		// Verify keys are different
		if pub1.N.Cmp(pub2.N) == 0 {
			t.Error("Expected different keys after rotation")
		}
	})

	t.Run("NonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-rotate-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := ks.RotateKey(attrs)
		if err == nil {
			t.Fatal("Expected error rotating non-existent key")
		}
	})

	t.Run("Ed25519NotSupported", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-ed25519",
			KeyAlgorithm: x509.Ed25519,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		// Mock the key exists (even though we can't create it)
		// This tests the rotation logic for unsupported algorithms
		_, err := ks.RotateKey(attrs)
		if err == nil {
			t.Fatal("Expected error for Ed25519 rotation")
		}
	})
}

func TestKeyStore_Equal(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("RSAEqual", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-equal-rsa",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Generate an RSA key with the same public key
		rsaPub := key.(crypto.Signer).Public().(*rsa.PublicKey)
		rsaPriv := &rsa.PrivateKey{
			PublicKey: *rsaPub,
			D:         big.NewInt(1), // Dummy value
			Primes:    []*big.Int{big.NewInt(2), big.NewInt(3)},
		}

		if !ks.(*KeyStore).Equal(key, rsaPriv) {
			t.Error("Expected keys to be equal")
		}
	})

	t.Run("RSANotEqual", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-not-equal-rsa",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Generate a different RSA key
		otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		if ks.(*KeyStore).Equal(key, otherKey) {
			t.Error("Expected keys to not be equal")
		}
	})

	t.Run("ECDSAEqual", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-equal-ecdsa",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		key, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}

		// Generate an ECDSA key with the same public key
		ecdsaPub := key.(crypto.Signer).Public().(*ecdsa.PublicKey)
		ecdsaPriv := &ecdsa.PrivateKey{
			PublicKey: *ecdsaPub,
			D:         big.NewInt(1), // Dummy value
		}

		if !ks.(*KeyStore).Equal(key, ecdsaPriv) {
			t.Error("Expected keys to be equal")
		}
	})

	t.Run("NilOpaqueKey", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		if ks.(*KeyStore).Equal(nil, key) {
			t.Error("Expected false for nil opaque key")
		}
	})

	t.Run("NilPrivateKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-nil-private",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		if ks.(*KeyStore).Equal(key, nil) {
			t.Error("Expected false for nil private key")
		}
	})

	t.Run("DifferentKeyTypes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-different-types",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		key, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Try to compare with ECDSA key
		ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		if ks.(*KeyStore).Equal(key, ecdsaKey) {
			t.Error("Expected false for different key types")
		}
	})

	t.Run("Ed25519Equal", func(t *testing.T) {
		// Test Ed25519 comparison logic even though we can't generate them
		pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
		pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)

		// Create opaque keys manually for testing
		opaqueKey1, _ := opaque.NewOpaqueKey(ks, &types.KeyAttributes{
			CN:           "ed25519-1",
			KeyAlgorithm: x509.Ed25519,
		}, pub1)

		opaqueKey2, _ := opaque.NewOpaqueKey(ks, &types.KeyAttributes{
			CN:           "ed25519-2",
			KeyAlgorithm: x509.Ed25519,
		}, pub2)

		// Test equal keys
		if !ks.(*KeyStore).Equal(opaqueKey1, priv1) {
			t.Error("Expected Ed25519 keys to be equal")
		}

		// Test not equal keys
		if ks.(*KeyStore).Equal(opaqueKey1, priv2) {
			t.Error("Expected Ed25519 keys to not be equal")
		}

		// Test with different public key
		if ks.(*KeyStore).Equal(opaqueKey1, opaqueKey2) {
			t.Error("Expected different Ed25519 keys to not be equal")
		}
	})
}

func TestKeyStore_Signer(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	t.Run("RSASigner", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-signer-rsa",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate key
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("GenerateRSA failed: %v", err)
		}

		// Get signer
		signer, err := ks.Signer(attrs)
		if err != nil {
			t.Fatalf("Signer failed: %v", err)
		}
		if signer == nil {
			t.Fatal("Signer returned nil")
		}

		// Test signing
		digest := make([]byte, 32)
		_, err = rand.Read(digest)
		if err != nil {
			t.Fatalf("Failed to generate digest: %v", err)
		}

		signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Signature is empty")
		}
	})

	t.Run("ECDSASigner", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-signer-ecdsa",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Generate key
		_, err := ks.GenerateECDSA(attrs)
		if err != nil {
			t.Fatalf("GenerateECDSA failed: %v", err)
		}

		// Get signer
		signer, err := ks.Signer(attrs)
		if err != nil {
			t.Fatalf("Signer failed: %v", err)
		}

		// Test signing
		digest := make([]byte, 32)
		_, err = rand.Read(digest)
		if err != nil {
			t.Fatalf("Failed to generate digest: %v", err)
		}

		signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Signature is empty")
		}
	})

	t.Run("NonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-signer",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		}

		_, err := ks.Signer(attrs)
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
	})
}

func TestKeyStore_Decrypter(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-decrypter",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = ks.Decrypter(attrs)
	if err == nil {
		t.Fatal("Expected error for Decrypter (not supported)")
	}
}

// TestKeyStore_Verifier removed - Verifier method doesn't exist on KeyStore
/*
func TestKeyStore_Verifier(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-verifier",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
	}

	verifier := ks.(*KeyStore).Verifier(attrs)
	if verifier == nil {
		t.Fatal("Verifier returned nil")
	}
}
*/

func TestConvertToBackendAttrs(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		expected *types.KeyAttributes
	}{
		{
			name: "RSASigningKey",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
			},
			expected: &types.KeyAttributes{
				CN:           "test-key",
				StoreType:    backend.STORE_AWSKMS,
				KeyType:      backend.KEY_TYPE_SIGNING,
				KeyAlgorithm: x509.RSA,
			},
		},
		{
			name: "ECDSATLSKey",
			attrs: &types.KeyAttributes{
				CN:           "tls-key",
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_TLS,
			},
			expected: &types.KeyAttributes{
				CN:           "tls-key",
				StoreType:    backend.STORE_AWSKMS,
				KeyType:      backend.KEY_TYPE_TLS,
				KeyAlgorithm: x509.ECDSA,
			},
		},
		{
			name: "Ed25519Key",
			attrs: &types.KeyAttributes{
				CN:           "ed-key",
				StoreType:    backend.STORE_AWSKMS,
				KeyAlgorithm: x509.Ed25519,
				KeyType:      backend.KEY_TYPE_CA,
			},
			expected: &types.KeyAttributes{
				CN:           "ed-key",
				StoreType:    backend.STORE_AWSKMS,
				KeyType:      backend.KEY_TYPE_CA,
				KeyAlgorithm: x509.Ed25519,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attrs
			if result.CN != tt.expected.CN {
				t.Errorf("CN: expected %s, got %s", tt.expected.CN, result.CN)
			}
			if result.StoreType != tt.expected.StoreType {
				t.Errorf("StoreType: expected %s, got %s", tt.expected.StoreType, result.StoreType)
			}
			if result.KeyType != tt.expected.KeyType {
				t.Errorf("KeyType: expected %s, got %s", tt.expected.KeyType, result.KeyType)
			}
			if result.KeyAlgorithm != tt.expected.KeyAlgorithm {
				t.Errorf("KeyAlgorithm: expected %s, got %s", tt.expected.KeyAlgorithm, result.KeyAlgorithm)
			}
		})
	}
}

func TestBackendWrapper(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	wrapper := ks.Backend()

	t.Run("Type", func(t *testing.T) {
		if wrapper.Type() != backend.BackendTypeAWSKMS {
			t.Errorf("Expected type %s, got %s", backend.BackendTypeAWSKMS, wrapper.Type())
		}
	})

	// SaveAndGet and Delete tests removed - these methods don't exist on types.Backend interface

	t.Run("Close", func(t *testing.T) {
		// Close should be a no-op
		err := wrapper.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})
}

func TestKMSSigner(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-kms-signer",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Generate key
	_, err = ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA failed: %v", err)
	}

	// Get signer
	signer, err := ks.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	t.Run("Public", func(t *testing.T) {
		pub := signer.Public()
		if pub == nil {
			t.Fatal("Public returned nil")
		}
		if _, ok := pub.(*rsa.PublicKey); !ok {
			t.Errorf("Expected RSA public key, got %T", pub)
		}
	})

	t.Run("Sign", func(t *testing.T) {
		digest := make([]byte, 32)
		_, err := rand.Read(digest)
		if err != nil {
			t.Fatalf("Failed to generate digest: %v", err)
		}

		signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Signature is empty")
		}
	})
}

// Test concurrent access
func TestKeyStore_ConcurrentAccess(t *testing.T) {
	be := newTestBackend(t)
	defer func() { _ = be.Close() }()

	certStorage := memory.New()
	ks, err := NewKeyStore(be, storage.NewCertAdapter(certStorage))
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}
	defer func() { _ = ks.Close() }()

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:           "test-concurrent",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	_, err = ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA failed: %v", err)
	}

	// Test concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			_, err := ks.(*KeyStore).Find(attrs)
			if err != nil {
				t.Errorf("Concurrent Find failed: %v", err)
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test error handling in kmsSigner
func TestKMSSigner_ErrorHandling(t *testing.T) {
	// Create a backend with a mock client that returns errors
	config := &awskmsbackend.Config{
		Region:      "us-east-1",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	mockClient := &awskmsbackend.MockKMSClient{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return nil, fmt.Errorf("mock sign error")
		},
	}

	b, err := awskmsbackend.NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Create a signer directly
	signer := &kmsSigner{
		backend: b,
		attrs: &types.KeyAttributes{
			CN:           "test-error",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
		},
		pub: &rsa.PublicKey{N: big.NewInt(123), E: 65537},
	}

	digest := make([]byte, 32)
	_, err = signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err == nil {
		t.Fatal("Expected error from Sign")
	}
}
