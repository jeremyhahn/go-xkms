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

//go:build gcpkms

package gcpkms

import (
	"context"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// MockKMSClient is a mock implementation of the KMSClient interface for testing.
type MockKMSClient struct {
	CreateCryptoKeyFunc               func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error)
	GetCryptoKeyFunc                  func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error)
	GetCryptoKeyVersionFunc           func(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error)
	ListCryptoKeysFunc                func(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...interface{}) ([]*kmspb.CryptoKey, error)
	AsymmetricSignFunc                func(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error)
	AsymmetricDecryptFunc             func(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error)
	GetPublicKeyFunc                  func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error)
	CreateCryptoKeyVersionFunc        func(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error)
	UpdateCryptoKeyPrimaryVersionFunc func(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest, opts ...interface{}) (*kmspb.CryptoKey, error)
	DestroyCryptoKeyVersionFunc       func(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error)
	EncryptFunc                       func(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error)
	DecryptFunc                       func(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error)
	CreateImportJobFunc               func(ctx context.Context, req *kmspb.CreateImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error)
	GetImportJobFunc                  func(ctx context.Context, req *kmspb.GetImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error)
	ImportCryptoKeyVersionFunc        func(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error)
	CloseFunc                         func() error

	// Internal state for tracking created keys
	keys map[string]*kmspb.CryptoKey
}

// CreateCryptoKey mocks creating a crypto key in GCP KMS.
func (m *MockKMSClient) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
	if m.CreateCryptoKeyFunc != nil {
		return m.CreateCryptoKeyFunc(ctx, req, opts...)
	}

	key := &kmspb.CryptoKey{
		Name:    req.Parent + "/cryptoKeys/" + req.CryptoKeyId,
		Purpose: req.CryptoKey.Purpose,
		Primary: &kmspb.CryptoKeyVersion{
			Name:      req.Parent + "/cryptoKeys/" + req.CryptoKeyId + "/cryptoKeyVersions/1",
			State:     kmspb.CryptoKeyVersion_ENABLED,
			Algorithm: req.CryptoKey.VersionTemplate.Algorithm,
		},
	}

	// Store key in internal map for later retrieval
	if m.keys == nil {
		m.keys = make(map[string]*kmspb.CryptoKey)
	}
	m.keys[key.Name] = key

	return key, nil
}

// GetCryptoKey mocks retrieving a crypto key from GCP KMS.
func (m *MockKMSClient) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
	if m.GetCryptoKeyFunc != nil {
		return m.GetCryptoKeyFunc(ctx, req, opts...)
	}

	// Check if key exists in our internal map
	if m.keys != nil {
		if key, exists := m.keys[req.Name]; exists {
			return key, nil
		}
	}

	// Default fallback for keys not tracked (backward compatibility)
	return &kmspb.CryptoKey{
		Name:    req.Name,
		Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		Primary: &kmspb.CryptoKeyVersion{
			Name:      req.Name + "/cryptoKeyVersions/1",
			State:     kmspb.CryptoKeyVersion_ENABLED,
			Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		},
	}, nil
}

// GetCryptoKeyVersion mocks retrieving a crypto key version from GCP KMS.
func (m *MockKMSClient) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	if m.GetCryptoKeyVersionFunc != nil {
		return m.GetCryptoKeyVersionFunc(ctx, req, opts...)
	}
	return &kmspb.CryptoKeyVersion{
		Name:      req.Name,
		State:     kmspb.CryptoKeyVersion_ENABLED,
		Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
	}, nil
}

// AsymmetricSign mocks signing with GCP KMS.
func (m *MockKMSClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error) {
	if m.AsymmetricSignFunc != nil {
		return m.AsymmetricSignFunc(ctx, req, opts...)
	}
	// Return a mock signature
	signature := make([]byte, 256) // 2048-bit RSA signature
	for i := range signature {
		signature[i] = byte(i % 256)
	}
	return &kmspb.AsymmetricSignResponse{
		Signature: signature,
		SignatureCrc32C: &wrapperspb.Int64Value{
			Value: int64(crc32c(signature)),
		},
	}, nil
}

// GetPublicKey mocks retrieving a public key from GCP KMS.
func (m *MockKMSClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
	if m.GetPublicKeyFunc != nil {
		return m.GetPublicKeyFunc(ctx, req, opts...)
	}

	// Return a real RSA 2048 public key for testing
	rsaPubKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`

	return &kmspb.PublicKey{
		Pem:       rsaPubKeyPEM,
		Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
	}, nil
}

// DestroyCryptoKeyVersion mocks destroying a crypto key version.
func (m *MockKMSClient) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	if m.DestroyCryptoKeyVersionFunc != nil {
		return m.DestroyCryptoKeyVersionFunc(ctx, req, opts...)
	}
	return &kmspb.CryptoKeyVersion{
		Name:  req.Name,
		State: kmspb.CryptoKeyVersion_DESTROY_SCHEDULED,
	}, nil
}

// ListCryptoKeys mocks listing crypto keys in GCP KMS.
func (m *MockKMSClient) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...interface{}) ([]*kmspb.CryptoKey, error) {
	if m.ListCryptoKeysFunc != nil {
		return m.ListCryptoKeysFunc(ctx, req, opts...)
	}
	// Return empty list by default
	return []*kmspb.CryptoKey{}, nil
}

// AsymmetricDecrypt mocks decrypting with GCP KMS.
func (m *MockKMSClient) AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error) {
	if m.AsymmetricDecryptFunc != nil {
		return m.AsymmetricDecryptFunc(ctx, req, opts...)
	}
	// Return mock plaintext
	plaintext := []byte("decrypted plaintext")
	return &kmspb.AsymmetricDecryptResponse{
		Plaintext: plaintext,
		PlaintextCrc32C: &wrapperspb.Int64Value{
			Value: int64(crc32c(plaintext)),
		},
	}, nil
}

// CreateCryptoKeyVersion mocks creating a new crypto key version.
func (m *MockKMSClient) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	if m.CreateCryptoKeyVersionFunc != nil {
		return m.CreateCryptoKeyVersionFunc(ctx, req, opts...)
	}
	return &kmspb.CryptoKeyVersion{
		Name:      req.Parent + "/cryptoKeyVersions/2",
		State:     kmspb.CryptoKeyVersion_ENABLED,
		Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
	}, nil
}

// UpdateCryptoKeyPrimaryVersion mocks updating the primary key version.
func (m *MockKMSClient) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
	if m.UpdateCryptoKeyPrimaryVersionFunc != nil {
		return m.UpdateCryptoKeyPrimaryVersionFunc(ctx, req, opts...)
	}
	return &kmspb.CryptoKey{
		Name:    req.Name,
		Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		Primary: &kmspb.CryptoKeyVersion{
			Name:      req.Name + "/cryptoKeyVersions/" + req.CryptoKeyVersionId,
			State:     kmspb.CryptoKeyVersion_ENABLED,
			Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		},
	}, nil
}

// Encrypt mocks symmetric encryption with GCP KMS.
func (m *MockKMSClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error) {
	if m.EncryptFunc != nil {
		return m.EncryptFunc(ctx, req, opts...)
	}
	// Return mock ciphertext (plaintext reversed for testing)
	ciphertext := make([]byte, len(req.Plaintext))
	for i := range req.Plaintext {
		ciphertext[len(ciphertext)-1-i] = req.Plaintext[i]
	}
	return &kmspb.EncryptResponse{
		Ciphertext: ciphertext,
		CiphertextCrc32C: &wrapperspb.Int64Value{
			Value: int64(crc32c(ciphertext)),
		},
	}, nil
}

// Decrypt mocks symmetric decryption with GCP KMS.
func (m *MockKMSClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error) {
	if m.DecryptFunc != nil {
		return m.DecryptFunc(ctx, req, opts...)
	}
	// Return mock plaintext (ciphertext reversed for testing)
	plaintext := make([]byte, len(req.Ciphertext))
	for i := range req.Ciphertext {
		plaintext[len(plaintext)-1-i] = req.Ciphertext[i]
	}
	return &kmspb.DecryptResponse{
		Plaintext: plaintext,
		PlaintextCrc32C: &wrapperspb.Int64Value{
			Value: int64(crc32c(plaintext)),
		},
	}, nil
}

// Close mocks closing the KMS client.
func (m *MockKMSClient) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// CreateImportJob mocks creating an import job in GCP KMS.
func (m *MockKMSClient) CreateImportJob(ctx context.Context, req *kmspb.CreateImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error) {
	if m.CreateImportJobFunc != nil {
		return m.CreateImportJobFunc(ctx, req, opts...)
	}

	// Return a mock import job with a real RSA 3072 public key for testing
	rsaWrappingKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1234567890abcdefghij
klmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijk
lmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijkl
mnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklm
nopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn
opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmno
pqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop
qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopq
rstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqr
stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrs
tuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrst
uvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12AgMBAAE=
-----END PUBLIC KEY-----`

	importJob := &kmspb.ImportJob{
		Name:            req.Parent + "/importJobs/" + req.ImportJobId,
		ImportMethod:    req.ImportJob.ImportMethod,
		ProtectionLevel: req.ImportJob.ProtectionLevel,
		State:           kmspb.ImportJob_ACTIVE,
		PublicKey: &kmspb.ImportJob_WrappingPublicKey{
			Pem: rsaWrappingKeyPEM,
		},
	}

	return importJob, nil
}

// GetImportJob mocks retrieving an import job from GCP KMS.
func (m *MockKMSClient) GetImportJob(ctx context.Context, req *kmspb.GetImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error) {
	if m.GetImportJobFunc != nil {
		return m.GetImportJobFunc(ctx, req, opts...)
	}

	// Return a mock import job
	rsaWrappingKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1234567890abcdefghij
klmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijk
lmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijkl
mnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklm
nopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn
opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmno
pqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop
qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopq
rstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqr
stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrs
tuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrst
uvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12AgMBAAE=
-----END PUBLIC KEY-----`

	return &kmspb.ImportJob{
		Name:            req.Name,
		ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256,
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
		State:           kmspb.ImportJob_ACTIVE,
		PublicKey: &kmspb.ImportJob_WrappingPublicKey{
			Pem: rsaWrappingKeyPEM,
		},
	}, nil
}

// ImportCryptoKeyVersion mocks importing a crypto key version into GCP KMS.
func (m *MockKMSClient) ImportCryptoKeyVersion(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	if m.ImportCryptoKeyVersionFunc != nil {
		return m.ImportCryptoKeyVersionFunc(ctx, req, opts...)
	}

	// Return a mock imported crypto key version
	return &kmspb.CryptoKeyVersion{
		Name:       req.Parent + "/cryptoKeyVersions/1",
		State:      kmspb.CryptoKeyVersion_ENABLED,
		Algorithm:  req.Algorithm,
		ImportJob:  req.ImportJob,
		ImportTime: nil, // Would be set to current time in production
	}, nil
}
