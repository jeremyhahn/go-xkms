// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package kms_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
)

// =============================================================================
// Error type tests
// =============================================================================

func TestError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *kms.Error
		wantSub string
	}{
		{
			name: "code and message only",
			err: &kms.Error{
				Code:    kms.ErrorCodeNotFound,
				Message: "resource not found",
			},
			wantSub: "NOT_FOUND: resource not found",
		},
		{
			name: "with cause",
			err: &kms.Error{
				Code:    kms.ErrorCodeInternal,
				Message: "internal error",
				Cause:   errors.New("db error"),
			},
			wantSub: "db error",
		},
		{
			name: "with context key-value",
			err: &kms.Error{
				Code:    kms.ErrorCodeKeyNotFound,
				Message: "key not found",
				Context: map[string]interface{}{"key_id": "abc"},
			},
			wantSub: "key_id=abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if len(msg) == 0 {
				t.Fatal("expected non-empty error message")
			}
			if tc.wantSub != "" {
				found := false
				for i := 0; i <= len(msg)-len(tc.wantSub); i++ {
					if msg[i:i+len(tc.wantSub)] == tc.wantSub {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error message to contain %q, got %q", tc.wantSub, msg)
				}
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := &kms.Error{
		Code:    kms.ErrorCodeInternal,
		Message: "internal error",
		Cause:   cause,
	}
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the wrapped cause")
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestError_Is(t *testing.T) {
	e1 := &kms.Error{Code: kms.ErrorCodeNotFound, Message: "not found"}
	e2 := &kms.Error{Code: kms.ErrorCodeNotFound, Message: "different message"}
	e3 := &kms.Error{Code: kms.ErrorCodeInternal, Message: "internal"}

	if !errors.Is(e1, e2) {
		t.Error("errors with same code should match via Is")
	}
	if errors.Is(e1, e3) {
		t.Error("errors with different codes should not match via Is")
	}
}

func TestError_WithCause(t *testing.T) {
	base := &kms.Error{
		Code:    kms.ErrorCodeInternal,
		Message: "internal error",
		Context: map[string]interface{}{"op": "test"},
	}
	cause := errors.New("db failure")
	derived := base.WithCause(cause)

	if derived.Code != base.Code {
		t.Errorf("WithCause should preserve code: got %v", derived.Code)
	}
	if derived.Message != base.Message {
		t.Errorf("WithCause should preserve message: got %v", derived.Message)
	}
	if derived.Cause != cause {
		t.Error("WithCause should set the new cause")
	}
	// Original should be unmodified.
	if base.Cause != nil {
		t.Error("WithCause should not mutate the original error")
	}
	// Context should be copied.
	if derived.Context["op"] != "test" {
		t.Error("WithCause should copy context from original")
	}
}

func TestError_WithContext(t *testing.T) {
	base := &kms.Error{
		Code:    kms.ErrorCodeKeyNotFound,
		Message: "key not found",
	}
	derived := base.WithContext("key_id", "k-123")

	if derived.Context["key_id"] != "k-123" {
		t.Errorf("WithContext should add the key: got %v", derived.Context["key_id"])
	}
	if base.Context != nil {
		t.Error("WithContext should not mutate the original error")
	}
	// Chain multiple WithContext calls.
	derived2 := derived.WithContext("tenant", "t-abc")
	if derived2.Context["key_id"] != "k-123" {
		t.Error("chained WithContext should preserve previous context")
	}
	if derived2.Context["tenant"] != "t-abc" {
		t.Error("chained WithContext should add the new key")
	}
}

func TestNewError(t *testing.T) {
	err := kms.NewError(kms.ErrorCodeInvalidInput, "bad input")
	if err.Code != kms.ErrorCodeInvalidInput {
		t.Errorf("NewError: expected code %v, got %v", kms.ErrorCodeInvalidInput, err.Code)
	}
	if err.Message != "bad input" {
		t.Errorf("NewError: expected message %q, got %q", "bad input", err.Message)
	}
}

func TestPredefinedErrors(t *testing.T) {
	tests := []struct {
		name string
		err  *kms.Error
		code kms.ErrorCode
	}{
		{"ErrNotFound", kms.ErrNotFound, kms.ErrorCodeNotFound},
		{"ErrInvalidInput", kms.ErrInvalidInput, kms.ErrorCodeInvalidInput},
		{"ErrInternal", kms.ErrInternal, kms.ErrorCodeInternal},
		{"ErrKeyNotFound", kms.ErrKeyNotFound, kms.ErrorCodeKeyNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Code != tc.code {
				t.Errorf("expected code %v, got %v", tc.code, tc.err.Code)
			}
			if tc.err.Error() == "" {
				t.Error("predefined error should return non-empty message")
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"not-found error", kms.ErrNotFound, true},
		{"key-not-found error", kms.ErrKeyNotFound, true},
		{"internal error", kms.ErrInternal, false},
		{"wrapped not-found", kms.ErrNotFound.WithCause(errors.New("db")), true},
		{"string not_found", errors.New("not_found: key missing"), true},
		{"unrelated error", errors.New("something else"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := kms.IsNotFound(tc.err)
			if got != tc.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsKeyNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"key-not-found error", kms.ErrKeyNotFound, true},
		{"not-found error (not key)", kms.ErrNotFound, false},
		{"internal error", kms.ErrInternal, false},
		{"wrapped key-not-found", kms.ErrKeyNotFound.WithContext("key_id", "k1"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := kms.IsKeyNotFound(tc.err)
			if got != tc.want {
				t.Errorf("IsKeyNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// =============================================================================
// Constants tests
// =============================================================================

func TestKMSKeyAlgorithmConstants(t *testing.T) {
	tests := []struct {
		name  string
		value kms.KMSKeyAlgorithm
		want  string
	}{
		{"RSA2048", kms.AlgorithmRSA2048, "RSA-2048"},
		{"RSA4096", kms.AlgorithmRSA4096, "RSA-4096"},
		{"ECDSAP256", kms.AlgorithmECDSAP256, "ECDSA-P256"},
		{"ECDSAP384", kms.AlgorithmECDSAP384, "ECDSA-P384"},
		{"ED25519", kms.AlgorithmED25519, "ED25519"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.value) != tc.want {
				t.Errorf("expected %q, got %q", tc.want, tc.value)
			}
		})
	}
}

func TestKMSKeyUsageConstants(t *testing.T) {
	tests := []struct {
		name  string
		value kms.KMSKeyUsage
		want  string
	}{
		{"Sign", kms.KeyUsageSign, "sign"},
		{"Verify", kms.KeyUsageVerify, "verify"},
		{"Encrypt", kms.KeyUsageEncrypt, "encrypt"},
		{"Decrypt", kms.KeyUsageDecrypt, "decrypt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.value) != tc.want {
				t.Errorf("expected %q, got %q", tc.want, tc.value)
			}
		})
	}
}

func TestKeyPurposeConstants(t *testing.T) {
	tests := []struct {
		name  string
		value kms.KeyPurpose
		want  string
	}{
		{"TenantRootCA", kms.KeyPurposeTenantRootCA, "tenant-root-ca"},
		{"TenantIntermediateCA", kms.KeyPurposeTenantIntermediateCA, "tenant-intermediate-ca"},
		{"OCSP", kms.KeyPurposeOCSP, "ocsp"},
		{"CRL", kms.KeyPurposeCRL, "crl"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.value) != tc.want {
				t.Errorf("expected %q, got %q", tc.want, tc.value)
			}
		})
	}
}

// =============================================================================
// MemoryKMSClient tests
// =============================================================================

func TestMemoryKMSClient_GenerateKey(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	resp, err := c.GenerateKey(ctx, &kms.KMSGenerateKeyRequest{
		Name:      "mykey",
		Algorithm: kms.AlgorithmECDSAP256,
		Usage:     []kms.KMSKeyUsage{kms.KeyUsageSign, kms.KeyUsageVerify},
	})
	if err != nil {
		t.Fatalf("GenerateKey: unexpected error: %v", err)
	}
	if resp.KeyID != "mykey" {
		t.Errorf("expected KeyID %q, got %q", "mykey", resp.KeyID)
	}
	if resp.Version != 1 {
		t.Errorf("expected Version 1, got %d", resp.Version)
	}
}

func TestMemoryKMSClient_GenerateKey_EmptyName(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	resp, err := c.GenerateKey(ctx, &kms.KMSGenerateKeyRequest{
		Name:      "",
		Algorithm: kms.AlgorithmRSA2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey with empty name: unexpected error: %v", err)
	}
	if resp.KeyID == "" {
		t.Error("expected auto-generated KeyID, got empty string")
	}
}

func TestMemoryKMSClient_GetKey(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	_, err := c.GenerateKey(ctx, &kms.KMSGenerateKeyRequest{
		Name:      "gettest",
		Algorithm: kms.AlgorithmECDSAP384,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info, err := c.GetKey(ctx, "gettest")
	if err != nil {
		t.Fatalf("GetKey: unexpected error: %v", err)
	}
	if info.KeyID != "gettest" {
		t.Errorf("expected KeyID %q, got %q", "gettest", info.KeyID)
	}
	if info.Algorithm != kms.AlgorithmECDSAP384 {
		t.Errorf("expected algorithm %v, got %v", kms.AlgorithmECDSAP384, info.Algorithm)
	}
}

func TestMemoryKMSClient_GetKey_NotFound(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	_, err := c.GetKey(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if !kms.IsNotFound(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

func TestMemoryKMSClient_ListKeys(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	// Initially empty.
	resp, err := c.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(resp.Keys) != 0 {
		t.Errorf("expected empty list, got %d keys", len(resp.Keys))
	}

	// Add two keys.
	for _, name := range []string{"key1", "key2"} {
		if _, err := c.GenerateKey(ctx, &kms.KMSGenerateKeyRequest{
			Name:      name,
			Algorithm: kms.AlgorithmED25519,
		}); err != nil {
			t.Fatalf("GenerateKey(%q): %v", name, err)
		}
	}

	resp, err = c.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys after adding: %v", err)
	}
	if len(resp.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(resp.Keys))
	}
}

func TestMemoryKMSClient_RotateKey(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	if _, err := c.GenerateKey(ctx, &kms.KMSGenerateKeyRequest{
		Name:      "rotatekey",
		Algorithm: kms.AlgorithmECDSAP256,
	}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	resp, err := c.RotateKey(ctx, "rotatekey")
	if err != nil {
		t.Fatalf("RotateKey: unexpected error: %v", err)
	}
	if resp.NewVersion != 2 {
		t.Errorf("expected version 2 after rotation, got %d", resp.NewVersion)
	}

	// Verify the stored key has the new version.
	info, err := c.GetKey(ctx, "rotatekey")
	if err != nil {
		t.Fatalf("GetKey after rotate: %v", err)
	}
	if info.Version != 2 {
		t.Errorf("expected version 2 in stored key, got %d", info.Version)
	}
}

func TestMemoryKMSClient_RotateKey_NotFound(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	_, err := c.RotateKey(ctx, "missing")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if !kms.IsNotFound(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

func TestMemoryKMSClient_DeleteKey(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	if _, err := c.GenerateKey(ctx, &kms.KMSGenerateKeyRequest{
		Name:      "delkey",
		Algorithm: kms.AlgorithmRSA4096,
	}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if err := c.DeleteKey(ctx, "delkey"); err != nil {
		t.Fatalf("DeleteKey: unexpected error: %v", err)
	}

	// Verify it's gone.
	if _, err := c.GetKey(ctx, "delkey"); err == nil {
		t.Error("expected error after deletion, got nil")
	}
}

func TestMemoryKMSClient_DeleteKey_NotFound(t *testing.T) {
	c := kms.NewMemoryKMSClient()
	ctx := context.Background()

	err := c.DeleteKey(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if !kms.IsNotFound(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

func TestMemoryKMSClient_InterfaceCompliance(t *testing.T) {
	var _ kms.KMSClient = kms.NewMemoryKMSClient()
}

// =============================================================================
// MemoryCryptoClient tests
// =============================================================================

func TestMemoryCryptoClient_Sign(t *testing.T) {
	c := kms.NewMemoryCryptoClient()
	ctx := context.Background()

	resp, err := c.Sign(ctx, &kms.CryptoSignRequest{
		KeyID:   "k1",
		Data:    []byte("hello"),
		HashAlg: kms.HashSHA256,
	})
	if err != nil {
		t.Fatalf("Sign: unexpected error: %v", err)
	}
	if len(resp.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestMemoryCryptoClient_Verify(t *testing.T) {
	c := kms.NewMemoryCryptoClient()
	ctx := context.Background()

	resp, err := c.Verify(ctx, &kms.CryptoVerifyRequest{
		KeyID:     "k1",
		Data:      []byte("hello"),
		Signature: []byte("mock-signature"),
		HashAlg:   kms.HashSHA256,
	})
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Error("expected Valid=true from MemoryCryptoClient.Verify")
	}
}

func TestMemoryCryptoClient_InterfaceCompliance(t *testing.T) {
	var _ kms.CryptoClient = kms.NewMemoryCryptoClient()
}

func TestCryptoHashAlgorithmConstants(t *testing.T) {
	tests := []struct {
		name  string
		value kms.CryptoHashAlgorithm
		want  string
	}{
		{"SHA256", kms.HashSHA256, "SHA-256"},
		{"SHA384", kms.HashSHA384, "SHA-384"},
		{"SHA512", kms.HashSHA512, "SHA-512"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.value) != tc.want {
				t.Errorf("expected %q, got %q", tc.want, tc.value)
			}
		})
	}
}

// =============================================================================
// KeyMetadata struct test
// =============================================================================

func TestKeyMetadata_Fields(t *testing.T) {
	m := kms.KeyMetadata{
		KeyID:     "k-abc",
		TenantID:  "t-123",
		Purpose:   kms.KeyPurposeTenantRootCA,
		Algorithm: "ECDSA-P256",
		Enabled:   true,
		CreatedAt: 1234567890,
	}
	if m.KeyID != "k-abc" {
		t.Errorf("KeyID: expected %q, got %q", "k-abc", m.KeyID)
	}
	if m.TenantID != "t-123" {
		t.Errorf("TenantID: expected %q, got %q", "t-123", m.TenantID)
	}
	if m.Purpose != kms.KeyPurposeTenantRootCA {
		t.Errorf("Purpose: expected %v, got %v", kms.KeyPurposeTenantRootCA, m.Purpose)
	}
	if !m.Enabled {
		t.Error("Enabled: expected true")
	}
}
