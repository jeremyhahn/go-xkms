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

package software

import (
	"crypto"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// createMLDSAAttrs creates ML-DSA key attributes for the given algorithm.
func createMLDSAAttrs(cn string, algo types.QuantumAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:        cn,
		KeyType:   backend.KEY_TYPE_TLS,
		StoreType: backend.STORE_SW,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: algo,
		},
	}
}

// createMLKEMAttrs creates ML-KEM key attributes for the given algorithm.
func createMLKEMAttrs(cn string, algo types.QuantumAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:        cn,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_SW,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: algo,
		},
	}
}

func TestGenerateKey_MLDSA44(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("test.mldsa44", types.QuantumAlgorithmMLDSA44)
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey ML-DSA-44 failed: %v", err)
	}

	mldsaKey, ok := key.(*quantum.MLDSAPrivateKey)
	if !ok {
		t.Fatalf("expected *quantum.MLDSAPrivateKey, got %T", key)
	}

	if mldsaKey.Algorithm != "ML-DSA-44" {
		t.Errorf("expected algorithm ML-DSA-44, got %s", mldsaKey.Algorithm)
	}
}

func TestGenerateKey_MLDSA44_InvalidCN(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("", types.QuantumAlgorithmMLDSA44)
	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("expected error for empty CN, got nil")
	}
}

func TestGenerateKey_MLDSA65(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("test.mldsa65", types.QuantumAlgorithmMLDSA65)
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey ML-DSA-65 failed: %v", err)
	}

	mldsaKey, ok := key.(*quantum.MLDSAPrivateKey)
	if !ok {
		t.Fatalf("expected *quantum.MLDSAPrivateKey, got %T", key)
	}

	if mldsaKey.Algorithm != "ML-DSA-65" {
		t.Errorf("expected algorithm ML-DSA-65, got %s", mldsaKey.Algorithm)
	}
}

func TestGenerateKey_MLDSA87(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("test.mldsa87", types.QuantumAlgorithmMLDSA87)
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey ML-DSA-87 failed: %v", err)
	}

	mldsaKey, ok := key.(*quantum.MLDSAPrivateKey)
	if !ok {
		t.Fatalf("expected *quantum.MLDSAPrivateKey, got %T", key)
	}

	if mldsaKey.Algorithm != "ML-DSA-87" {
		t.Errorf("expected algorithm ML-DSA-87, got %s", mldsaKey.Algorithm)
	}
}

func TestGenerateKey_MLKEM768(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLKEMAttrs("test.mlkem768", types.QuantumAlgorithmMLKEM768)
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey ML-KEM-768 failed: %v", err)
	}

	mlkemKey, ok := key.(*quantum.MLKEMPrivateKey)
	if !ok {
		t.Fatalf("expected *quantum.MLKEMPrivateKey, got %T", key)
	}

	if mlkemKey.Algorithm != "ML-KEM-768" {
		t.Errorf("expected algorithm ML-KEM-768, got %s", mlkemKey.Algorithm)
	}
}

func TestGenerateKey_MLKEM1024(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLKEMAttrs("test.mlkem1024", types.QuantumAlgorithmMLKEM1024)
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey ML-KEM-1024 failed: %v", err)
	}

	mlkemKey, ok := key.(*quantum.MLKEMPrivateKey)
	if !ok {
		t.Fatalf("expected *quantum.MLKEMPrivateKey, got %T", key)
	}

	if mlkemKey.Algorithm != "ML-KEM-1024" {
		t.Errorf("expected algorithm ML-KEM-1024, got %s", mlkemKey.Algorithm)
	}
}

func TestGetKey_MLDSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("test.getkey.mldsa", types.QuantumAlgorithmMLDSA44)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	mldsaKey, ok := retrieved.(*quantum.MLDSAPrivateKey)
	if !ok {
		t.Fatalf("expected *quantum.MLDSAPrivateKey, got %T", retrieved)
	}

	if mldsaKey.Algorithm != "ML-DSA-44" {
		t.Errorf("expected algorithm ML-DSA-44, got %s", mldsaKey.Algorithm)
	}
}

func TestGetKey_MLDSA_NotFound(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("nonexistent.mldsa", types.QuantumAlgorithmMLDSA44)
	_, err := be.GetKey(attrs)
	if err == nil {
		t.Fatal("expected error for nonexistent key, got nil")
	}
}

func TestGetKey_MLKEM(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLKEMAttrs("test.getkey.mlkem", types.QuantumAlgorithmMLKEM768)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	mlkemKey, ok := retrieved.(*quantum.MLKEMPrivateKey)
	if !ok {
		t.Fatalf("expected *quantum.MLKEMPrivateKey, got %T", retrieved)
	}

	if mlkemKey.Algorithm != "ML-KEM-768" {
		t.Errorf("expected algorithm ML-KEM-768, got %s", mlkemKey.Algorithm)
	}
}

func TestDeleteKey_Quantum(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("test.delete.mldsa", types.QuantumAlgorithmMLDSA44)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	err = be.DeleteKey(attrs)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify key is gone
	_, err = be.GetKey(attrs)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestDeleteKey_Quantum_NotFound(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("nonexistent.delete", types.QuantumAlgorithmMLDSA44)
	err := be.DeleteKey(attrs)
	if err == nil {
		t.Fatal("expected error deleting nonexistent key, got nil")
	}
}

func TestSigner_MLDSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("test.signer.mldsa", types.QuantumAlgorithmMLDSA65)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	// ML-DSA signs the full message, not a pre-hash; opts.HashFunc() must return 0
	message := []byte("test message for ML-DSA signing")
	sig, err := signer.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify via the MLDSAPrivateKey.Verify method
	key, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	mldsaKey := key.(*quantum.MLDSAPrivateKey)
	valid, err := mldsaKey.Verify(message, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatal("signature verification failed")
	}
}

func TestSigner_MLDSA_VerifyTampered(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("test.signer.tampered", types.QuantumAlgorithmMLDSA44)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	message := []byte("original message")
	sig, err := signer.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Tamper with the message
	key, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	mldsaKey := key.(*quantum.MLDSAPrivateKey)
	valid, err := mldsaKey.Verify([]byte("tampered message"), sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Fatal("expected verification to fail with tampered message")
	}
}

func TestRotateKey_Quantum(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("test.rotate.mldsa", types.QuantumAlgorithmMLDSA44)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get original key seed for comparison
	origKey, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	origSeed := origKey.(*quantum.MLDSAPrivateKey).ExportSecretKey()

	err = be.RotateKey(attrs)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Verify the key changed
	newKey, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey after rotate failed: %v", err)
	}
	newSeed := newKey.(*quantum.MLDSAPrivateKey).ExportSecretKey()

	if string(origSeed) == string(newSeed) {
		t.Fatal("key should have changed after rotation")
	}
}

func TestRotateKey_Quantum_NotFound(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLDSAAttrs("nonexistent.rotate", types.QuantumAlgorithmMLDSA44)
	err := be.RotateKey(attrs)
	if err == nil {
		t.Fatal("expected error rotating nonexistent key, got nil")
	}
}

func TestListKeys_IncludesQuantum(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Generate one classical and one quantum key
	rsaAttrs := createRSAAttrs("test.list.rsa", 2048)
	_, err := be.GenerateKey(rsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}

	mldsaAttrs := createMLDSAAttrs("test.list.mldsa", types.QuantumAlgorithmMLDSA44)
	_, err = be.GenerateKey(mldsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey ML-DSA-44 failed: %v", err)
	}

	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) < 2 {
		t.Fatalf("expected at least 2 keys, got %d", len(keys))
	}

	// Verify quantum key is present
	var foundQuantum bool
	for _, k := range keys {
		if k.QuantumAttributes != nil {
			foundQuantum = true
			break
		}
	}

	if !foundQuantum {
		t.Fatal("quantum key not found in ListKeys results")
	}
}

func TestCapabilities_Quantum(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	caps := be.Capabilities()

	if !caps.QuantumSigning {
		t.Error("expected QuantumSigning to be true")
	}

	if !caps.KeyEncapsulation {
		t.Error("expected KeyEncapsulation to be true")
	}
}

func TestEncapsulateDecapsulate_MLKEM768(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Generate sender and recipient keys
	senderAttrs := createMLKEMAttrs("sender.mlkem", types.QuantumAlgorithmMLKEM768)
	_, err := be.GenerateKey(senderAttrs)
	if err != nil {
		t.Fatalf("GenerateKey sender failed: %v", err)
	}

	recipientAttrs := createMLKEMAttrs("recipient.mlkem", types.QuantumAlgorithmMLKEM768)
	recipientKey, err := be.GenerateKey(recipientAttrs)
	if err != nil {
		t.Fatalf("GenerateKey recipient failed: %v", err)
	}

	recipientMLKEM := recipientKey.(*quantum.MLKEMPrivateKey)

	// Sender encapsulates to recipient's public key
	senderKey, err := be.GetKey(senderAttrs)
	if err != nil {
		t.Fatalf("GetKey sender failed: %v", err)
	}
	senderMLKEM := senderKey.(*quantum.MLKEMPrivateKey)

	ciphertext, senderSecret, err := senderMLKEM.Encapsulate(recipientMLKEM.PublicKey.Bytes())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Recipient decapsulates
	recipientSecret, err := recipientMLKEM.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if string(senderSecret) != string(recipientSecret) {
		t.Fatal("shared secrets do not match")
	}
}

func TestEncapsulateDecapsulate_MLKEM768_BadCiphertext(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createMLKEMAttrs("test.badct", types.QuantumAlgorithmMLKEM768)
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	mlkemKey := key.(*quantum.MLKEMPrivateKey)

	// Decapsulate with bad ciphertext (wrong size)
	_, err = mlkemKey.Decapsulate([]byte("bad ciphertext"))
	if err == nil {
		t.Fatal("expected error decapsulating bad ciphertext, got nil")
	}
}

func TestClose_Quantum(t *testing.T) {
	be, _ := createTestBackend(t)

	// Generate a quantum key
	attrs := createMLDSAAttrs("test.close", types.QuantumAlgorithmMLDSA44)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	err = be.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Operations after close should fail
	_, err = be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("expected error after close, got nil")
	}
}
