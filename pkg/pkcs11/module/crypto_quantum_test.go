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

package module

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewQuantumCryptoManager(t *testing.T) {
	qcm := NewQuantumCryptoManager()
	require.NotNil(t, qcm)
}

func TestGenerateMLDSA44KeyPair(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("generates valid key pair", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)
		require.NotNil(t, keyPair)

		assert.Len(t, keyPair.PublicKey, MLDSA44PublicKeySize)
		assert.Len(t, keyPair.SecretKey, mldsaSeedSize)
		assert.Equal(t, CKK_VENDOR_ML_DSA, keyPair.KeyType)
		assert.Equal(t, CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN, keyPair.Mechanism)
		assert.Equal(t, MLDSA44PublicKeySize, keyPair.PublicSize)
		assert.Equal(t, mldsaSeedSize, keyPair.SecretSize)
	})

	t.Run("generates unique key pairs", func(t *testing.T) {
		keyPair1, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		keyPair2, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		// Public keys should be different for different key pairs
		assert.False(t, bytes.Equal(keyPair1.PublicKey, keyPair2.PublicKey),
			"public keys should be unique")
		// Seeds are independent random values and will be different
	})

	t.Run("ML-DSA-65 generates valid key pair", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(65)
		require.NoError(t, err)
		require.NotNil(t, keyPair)

		assert.Len(t, keyPair.PublicKey, MLDSA65PublicKeySize)
		assert.Len(t, keyPair.SecretKey, mldsaSeedSize)
		assert.Equal(t, CKK_VENDOR_ML_DSA, keyPair.KeyType)
		assert.Equal(t, CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN, keyPair.Mechanism)
		assert.Equal(t, MLDSA65PublicKeySize, keyPair.PublicSize)
		assert.Equal(t, mldsaSeedSize, keyPair.SecretSize)
	})

	t.Run("ML-DSA-87 generates valid key pair", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(87)
		require.NoError(t, err)
		require.NotNil(t, keyPair)

		assert.Len(t, keyPair.PublicKey, MLDSA87PublicKeySize)
		assert.Len(t, keyPair.SecretKey, mldsaSeedSize)
		assert.Equal(t, CKK_VENDOR_ML_DSA, keyPair.KeyType)
		assert.Equal(t, CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN, keyPair.Mechanism)
		assert.Equal(t, MLDSA87PublicKeySize, keyPair.PublicSize)
		assert.Equal(t, mldsaSeedSize, keyPair.SecretSize)
	})

	t.Run("returns error for unsupported security level", func(t *testing.T) {
		_, err := qcm.GenerateMLDSAKeyPair(99)
		assert.Error(t, err)
	})
}

func TestMLDSA44SignAndVerify(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	// Generate key pair
	keyPair, err := qcm.GenerateMLDSAKeyPair(44)
	require.NoError(t, err)

	testMessage := []byte("test message for quantum signing")

	t.Run("sign and verify succeeds", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}

		// Initialize signing
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key", "test", keyPair.SecretKey)
		require.NoError(t, err)
		require.NotNil(t, signOp)

		// Sign
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)
		require.NotEmpty(t, signature)
		assert.LessOrEqual(t, len(signature), MLDSA44SignatureSize)

		// Initialize verification
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, verifyOp)

		// Verify
		err = qcm.QuantumVerify(verifyOp, testMessage, signature)
		assert.NoError(t, err)
	})

	t.Run("verification fails with wrong message", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}

		// Sign original message
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key", "test", keyPair.SecretKey)
		require.NoError(t, err)
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)

		// Verify with different message
		wrongMessage := []byte("wrong message")
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)

		err = qcm.QuantumVerify(verifyOp, wrongMessage, signature)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_SIGNATURE_INVALID, pkcs11Err.Code)
	})

	t.Run("verification fails with tampered signature", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}

		// Sign
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key", "test", keyPair.SecretKey)
		require.NoError(t, err)
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)

		// Tamper with signature
		tamperedSig := make([]byte, len(signature))
		copy(tamperedSig, signature)
		tamperedSig[0] ^= 0xFF

		// Verify
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)

		err = qcm.QuantumVerify(verifyOp, testMessage, tamperedSig)
		assert.Error(t, err)
	})
}

func TestMLDSA65SignAndVerify(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	// Generate key pair
	keyPair, err := qcm.GenerateMLDSAKeyPair(65)
	require.NoError(t, err)

	testMessage := []byte("test message for ML-DSA-65 quantum signing")

	t.Run("sign and verify succeeds", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_65}

		// Initialize signing
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key-65", "test", keyPair.SecretKey)
		require.NoError(t, err)
		require.NotNil(t, signOp)

		// Sign
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)
		require.NotEmpty(t, signature)
		assert.LessOrEqual(t, len(signature), MLDSA65SignatureSize)

		// Initialize verification
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key-65", "test", keyPair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, verifyOp)

		// Verify
		err = qcm.QuantumVerify(verifyOp, testMessage, signature)
		assert.NoError(t, err)
	})

	t.Run("verification fails with wrong message", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_65}

		// Sign original message
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key-65", "test", keyPair.SecretKey)
		require.NoError(t, err)
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)

		// Verify with different message
		wrongMessage := []byte("wrong message")
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key-65", "test", keyPair.PublicKey)
		require.NoError(t, err)

		err = qcm.QuantumVerify(verifyOp, wrongMessage, signature)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_SIGNATURE_INVALID, pkcs11Err.Code)
	})

	t.Run("verification fails with tampered signature", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_65}

		// Sign
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key-65", "test", keyPair.SecretKey)
		require.NoError(t, err)
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)

		// Tamper with signature
		tamperedSig := make([]byte, len(signature))
		copy(tamperedSig, signature)
		tamperedSig[0] ^= 0xFF

		// Verify
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key-65", "test", keyPair.PublicKey)
		require.NoError(t, err)

		err = qcm.QuantumVerify(verifyOp, testMessage, tamperedSig)
		assert.Error(t, err)
	})
}

func TestMLDSA87SignAndVerify(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	// Generate key pair
	keyPair, err := qcm.GenerateMLDSAKeyPair(87)
	require.NoError(t, err)

	testMessage := []byte("test message for ML-DSA-87 quantum signing")

	t.Run("sign and verify succeeds", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_87}

		// Initialize signing
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key-87", "test", keyPair.SecretKey)
		require.NoError(t, err)
		require.NotNil(t, signOp)

		// Sign
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)
		require.NotEmpty(t, signature)
		assert.LessOrEqual(t, len(signature), MLDSA87SignatureSize)

		// Initialize verification
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key-87", "test", keyPair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, verifyOp)

		// Verify
		err = qcm.QuantumVerify(verifyOp, testMessage, signature)
		assert.NoError(t, err)
	})

	t.Run("verification fails with wrong message", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_87}

		// Sign original message
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key-87", "test", keyPair.SecretKey)
		require.NoError(t, err)
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)

		// Verify with different message
		wrongMessage := []byte("wrong message")
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key-87", "test", keyPair.PublicKey)
		require.NoError(t, err)

		err = qcm.QuantumVerify(verifyOp, wrongMessage, signature)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_SIGNATURE_INVALID, pkcs11Err.Code)
	})

	t.Run("verification fails with tampered signature", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_87}

		// Sign
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key-87", "test", keyPair.SecretKey)
		require.NoError(t, err)
		signature, err := qcm.QuantumSign(signOp, testMessage)
		require.NoError(t, err)

		// Tamper with signature
		tamperedSig := make([]byte, len(signature))
		copy(tamperedSig, signature)
		tamperedSig[0] ^= 0xFF

		// Verify
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key-87", "test", keyPair.PublicKey)
		require.NoError(t, err)

		err = qcm.QuantumVerify(verifyOp, testMessage, tamperedSig)
		assert.Error(t, err)
	})
}

func TestMLDSA44MultiPartSigning(t *testing.T) {
	qcm := NewQuantumCryptoManager()
	mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
	testData := []byte("part1 part2 part3")

	t.Run("multi-part signing works", func(t *testing.T) {
		// Generate fresh key pair for this test
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		// Initialize
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key", "test", keyPair.SecretKey)
		require.NoError(t, err)

		// Update in parts
		err = qcm.QuantumSignUpdate(signOp, []byte("part1 "))
		require.NoError(t, err)
		err = qcm.QuantumSignUpdate(signOp, []byte("part2 "))
		require.NoError(t, err)
		err = qcm.QuantumSignUpdate(signOp, []byte("part3"))
		require.NoError(t, err)

		// Finalize
		signature, err := qcm.QuantumSignFinal(signOp)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify with single-part
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)

		err = qcm.QuantumVerify(verifyOp, testData, signature)
		assert.NoError(t, err)
	})

	t.Run("multi-part verification works", func(t *testing.T) {
		// Generate fresh key pair for this test
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		// Single-part sign
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key", "test", keyPair.SecretKey)
		require.NoError(t, err)
		signature, err := qcm.QuantumSign(signOp, testData)
		require.NoError(t, err)

		// Multi-part verify
		verifyOp, err := qcm.QuantumVerifyInit(mech, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)

		err = qcm.QuantumVerifyUpdate(verifyOp, []byte("part1 "))
		require.NoError(t, err)
		err = qcm.QuantumVerifyUpdate(verifyOp, []byte("part2 "))
		require.NoError(t, err)
		err = qcm.QuantumVerifyUpdate(verifyOp, []byte("part3"))
		require.NoError(t, err)

		err = qcm.QuantumVerifyFinal(verifyOp, signature)
		assert.NoError(t, err)
	})
}

func TestQuantumSignInitErrors(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("nil mechanism returns error", func(t *testing.T) {
		_, err := qcm.QuantumSignInit(nil, 1, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcs11Err.Code)
	})

	t.Run("zero key handle returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		_, err := qcm.QuantumSignInit(mech, 0, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcs11Err.Code)
	})

	t.Run("non-ML-DSA mechanism returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		_, err := qcm.QuantumSignInit(mech, 1, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcs11Err.Code)
	})

	t.Run("empty secret key returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		_, err := qcm.QuantumSignInit(mech, 1, "test-key", "test", nil)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcs11Err.Code)
	})
}

func TestQuantumSignErrors(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("nil operation returns error", func(t *testing.T) {
		_, err := qcm.QuantumSign(nil, []byte("data"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcs11Err.Code)
	})

	t.Run("double sign returns error", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		signOp, err := qcm.QuantumSignInit(mech, 1, "test-key", "test", keyPair.SecretKey)
		require.NoError(t, err)

		// First sign succeeds
		_, err = qcm.QuantumSign(signOp, []byte("data"))
		require.NoError(t, err)

		// Second sign fails
		_, err = qcm.QuantumSign(signOp, []byte("data"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcs11Err.Code)
	})
}

func TestGenerateMLKEM768KeyPair(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("generates valid key pair", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)
		require.NotNil(t, keyPair)

		assert.Len(t, keyPair.PublicKey, MLKEM768PublicKeySize)
		assert.Len(t, keyPair.SecretKey, mlkemSeedSize)
		assert.Equal(t, CKK_VENDOR_ML_KEM, keyPair.KeyType)
		assert.Equal(t, CKM_VENDOR_ML_KEM_768_KEY_GEN, keyPair.Mechanism)
		assert.Equal(t, MLKEM768PublicKeySize, keyPair.PublicSize)
		assert.Equal(t, mlkemSeedSize, keyPair.SecretSize)
	})

	t.Run("generates unique key pairs", func(t *testing.T) {
		keyPair1, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		keyPair2, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		// Public keys should be different for different key pairs
		assert.False(t, bytes.Equal(keyPair1.PublicKey, keyPair2.PublicKey),
			"public keys should be unique")
		// Seeds are independent random values
	})

	t.Run("ML-KEM-1024 generates valid key pair", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(1024)
		require.NoError(t, err)
		require.NotNil(t, keyPair)

		assert.Len(t, keyPair.PublicKey, MLKEM1024PublicKeySize)
		assert.Len(t, keyPair.SecretKey, mlkemSeedSize)
		assert.Equal(t, CKK_VENDOR_ML_KEM, keyPair.KeyType)
		assert.Equal(t, CKM_VENDOR_ML_KEM_1024_KEY_GEN, keyPair.Mechanism)
		assert.Equal(t, MLKEM1024PublicKeySize, keyPair.PublicSize)
		assert.Equal(t, mlkemSeedSize, keyPair.SecretSize)
	})

	t.Run("returns error for unsupported security levels", func(t *testing.T) {
		_, err := qcm.GenerateMLKEMKeyPair(512)
		assert.Error(t, err)

		_, err = qcm.GenerateMLKEMKeyPair(256)
		assert.Error(t, err)
	})
}

func TestMLKEM768EncapsulateAndDecapsulate(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	// Generate key pair
	keyPair, err := qcm.GenerateMLKEMKeyPair(768)
	require.NoError(t, err)

	t.Run("encapsulate and decapsulate succeeds", func(t *testing.T) {
		mechEncap := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}

		// Initialize encapsulation
		encapOp, err := qcm.EncapsulateInit(mechEncap, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, encapOp)
		assert.Equal(t, 768, encapOp.SecurityLevel())

		// Encapsulate
		result, err := qcm.Encapsulate(encapOp)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Len(t, result.Ciphertext, MLKEM768CiphertextSize)
		assert.Len(t, result.SharedSecret, MLKEM768SharedSecretSize)

		// Initialize decapsulation
		mechDecap := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
		decapOp, err := qcm.DecapsulateInit(mechDecap, 1, "test-key", "test", keyPair.SecretKey)
		require.NoError(t, err)
		require.NotNil(t, decapOp)
		assert.Equal(t, 768, decapOp.SecurityLevel())

		// Decapsulate
		sharedSecret, err := qcm.Decapsulate(decapOp, result.Ciphertext)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecret)

		// Shared secrets should match
		assert.True(t, bytes.Equal(result.SharedSecret, sharedSecret),
			"shared secrets should match")
	})

	t.Run("each encapsulation produces unique ciphertext and shared secret", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}

		encapOp1, err := qcm.EncapsulateInit(mech, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)
		result1, err := qcm.Encapsulate(encapOp1)
		require.NoError(t, err)

		encapOp2, err := qcm.EncapsulateInit(mech, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)
		result2, err := qcm.Encapsulate(encapOp2)
		require.NoError(t, err)

		assert.False(t, bytes.Equal(result1.Ciphertext, result2.Ciphertext),
			"ciphertexts should be unique")
		assert.False(t, bytes.Equal(result1.SharedSecret, result2.SharedSecret),
			"shared secrets should be unique")
	})
}

func TestMLKEM1024EncapsulateAndDecapsulate(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	// Generate key pair
	keyPair, err := qcm.GenerateMLKEMKeyPair(1024)
	require.NoError(t, err)

	t.Run("encapsulate and decapsulate succeeds", func(t *testing.T) {
		mechEncap := &Mechanism{Type: CKM_VENDOR_ML_KEM_1024_ENCAPSULATE}

		// Initialize encapsulation
		encapOp, err := qcm.EncapsulateInit(mechEncap, 1, "test-key-1024", "test", keyPair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, encapOp)
		assert.Equal(t, 1024, encapOp.SecurityLevel())

		// Encapsulate
		result, err := qcm.Encapsulate(encapOp)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Len(t, result.Ciphertext, MLKEM1024CiphertextSize)
		assert.Len(t, result.SharedSecret, MLKEM1024SharedSecretSize)

		// Initialize decapsulation
		mechDecap := &Mechanism{Type: CKM_VENDOR_ML_KEM_1024_DECAPSULATE}
		decapOp, err := qcm.DecapsulateInit(mechDecap, 1, "test-key-1024", "test", keyPair.SecretKey)
		require.NoError(t, err)
		require.NotNil(t, decapOp)
		assert.Equal(t, 1024, decapOp.SecurityLevel())

		// Decapsulate
		sharedSecret, err := qcm.Decapsulate(decapOp, result.Ciphertext)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecret)

		// Shared secrets should match
		assert.True(t, bytes.Equal(result.SharedSecret, sharedSecret),
			"shared secrets should match")
	})

	t.Run("each encapsulation produces unique ciphertext and shared secret", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_1024_ENCAPSULATE}

		encapOp1, err := qcm.EncapsulateInit(mech, 1, "test-key-1024", "test", keyPair.PublicKey)
		require.NoError(t, err)
		result1, err := qcm.Encapsulate(encapOp1)
		require.NoError(t, err)

		encapOp2, err := qcm.EncapsulateInit(mech, 1, "test-key-1024", "test", keyPair.PublicKey)
		require.NoError(t, err)
		result2, err := qcm.Encapsulate(encapOp2)
		require.NoError(t, err)

		assert.False(t, bytes.Equal(result1.Ciphertext, result2.Ciphertext),
			"ciphertexts should be unique")
		assert.False(t, bytes.Equal(result1.SharedSecret, result2.SharedSecret),
			"shared secrets should be unique")
	})
}

func TestEncapsulateInitErrors(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("nil mechanism returns error", func(t *testing.T) {
		_, err := qcm.EncapsulateInit(nil, 1, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcs11Err.Code)
	})

	t.Run("zero key handle returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		_, err := qcm.EncapsulateInit(mech, 0, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcs11Err.Code)
	})

	t.Run("non-ML-KEM mechanism returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		_, err := qcm.EncapsulateInit(mech, 1, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcs11Err.Code)
	})

	t.Run("empty public key returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		_, err := qcm.EncapsulateInit(mech, 1, "test-key", "test", nil)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcs11Err.Code)
	})
}

func TestEncapsulateErrors(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("nil operation returns error", func(t *testing.T) {
		_, err := qcm.Encapsulate(nil)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcs11Err.Code)
	})

	t.Run("double encapsulate returns error", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		encapOp, err := qcm.EncapsulateInit(mech, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)

		// First encapsulate succeeds
		_, err = qcm.Encapsulate(encapOp)
		require.NoError(t, err)

		// Second encapsulate fails
		_, err = qcm.Encapsulate(encapOp)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcs11Err.Code)
	})
}

func TestDecapsulateInitErrors(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("nil mechanism returns error", func(t *testing.T) {
		_, err := qcm.DecapsulateInit(nil, 1, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcs11Err.Code)
	})

	t.Run("zero key handle returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
		_, err := qcm.DecapsulateInit(mech, 0, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcs11Err.Code)
	})

	t.Run("non-ML-KEM mechanism returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		_, err := qcm.DecapsulateInit(mech, 1, "test-key", "test", []byte("key"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_MECHANISM_INVALID, pkcs11Err.Code)
	})

	t.Run("empty secret key returns error", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
		_, err := qcm.DecapsulateInit(mech, 1, "test-key", "test", nil)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcs11Err.Code)
	})
}

func TestDecapsulateErrors(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("nil operation returns error", func(t *testing.T) {
		_, err := qcm.Decapsulate(nil, []byte("ciphertext"))
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcs11Err.Code)
	})

	t.Run("double decapsulate returns error", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		// First encapsulate to get valid ciphertext
		mechEncap := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		encapOp, err := qcm.EncapsulateInit(mechEncap, 1, "test-key", "test", keyPair.PublicKey)
		require.NoError(t, err)
		result, err := qcm.Encapsulate(encapOp)
		require.NoError(t, err)

		mechDecap := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
		decapOp, err := qcm.DecapsulateInit(mechDecap, 1, "test-key", "test", keyPair.SecretKey)
		require.NoError(t, err)

		// First decapsulate succeeds
		_, err = qcm.Decapsulate(decapOp, result.Ciphertext)
		require.NoError(t, err)

		// Second decapsulate fails
		_, err = qcm.Decapsulate(decapOp, result.Ciphertext)
		assert.Error(t, err)

		pkcs11Err, ok := err.(*PKCS11Error)
		require.True(t, ok)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkcs11Err.Code)
	})
}

func TestQuantumOperationTypes(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("sign operation has correct type", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		op, err := qcm.QuantumSignInit(mech, 1, "test", "test", keyPair.SecretKey)
		require.NoError(t, err)

		assert.Equal(t, OperationSign, op.Type())
		assert.Equal(t, ObjectHandle(1), op.KeyHandle())
		assert.Equal(t, "test", op.KeyID())
		assert.Equal(t, "test", op.Backend())
		assert.Equal(t, 44, op.SecurityLevel())
		assert.False(t, op.IsFinalized())
	})

	t.Run("verify operation has correct type", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		op, err := qcm.QuantumVerifyInit(mech, 1, "test", "test", keyPair.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, OperationVerify, op.Type())
		assert.Equal(t, ObjectHandle(1), op.KeyHandle())
		assert.Equal(t, "test", op.KeyID())
		assert.Equal(t, "test", op.Backend())
		assert.Equal(t, 44, op.SecurityLevel())
		assert.False(t, op.IsFinalized())
	})

	t.Run("encapsulate operation has correct type", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		op, err := qcm.EncapsulateInit(mech, 1, "test", "test", keyPair.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, OperationType(CategoryEncapsulate), op.Type())
		assert.Equal(t, ObjectHandle(1), op.KeyHandle())
		assert.Equal(t, "test", op.KeyID())
		assert.Equal(t, "test", op.Backend())
		assert.Equal(t, 768, op.SecurityLevel())
		assert.False(t, op.IsFinalized())
	})

	t.Run("decapsulate operation has correct type", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
		op, err := qcm.DecapsulateInit(mech, 1, "test", "test", keyPair.SecretKey)
		require.NoError(t, err)

		assert.Equal(t, OperationType(CategoryDecapsulate), op.Type())
		assert.Equal(t, ObjectHandle(1), op.KeyHandle())
		assert.Equal(t, "test", op.KeyID())
		assert.Equal(t, "test", op.Backend())
		assert.Equal(t, 768, op.SecurityLevel())
		assert.False(t, op.IsFinalized())
	})
}

func TestQuantumOperationReset(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("sign operation reset clears state", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		op, err := qcm.QuantumSignInit(mech, 1, "test", "test", keyPair.SecretKey)
		require.NoError(t, err)

		// Add some data
		err = qcm.QuantumSignUpdate(op, []byte("test data"))
		require.NoError(t, err)

		// Finalize
		_, err = qcm.QuantumSignFinal(op)
		require.NoError(t, err)
		assert.True(t, op.IsFinalized())

		// Reset
		op.Reset()
		assert.False(t, op.IsFinalized())
	})

	t.Run("verify operation reset clears state", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		op, err := qcm.QuantumVerifyInit(mech, 1, "test", "test", keyPair.PublicKey)
		require.NoError(t, err)

		// Add some data
		err = qcm.QuantumVerifyUpdate(op, []byte("test data"))
		require.NoError(t, err)

		// Mark as finalized manually for test
		op.finalized = true
		assert.True(t, op.IsFinalized())

		// Reset
		op.Reset()
		assert.False(t, op.IsFinalized())
	})

	t.Run("encapsulate operation reset clears state", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		op, err := qcm.EncapsulateInit(mech, 1, "test", "test", keyPair.PublicKey)
		require.NoError(t, err)

		// Finalize
		_, err = qcm.Encapsulate(op)
		require.NoError(t, err)
		assert.True(t, op.IsFinalized())

		// Reset
		op.Reset()
		assert.False(t, op.IsFinalized())
	})

	t.Run("decapsulate operation reset clears state", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
		op, err := qcm.DecapsulateInit(mech, 1, "test", "test", keyPair.SecretKey)
		require.NoError(t, err)

		// Mark as finalized manually for test
		op.finalized = true
		assert.True(t, op.IsFinalized())

		// Reset
		op.Reset()
		assert.False(t, op.IsFinalized())
	})
}

func TestQuantumMechanismAccessor(t *testing.T) {
	qcm := NewQuantumCryptoManager()

	t.Run("sign operation returns mechanism", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		op, err := qcm.QuantumSignInit(mech, 1, "test", "test", keyPair.SecretKey)
		require.NoError(t, err)

		assert.Equal(t, mech, op.Mechanism())
	})

	t.Run("verify operation returns mechanism", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLDSAKeyPair(44)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
		op, err := qcm.QuantumVerifyInit(mech, 1, "test", "test", keyPair.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, mech, op.Mechanism())
	})

	t.Run("encapsulate operation returns mechanism", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		op, err := qcm.EncapsulateInit(mech, 1, "test", "test", keyPair.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, mech, op.Mechanism())
	})

	t.Run("decapsulate operation returns mechanism", func(t *testing.T) {
		keyPair, err := qcm.GenerateMLKEMKeyPair(768)
		require.NoError(t, err)

		mech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
		op, err := qcm.DecapsulateInit(mech, 1, "test", "test", keyPair.SecretKey)
		require.NoError(t, err)

		assert.Equal(t, mech, op.Mechanism())
	})
}
