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

//go:build integration && quantum

package quantum_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/quantum/dilithium2"
	"github.com/jeremyhahn/go-keychain/pkg/quantum/kyber768"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHybridIntegration_DualSignature tests signing with both classical and quantum signatures
func TestHybridIntegration_DualSignature(t *testing.T) {
	// Generate classical ECDSA key
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate quantum Dilithium2 key
	dilithium, err := dilithium2.New()
	require.NoError(t, err)
	defer dilithium.Clean()

	dilithiumPub, err := dilithium.GenerateKeyPair()
	require.NoError(t, err)

	// Document to sign
	document := []byte("Important legal document requiring dual signatures")
	hash := sha256.Sum256(document)

	// Classical signature (ECDSA)
	ecdsaSig, err := ecdsa.SignASN1(rand.Reader, ecdsaPriv, hash[:])
	require.NoError(t, err)

	// Quantum signature (Dilithium2)
	dilithiumSig, err := dilithium.Sign(document)
	require.NoError(t, err)

	// Verify classical signature
	classicalValid := ecdsa.VerifyASN1(&ecdsaPriv.PublicKey, hash[:], ecdsaSig)
	assert.True(t, classicalValid, "Classical ECDSA signature should be valid")

	// Verify quantum signature
	quantumValid, err := dilithium.Verify(document, dilithiumSig, dilithiumPub)
	require.NoError(t, err)
	assert.True(t, quantumValid, "Quantum Dilithium2 signature should be valid")

	t.Logf("Document: %d bytes", len(document))
	t.Logf("ECDSA signature: %d bytes", len(ecdsaSig))
	t.Logf("Dilithium2 signature: %d bytes", len(dilithiumSig))
	t.Logf("Total signature overhead: %d bytes", len(ecdsaSig)+len(dilithiumSig))

	// Both signatures valid = document is authentic
	assert.True(t, classicalValid && quantumValid,
		"Document requires both classical and quantum signature verification")
}

// TestHybridIntegration_KeyEncapsulationWithAES tests Kyber KEM + AES-GCM encryption
func TestHybridIntegration_KeyEncapsulationWithAES(t *testing.T) {
	// Recipient generates Kyber key pair
	recipient, err := kyber768.New()
	require.NoError(t, err)
	defer recipient.Clean()

	recipientPubKey, err := recipient.GenerateKeyPair()
	require.NoError(t, err)

	// Sender encapsulates to get shared secret
	sender, err := kyber768.New()
	require.NoError(t, err)
	defer sender.Clean()

	ciphertext, senderSharedSecret, err := sender.Encapsulate(recipientPubKey)
	require.NoError(t, err)

	// Sender uses shared secret for AES-GCM encryption
	plaintext := []byte("Highly confidential quantum-resistant encrypted message")

	block, err := aes.NewCipher(senderSharedSecret)
	require.NoError(t, err)

	aesGCM, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	encryptedMessage := aesGCM.Seal(nonce, nonce, plaintext, nil)

	t.Logf("Plaintext: %d bytes", len(plaintext))
	t.Logf("Kyber ciphertext: %d bytes", len(ciphertext))
	t.Logf("AES-GCM encrypted: %d bytes", len(encryptedMessage))
	t.Logf("Total transmission: %d bytes", len(ciphertext)+len(encryptedMessage))

	// Recipient decapsulates to recover shared secret
	recipientSharedSecret, err := recipient.Decapsulate(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, senderSharedSecret, recipientSharedSecret,
		"Shared secrets should match")

	// Recipient decrypts message
	block2, err := aes.NewCipher(recipientSharedSecret)
	require.NoError(t, err)

	aesGCM2, err := cipher.NewGCM(block2)
	require.NoError(t, err)

	receivedNonce := encryptedMessage[:aesGCM2.NonceSize()]
	receivedCiphertext := encryptedMessage[aesGCM2.NonceSize():]

	decryptedMessage, err := aesGCM2.Open(nil, receivedNonce, receivedCiphertext, nil)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decryptedMessage,
		"Decrypted message should match original plaintext")
}

// TestHybridIntegration_QuantumResistantTLSHandshake simulates quantum-resistant handshake
func TestHybridIntegration_QuantumResistantTLSHandshake(t *testing.T) {
	// Server's long-term identity (quantum-resistant signature)
	serverSigner, err := dilithium2.New()
	require.NoError(t, err)
	defer serverSigner.Clean()

	serverSignPubKey, err := serverSigner.GenerateKeyPair()
	require.NoError(t, err)

	// Server's ephemeral KEM key
	serverKEM, err := kyber768.New()
	require.NoError(t, err)
	defer serverKEM.Clean()

	serverKEMPubKey, err := serverKEM.GenerateKeyPair()
	require.NoError(t, err)

	// Server signs its KEM public key
	serverHello := serverKEMPubKey
	serverHelloSig, err := serverSigner.Sign(serverHello)
	require.NoError(t, err)

	// Client verifies server's identity
	clientVerifier, err := dilithium2.New()
	require.NoError(t, err)
	defer clientVerifier.Clean()

	serverIdentityValid, err := clientVerifier.Verify(serverHello, serverHelloSig, serverSignPubKey)
	require.NoError(t, err)
	assert.True(t, serverIdentityValid, "Client should verify server's quantum-resistant identity")

	// Client encapsulates session key
	clientKEM, err := kyber768.New()
	require.NoError(t, err)
	defer clientKEM.Clean()

	clientCiphertext, clientSessionKey, err := clientKEM.Encapsulate(serverKEMPubKey)
	require.NoError(t, err)

	// Server decapsulates to get same session key
	serverSessionKey, err := serverKEM.Decapsulate(clientCiphertext)
	require.NoError(t, err)

	assert.Equal(t, clientSessionKey, serverSessionKey,
		"Client and server should have identical session keys")

	t.Logf("=== Quantum-Resistant Handshake Complete ===")
	t.Logf("Server signature key: %d bytes", len(serverSignPubKey))
	t.Logf("Server KEM key: %d bytes", len(serverKEMPubKey))
	t.Logf("Server hello signature: %d bytes", len(serverHelloSig))
	t.Logf("Client KEM ciphertext: %d bytes", len(clientCiphertext))
	t.Logf("Session key: %d bytes (256-bit)", len(serverSessionKey))
	t.Logf("Total handshake overhead: %d bytes",
		len(serverKEMPubKey)+len(serverHelloSig)+len(clientCiphertext))
}

// TestHybridIntegration_MultiLayerSecurity tests defense-in-depth approach
func TestHybridIntegration_MultiLayerSecurity(t *testing.T) {
	message := []byte("Critical infrastructure command: ENGAGE_SAFETY_PROTOCOL")

	// Layer 1: Classical ECDSA signature
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	hash := sha256.Sum256(message)
	ecdsaSig, err := ecdsa.SignASN1(rand.Reader, ecdsaPriv, hash[:])
	require.NoError(t, err)

	// Layer 2: Quantum Dilithium2 signature
	dilithium, err := dilithium2.New()
	require.NoError(t, err)
	defer dilithium.Clean()
	dilithiumPub, err := dilithium.GenerateKeyPair()
	require.NoError(t, err)
	dilithiumSig, err := dilithium.Sign(message)
	require.NoError(t, err)

	// Layer 3: Quantum Kyber768 key encapsulation
	recipient, err := kyber768.New()
	require.NoError(t, err)
	defer recipient.Clean()
	recipientPub, err := recipient.GenerateKeyPair()
	require.NoError(t, err)

	sender, err := kyber768.New()
	require.NoError(t, err)
	defer sender.Clean()
	kemCiphertext, sessionKey, err := sender.Encapsulate(recipientPub)
	require.NoError(t, err)

	// Layer 4: AES-256-GCM encryption
	block, err := aes.NewCipher(sessionKey)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	// Package: message + ECDSA sig + Dilithium sig
	package1 := append(message, ecdsaSig...)
	package2 := append(package1, dilithiumSig...)

	encryptedPackage := aesGCM.Seal(nonce, nonce, package2, nil)

	t.Logf("=== Multi-Layer Security Package ===")
	t.Logf("Original message: %d bytes", len(message))
	t.Logf("+ ECDSA signature: %d bytes", len(ecdsaSig))
	t.Logf("+ Dilithium2 signature: %d bytes", len(dilithiumSig))
	t.Logf("= Signed package: %d bytes", len(package2))
	t.Logf("+ AES-GCM overhead: %d bytes", len(encryptedPackage)-len(package2))
	t.Logf("= Encrypted package: %d bytes", len(encryptedPackage))
	t.Logf("+ Kyber ciphertext: %d bytes", len(kemCiphertext))
	t.Logf("= Total transmission: %d bytes", len(encryptedPackage)+len(kemCiphertext))

	// Recipient decryption and verification
	recoveredKey, err := recipient.Decapsulate(kemCiphertext)
	require.NoError(t, err)

	block2, err := aes.NewCipher(recoveredKey)
	require.NoError(t, err)
	aesGCM2, err := cipher.NewGCM(block2)
	require.NoError(t, err)

	receivedNonce := encryptedPackage[:aesGCM2.NonceSize()]
	receivedCiphertext := encryptedPackage[aesGCM2.NonceSize():]
	decryptedPackage, err := aesGCM2.Open(nil, receivedNonce, receivedCiphertext, nil)
	require.NoError(t, err)

	// Extract components
	recoveredMessage := decryptedPackage[:len(message)]
	recoveredECDSASig := decryptedPackage[len(message) : len(message)+len(ecdsaSig)]
	recoveredDilithiumSig := decryptedPackage[len(message)+len(ecdsaSig):]

	// Verify Layer 2: Quantum signature
	quantumValid, err := dilithium.Verify(recoveredMessage, recoveredDilithiumSig, dilithiumPub)
	require.NoError(t, err)
	assert.True(t, quantumValid, "Quantum signature must be valid")

	// Verify Layer 1: Classical signature
	recoveredHash := sha256.Sum256(recoveredMessage)
	classicalValid := ecdsa.VerifyASN1(&ecdsaPriv.PublicKey, recoveredHash[:], recoveredECDSASig)
	assert.True(t, classicalValid, "Classical signature must be valid")

	assert.Equal(t, message, recoveredMessage, "Message integrity verified")

	t.Logf("=== All Security Layers Verified ===")
	t.Logf("Layer 1 (ECDSA P-384): %v", classicalValid)
	t.Logf("Layer 2 (Dilithium2): %v", quantumValid)
	t.Logf("Layer 3 (Kyber768 KEM): Session key recovered")
	t.Logf("Layer 4 (AES-256-GCM): Message decrypted and authenticated")
}

// TestHybridIntegration_KeyRotation tests rotating quantum keys
func TestHybridIntegration_KeyRotation(t *testing.T) {
	// Old key pair
	oldSigner, err := dilithium2.New()
	require.NoError(t, err)
	defer oldSigner.Clean()

	oldPubKey, err := oldSigner.GenerateKeyPair()
	require.NoError(t, err)

	// New key pair
	newSigner, err := dilithium2.New()
	require.NoError(t, err)
	defer newSigner.Clean()

	newPubKey, err := newSigner.GenerateKeyPair()
	require.NoError(t, err)

	// Old key signs new key (key rotation certificate)
	rotationCert := append([]byte("KEY_ROTATION:"), newPubKey...)
	rotationSig, err := oldSigner.Sign(rotationCert)
	require.NoError(t, err)

	// New key signs itself (self-attestation)
	selfAttestation := append([]byte("SELF_ATTEST:"), newPubKey...)
	selfAttestSig, err := newSigner.Sign(selfAttestation)
	require.NoError(t, err)

	// Verify rotation chain
	rotationValid, err := oldSigner.Verify(rotationCert, rotationSig, oldPubKey)
	require.NoError(t, err)
	assert.True(t, rotationValid, "Old key should certify new key")

	selfAttestValid, err := newSigner.Verify(selfAttestation, selfAttestSig, newPubKey)
	require.NoError(t, err)
	assert.True(t, selfAttestValid, "New key should self-attest")

	// After rotation, new messages signed with new key
	message := []byte("Post-rotation message")
	newSig, err := newSigner.Sign(message)
	require.NoError(t, err)

	valid, err := newSigner.Verify(message, newSig, newPubKey)
	require.NoError(t, err)
	assert.True(t, valid, "New key should sign new messages")

	t.Logf("Key rotation successful:")
	t.Logf("Old public key: %d bytes", len(oldPubKey))
	t.Logf("New public key: %d bytes", len(newPubKey))
	t.Logf("Rotation certificate signature: %d bytes", len(rotationSig))
}

// TestHybridIntegration_QuantumAlgorithmComparison compares sizes
func TestHybridIntegration_QuantumAlgorithmComparison(t *testing.T) {
	// Classical ECDSA P-256
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Quantum Dilithium2
	dilithium, err := dilithium2.New()
	require.NoError(t, err)
	defer dilithium.Clean()

	dilithiumPub, err := dilithium.GenerateKeyPair()
	require.NoError(t, err)

	// Quantum Kyber768
	kyber, err := kyber768.New()
	require.NoError(t, err)
	defer kyber.Clean()

	kyberPub, err := kyber.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("Comparison test message")
	hash := sha256.Sum256(message)

	// ECDSA signature
	ecdsaSig, err := ecdsa.SignASN1(rand.Reader, ecdsaPriv, hash[:])
	require.NoError(t, err)

	// Dilithium signature
	dilithiumSig, err := dilithium.Sign(message)
	require.NoError(t, err)

	t.Logf("=== Algorithm Size Comparison ===")
	t.Logf("")
	t.Logf("Public Key Sizes:")
	t.Logf("  ECDSA P-256: 65 bytes (compressed: 33 bytes)")
	t.Logf("  Dilithium2: %d bytes", len(dilithiumPub))
	t.Logf("  Kyber768: %d bytes", len(kyberPub))
	t.Logf("")
	t.Logf("Signature/Ciphertext Sizes:")
	t.Logf("  ECDSA P-256: %d bytes", len(ecdsaSig))
	t.Logf("  Dilithium2: %d bytes", len(dilithiumSig))
	t.Logf("  Kyber768 ciphertext: %d bytes", kyber.CiphertextLength())
	t.Logf("")
	t.Logf("Size Increase for Quantum Safety:")
	t.Logf("  Signature: %dx larger", len(dilithiumSig)/len(ecdsaSig))
	t.Logf("  Public key: %dx larger", len(dilithiumPub)/65)
	t.Logf("")
	t.Logf("Trade-off: Much larger but quantum-resistant")

	// Sizes are expected
	assert.Greater(t, len(dilithiumPub), 1000, "Dilithium2 public key should be >1KB")
	assert.Greater(t, len(dilithiumSig), 2000, "Dilithium2 signature should be >2KB")
	assert.Greater(t, len(kyberPub), 1000, "Kyber768 public key should be >1KB")
}
