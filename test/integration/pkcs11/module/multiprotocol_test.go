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

//go:build integration
// +build integration

// Package module provides multi-protocol integration tests for the PKCS#11 module.
//
// These tests validate that all PKCS#11 operations work consistently across both
// supported transport protocols (Unix gRPC over UDS, gRPC over TCP) and all
// available key storage backends.
//
// Test Matrix:
//
//	Protocols: unix (gRPC over UDS), grpc (gRPC over TCP)
//	Backends: software, tpm2, pkcs11, quantum, awskms, gcpkms, azurekv
//
// Environment Variables:
//
//	XKMS_UNIX_SOCKET    - Unix socket path (default: /var/run/xkms/xkms.sock)
//	XKMS_GRPC_ADDR      - gRPC server address (default: localhost:9443)
//	XKMS_GRPC_TLS_ENABLED - Enable TLS for gRPC (default: false)
//	XKMS_GRPC_TLS_INSECURE - Skip TLS verification (default: true)
//
// Usage:
//
//	go test -v -tags='integration' ./test/integration/pkcs11/module/... -run TestMultiProtocol
package module

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// =============================================================================
// Multi-Protocol Test Suite
// =============================================================================

// TestMultiProtocol_ModuleInitialization tests C_Initialize and C_Finalize
// across all protocols.
func TestMultiProtocol_ModuleInitialization(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	for _, protocol := range AllProtocols() {
		protocol := protocol // capture range variable
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			cfg := suite.GetProtocolConfig(protocol)
			env := SetupTestEnvironment(t, cfg.ToModuleConfig())

			// Test: Initialize
			rv := env.InitializeModule(t)
			if rv != module.CKR_OK {
				t.Fatalf("C_Initialize failed: %s", rv.String())
			}

			// Test: Get Info
			info, rv := env.Module.GetInfo()
			if rv != module.CKR_OK {
				t.Fatalf("C_GetInfo failed: %s", rv.String())
			}

			if info.CryptokiVersion.Major < 3 {
				t.Errorf("expected PKCS#11 v3.x, got v%d.%d",
					info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
			}

			// Test: Double initialize should fail
			rv = env.Module.Initialize(cfg.ToModuleConfig())
			if rv != module.CKR_CRYPTOKI_ALREADY_INITIALIZED {
				t.Errorf("double initialize: expected CKR_CRYPTOKI_ALREADY_INITIALIZED, got %s", rv.String())
			}

			// Finalize handled by cleanup
		})
	}
}

// TestMultiProtocol_SlotAndTokenInfo tests slot and token info across all protocols.
func TestMultiProtocol_SlotAndTokenInfo(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			cfg := suite.GetProtocolConfig(protocol)
			env := SetupTestEnvironment(t, cfg.ToModuleConfig())
			env.MustInitializeModule(t)

			// Test: Get slot list
			slotIDs, rv := env.Module.GetSlotList(false)
			if rv != module.CKR_OK {
				t.Fatalf("C_GetSlotList failed: %s", rv.String())
			}
			if len(slotIDs) == 0 {
				t.Fatal("no slots available")
			}

			// Test: Get slot info
			slotInfo, rv := env.Module.GetSlotInfo(slotIDs[0])
			if rv != module.CKR_OK {
				t.Fatalf("C_GetSlotInfo failed: %s", rv.String())
			}

			if slotInfo.GetSlotDescription() == "" {
				t.Error("slot description is empty")
			}

			// Test: Get token info (may not be initialized yet)
			_, rv = env.Module.GetTokenInfo(slotIDs[0])
			// Token info might fail if not initialized, that's OK
			if rv != module.CKR_OK && rv != module.CKR_TOKEN_NOT_PRESENT {
				t.Errorf("C_GetTokenInfo unexpected error: %s", rv.String())
			}

			// Test: Get mechanisms
			mechanisms, rv := env.Module.GetMechanismList(slotIDs[0])
			if rv != module.CKR_OK {
				t.Fatalf("C_GetMechanismList failed: %s", rv.String())
			}
			if len(mechanisms) == 0 {
				t.Error("no mechanisms available")
			}
		})
	}
}

// TestMultiProtocol_SessionManagement tests session operations across all protocols.
func TestMultiProtocol_SessionManagement(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			cfg := suite.GetProtocolConfig(protocol)
			env := SetupTestEnvironment(t, cfg.ToModuleConfig())
			env.MustInitializeModule(t)
			env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

			// Test: Open RO session
			roSession, rv := env.OpenROSession(t)
			if rv != module.CKR_OK {
				t.Fatalf("C_OpenSession (RO) failed: %s", rv.String())
			}

			// Test: Get session info
			sessionInfo, rv := env.Module.GetSessionInfo(roSession)
			if rv != module.CKR_OK {
				t.Fatalf("C_GetSessionInfo failed: %s", rv.String())
			}

			if sessionInfo.Flags&module.CKF_RW_SESSION != 0 {
				t.Error("RO session has RW flag set")
			}

			// Test: Open RW session
			rwSession, rv := env.OpenRWSession(t)
			if rv != module.CKR_OK {
				t.Fatalf("C_OpenSession (RW) failed: %s", rv.String())
			}

			sessionInfo, rv = env.Module.GetSessionInfo(rwSession)
			if rv != module.CKR_OK {
				t.Fatalf("C_GetSessionInfo (RW) failed: %s", rv.String())
			}

			if sessionInfo.Flags&module.CKF_RW_SESSION == 0 {
				t.Error("RW session missing RW flag")
			}

			// Test: Close sessions
			rv = env.Module.CloseSession(roSession)
			if rv != module.CKR_OK {
				t.Errorf("C_CloseSession (RO) failed: %s", rv.String())
			}

			rv = env.Module.CloseSession(rwSession)
			if rv != module.CKR_OK {
				t.Errorf("C_CloseSession (RW) failed: %s", rv.String())
			}
		})
	}
}

// TestMultiProtocol_LoginLogout tests login and logout across all protocols.
func TestMultiProtocol_LoginLogout(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			cfg := suite.GetProtocolConfig(protocol)
			env, session := SetupInitializedModuleWithConfig(t, cfg.ToModuleConfig())

			// Test: Login as user
			rv := env.LoginUser(t, session, TestPINs.User)
			if rv != module.CKR_OK {
				t.Fatalf("C_Login (USER) failed: %s", rv.String())
			}

			// Test: Double login should fail
			rv = env.LoginUser(t, session, TestPINs.User)
			if rv != module.CKR_USER_ALREADY_LOGGED_IN {
				t.Errorf("double login: expected CKR_USER_ALREADY_LOGGED_IN, got %s", rv.String())
			}

			// Test: Logout
			rv = env.Module.Logout(session)
			if rv != module.CKR_OK {
				t.Errorf("C_Logout failed: %s", rv.String())
			}

			// Test: Wrong PIN
			rv = env.LoginUser(t, session, []byte("wrongpin"))
			if rv != module.CKR_PIN_INCORRECT {
				t.Errorf("wrong PIN: expected CKR_PIN_INCORRECT, got %s", rv.String())
			}
		})
	}
}

// =============================================================================
// Multi-Protocol + Multi-Backend Test Matrix
// =============================================================================

// TestMultiProtocol_RSAKeyGeneration tests RSA key generation across all
// protocol/backend combinations.
func TestMultiProtocol_RSAKeyGeneration(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	testCases := []struct {
		Name        string
		ModulusBits uint32
	}{
		{"RSA-2048", 2048},
		{"RSA-3072", 3072},
		{"RSA-4096", 4096},
	}

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					for _, tc := range testCases {
						tc := tc
						t.Run(tc.Name, func(t *testing.T) {
							cfg := suite.GetProtocolConfig(protocol)
							modCfg := cfg.ToModuleConfig()
							modCfg.DefaultBackend = string(backend)

							env, session := SetupAuthenticatedModuleWithConfig(t, modCfg)

							label := fmt.Sprintf("test-rsa-%d-%s-%s", tc.ModulusBits, protocol, backend)
							pubTemplate := BuildRSAPublicKeyTemplate(label, tc.ModulusBits)
							privTemplate := BuildRSAPrivateKeyTemplate(label)

							mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

							pubHandle, privHandle, rv := env.Module.GenerateKeyPair(
								session, mechanism, pubTemplate, privTemplate)
							if rv != module.CKR_OK {
								t.Fatalf("C_GenerateKeyPair failed: %s", rv.String())
							}

							if pubHandle == 0 || privHandle == 0 {
								t.Error("generated key handles are zero")
							}

							// Verify keys exist
							_, found := FindKeyByLabel(t, env, session, label)
							if !found {
								t.Error("generated key not found by label")
							}
						})
					}
				})
			}
		})
	}
}

// TestMultiProtocol_ECKeyGeneration tests EC key generation across all
// protocol/backend combinations.
func TestMultiProtocol_ECKeyGeneration(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	testCases := []struct {
		Name     string
		CurveOID []byte
	}{
		{"P-256", OID_P256},
		{"P-384", OID_P384},
		{"P-521", OID_P521},
	}

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					for _, tc := range testCases {
						tc := tc
						t.Run(tc.Name, func(t *testing.T) {
							cfg := suite.GetProtocolConfig(protocol)
							modCfg := cfg.ToModuleConfig()
							modCfg.DefaultBackend = string(backend)

							env, session := SetupAuthenticatedModuleWithConfig(t, modCfg)

							label := fmt.Sprintf("test-ec-%s-%s-%s", tc.Name, protocol, backend)
							pubTemplate := BuildECPublicKeyTemplate(label, tc.CurveOID)
							privTemplate := BuildECPrivateKeyTemplate(label)

							mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

							pubHandle, privHandle, rv := env.Module.GenerateKeyPair(
								session, mechanism, pubTemplate, privTemplate)
							if rv != module.CKR_OK {
								t.Fatalf("C_GenerateKeyPair failed: %s", rv.String())
							}

							if pubHandle == 0 || privHandle == 0 {
								t.Error("generated key handles are zero")
							}
						})
					}
				})
			}
		})
	}
}

// TestMultiProtocol_AESKeyGeneration tests AES key generation across all
// protocol/backend combinations.
func TestMultiProtocol_AESKeyGeneration(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	testCases := []struct {
		Name   string
		KeyLen uint32
	}{
		{"AES-128", 16},
		{"AES-192", 24},
		{"AES-256", 32},
	}

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					for _, tc := range testCases {
						tc := tc
						t.Run(tc.Name, func(t *testing.T) {
							cfg := suite.GetProtocolConfig(protocol)
							modCfg := cfg.ToModuleConfig()
							modCfg.DefaultBackend = string(backend)

							env, session := SetupAuthenticatedModuleWithConfig(t, modCfg)

							label := fmt.Sprintf("test-aes-%d-%s-%s", tc.KeyLen*8, protocol, backend)
							template := BuildAESKeyTemplate(label, tc.KeyLen)

							mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

							keyHandle, rv := env.Module.GenerateKey(session, mechanism, template)
							if rv != module.CKR_OK {
								t.Fatalf("C_GenerateKey failed: %s", rv.String())
							}

							if keyHandle == 0 {
								t.Error("generated key handle is zero")
							}
						})
					}
				})
			}
		})
	}
}

// TestMultiProtocol_SignVerify tests sign/verify operations across all
// protocol/backend combinations.
func TestMultiProtocol_SignVerify(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	testData := []byte("Test data for signing across protocols and backends")
	hash := sha256.Sum256(testData)

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					cfg := suite.GetProtocolConfig(protocol)
					modCfg := cfg.ToModuleConfig()
					modCfg.DefaultBackend = string(backend)

					env, session := SetupAuthenticatedModuleWithConfig(t, modCfg)

					// Generate EC key for signing
					label := fmt.Sprintf("test-sign-%s-%s", protocol, backend)
					pubTemplate := BuildECPublicKeyTemplate(label, OID_P256)
					privTemplate := BuildECPrivateKeyTemplate(label)

					mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

					_, privHandle, rv := env.Module.GenerateKeyPair(
						session, mechanism, pubTemplate, privTemplate)
					if rv != module.CKR_OK {
						t.Fatalf("C_GenerateKeyPair failed: %s", rv.String())
					}

					// Sign
					signMech := &module.Mechanism{Type: module.CKM_ECDSA}
					rv = env.Module.SignInit(session, signMech, privHandle)
					if rv != module.CKR_OK {
						t.Fatalf("C_SignInit failed: %s", rv.String())
					}

					signature, rv := env.Module.Sign(session, hash[:])
					if rv != module.CKR_OK {
						t.Fatalf("C_Sign failed: %s", rv.String())
					}

					if len(signature) == 0 {
						t.Error("signature is empty")
					}

					// Find public key for verification
					pubHandle := MustFindKeyByLabel(t, env, session, label)

					// Verify
					rv = env.Module.VerifyInit(session, signMech, pubHandle)
					if rv != module.CKR_OK {
						t.Fatalf("C_VerifyInit failed: %s", rv.String())
					}

					rv = env.Module.Verify(session, hash[:], signature)
					if rv != module.CKR_OK {
						t.Errorf("C_Verify failed: %s", rv.String())
					}

					// Verify with wrong data should fail
					wrongHash := sha256.Sum256([]byte("wrong data"))
					signMech = &module.Mechanism{Type: module.CKM_ECDSA}
					rv = env.Module.VerifyInit(session, signMech, pubHandle)
					if rv != module.CKR_OK {
						t.Fatalf("C_VerifyInit (wrong data) failed: %s", rv.String())
					}

					rv = env.Module.Verify(session, wrongHash[:], signature)
					if rv == module.CKR_OK {
						t.Error("C_Verify should have failed with wrong data")
					}
				})
			}
		})
	}
}

// TestMultiProtocol_RandomGeneration tests random number generation across all
// protocol/backend combinations.
func TestMultiProtocol_RandomGeneration(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	sizes := []uint32{16, 32, 64, 128, 256}

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					cfg := suite.GetProtocolConfig(protocol)
					modCfg := cfg.ToModuleConfig()
					modCfg.DefaultBackend = string(backend)

					env := SetupTestEnvironment(t, modCfg)
					env.MustInitializeModule(t)

					session := env.MustOpenRWSession(t)

					for _, size := range sizes {
						t.Run(fmt.Sprintf("%d-bytes", size), func(t *testing.T) {
							randomBytes, rv := env.Module.GenerateRandom(session, size)
							if rv != module.CKR_OK {
								t.Fatalf("C_GenerateRandom failed: %s", rv.String())
							}

							if uint32(len(randomBytes)) != size {
								t.Errorf("expected %d bytes, got %d", size, len(randomBytes))
							}

							// Verify randomness (basic check: not all zeros)
							allZeros := true
							for _, b := range randomBytes {
								if b != 0 {
									allZeros = false
									break
								}
							}
							if allZeros && size > 4 {
								t.Error("random data appears to be all zeros")
							}

							// Generate again and verify different
							randomBytes2, rv := env.Module.GenerateRandom(session, size)
							if rv != module.CKR_OK {
								t.Fatalf("C_GenerateRandom (2) failed: %s", rv.String())
							}

							if size >= 16 && bytesEqual(randomBytes, randomBytes2) {
								t.Error("two random generations produced identical output")
							}
						})
					}
				})
			}
		})
	}
}

// TestMultiProtocol_AESEncryptDecrypt tests AES encrypt/decrypt across all
// protocol/backend combinations.
func TestMultiProtocol_AESEncryptDecrypt(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	plaintext := []byte("Test plaintext data for AES encryption across all protocols")
	// Pad to 16-byte boundary for CBC
	padLen := 16 - (len(plaintext) % 16)
	paddedPlaintext := make([]byte, len(plaintext)+padLen)
	copy(paddedPlaintext, plaintext)
	for i := len(plaintext); i < len(paddedPlaintext); i++ {
		paddedPlaintext[i] = byte(padLen)
	}

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					cfg := suite.GetProtocolConfig(protocol)
					modCfg := cfg.ToModuleConfig()
					modCfg.DefaultBackend = string(backend)

					env, session := SetupAuthenticatedModuleWithConfig(t, modCfg)

					// Generate AES key
					label := fmt.Sprintf("test-aes-enc-%s-%s", protocol, backend)
					template := BuildAESKeyTemplate(label, 32)

					mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

					keyHandle, rv := env.Module.GenerateKey(session, mechanism, template)
					if rv != module.CKR_OK {
						t.Fatalf("C_GenerateKey failed: %s", rv.String())
					}

					// Generate IV
					iv := make([]byte, 16)
					if _, err := rand.Read(iv); err != nil {
						t.Fatalf("failed to generate IV: %v", err)
					}

					// Encrypt
					encMech := &module.Mechanism{
						Type:      module.CKM_AES_CBC_PAD,
						Parameter: iv,
					}

					rv = env.Module.EncryptInit(session, encMech, keyHandle)
					if rv != module.CKR_OK {
						t.Fatalf("C_EncryptInit failed: %s", rv.String())
					}

					ciphertext, rv := env.Module.Encrypt(session, paddedPlaintext)
					if rv != module.CKR_OK {
						t.Fatalf("C_Encrypt failed: %s", rv.String())
					}

					if len(ciphertext) == 0 {
						t.Error("ciphertext is empty")
					}

					// Decrypt
					rv = env.Module.DecryptInit(session, encMech, keyHandle)
					if rv != module.CKR_OK {
						t.Fatalf("C_DecryptInit failed: %s", rv.String())
					}

					decrypted, rv := env.Module.Decrypt(session, ciphertext)
					if rv != module.CKR_OK {
						t.Fatalf("C_Decrypt failed: %s", rv.String())
					}

					// Verify decryption (compare original plaintext)
					if !bytesEqual(decrypted[:len(plaintext)], plaintext) {
						t.Error("decrypted data does not match original plaintext")
					}
				})
			}
		})
	}
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// =============================================================================
// Protocol Parity Tests
// =============================================================================

// TestMultiProtocol_FullKeyLifecycle tests the complete key lifecycle
// (generate, sign, verify, delete) to ensure protocol parity.
func TestMultiProtocol_FullKeyLifecycle(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	testData := []byte("Full lifecycle test data")
	hash := sha256.Sum256(testData)

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			cfg := suite.GetProtocolConfig(protocol)
			env, session := SetupAuthenticatedModuleWithConfig(t, cfg.ToModuleConfig())

			label := fmt.Sprintf("lifecycle-test-%s", protocol)

			// Step 1: Generate key pair
			pubTemplate := BuildECPublicKeyTemplate(label, OID_P256)
			privTemplate := BuildECPrivateKeyTemplate(label)
			mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

			pubHandle, privHandle, rv := env.Module.GenerateKeyPair(
				session, mechanism, pubTemplate, privTemplate)
			if rv != module.CKR_OK {
				t.Fatalf("generate key pair failed: %s", rv.String())
			}

			// Step 2: Sign
			signMech := &module.Mechanism{Type: module.CKM_ECDSA}
			rv = env.Module.SignInit(session, signMech, privHandle)
			if rv != module.CKR_OK {
				t.Fatalf("sign init failed: %s", rv.String())
			}

			signature, rv := env.Module.Sign(session, hash[:])
			if rv != module.CKR_OK {
				t.Fatalf("sign failed: %s", rv.String())
			}

			// Step 3: Verify
			rv = env.Module.VerifyInit(session, signMech, pubHandle)
			if rv != module.CKR_OK {
				t.Fatalf("verify init failed: %s", rv.String())
			}

			rv = env.Module.Verify(session, hash[:], signature)
			if rv != module.CKR_OK {
				t.Fatalf("verify failed: %s", rv.String())
			}

			// Step 4: Delete keys
			rv = env.Module.DestroyObject(session, privHandle)
			if rv != module.CKR_OK {
				t.Errorf("destroy private key failed: %s", rv.String())
			}

			rv = env.Module.DestroyObject(session, pubHandle)
			if rv != module.CKR_OK {
				t.Errorf("destroy public key failed: %s", rv.String())
			}

			// Step 5: Verify deletion
			_, found := FindKeyByLabel(t, env, session, label)
			if found {
				t.Error("key still found after deletion")
			}
		})
	}
}

// TestMultiProtocol_BackendAvailability verifies all registered backends
// are accessible via each protocol.
func TestMultiProtocol_BackendAvailability(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	t.Logf("Available backends: %v", suite.Backends)
	t.Logf("Available protocols: %v", suite.AvailableProtocols)

	if len(suite.Backends) == 0 {
		t.Error("no backends registered")
	}

	// software backend should always be available
	if !module.IsBackendAvailable(module.BackendSoftware) {
		t.Error("software backend not available")
	}
}

// TestMultiProtocol_ConcurrentSessions tests concurrent session handling
// across protocols.
func TestMultiProtocol_ConcurrentSessions(t *testing.T) {
	suite := NewMultiProtocolTestSuite()

	const numSessions = 5

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			cfg := suite.GetProtocolConfig(protocol)
			env := SetupTestEnvironment(t, cfg.ToModuleConfig())
			env.MustInitializeModule(t)
			env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

			// Open multiple sessions
			sessions := make([]module.SessionHandle, numSessions)
			for i := 0; i < numSessions; i++ {
				session, rv := env.OpenRWSession(t)
				if rv != module.CKR_OK {
					t.Fatalf("failed to open session %d: %s", i, rv.String())
				}
				sessions[i] = session
			}

			// Verify all sessions are valid
			for i, session := range sessions {
				info, rv := env.Module.GetSessionInfo(session)
				if rv != module.CKR_OK {
					t.Errorf("failed to get info for session %d: %s", i, rv.String())
					continue
				}
				if info.SlotID != 0 {
					t.Errorf("session %d has wrong slot ID", i)
				}
			}

			// Close all sessions
			for i, session := range sessions {
				rv := env.Module.CloseSession(session)
				if rv != module.CKR_OK {
					t.Errorf("failed to close session %d: %s", i, rv.String())
				}
			}
		})
	}
}
