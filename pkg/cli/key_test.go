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

package cli

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestKeyCmd_Exists(t *testing.T) {
	if keyCmd == nil {
		t.Fatal("keyCmd should not be nil")
	}
}

func TestKeyCmd_Properties(t *testing.T) {
	if keyCmd.Use != "key" {
		t.Errorf("keyCmd.Use = %v, want key", keyCmd.Use)
	}

	if keyCmd.Short == "" {
		t.Error("keyCmd.Short should not be empty")
	}
}

func TestKeyCmd_HasSubcommands(t *testing.T) {
	subcommands := keyCmd.Commands()

	expectedCmds := []string{
		"generate",
		"list",
		"get",
		"delete",
		"sign",
		"rotate",
		"encrypt",
		"decrypt",
		"import",
		"export",
		"copy",
		"verify",
	}
	foundCmds := make(map[string]bool)

	for _, cmd := range subcommands {
		foundCmds[cmd.Name()] = true
	}

	for _, expected := range expectedCmds {
		if !foundCmds[expected] {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestKeyGenerateCmd_Exists(t *testing.T) {
	if keyGenerateCmd == nil {
		t.Fatal("keyGenerateCmd should not be nil")
	}
}

func TestKeyGenerateCmd_Properties(t *testing.T) {
	if keyGenerateCmd.Use != "generate <key-id>" {
		t.Errorf("keyGenerateCmd.Use = %v, want 'generate <key-id>'", keyGenerateCmd.Use)
	}
}

func TestKeyListCmd_Exists(t *testing.T) {
	if keyListCmd == nil {
		t.Fatal("keyListCmd should not be nil")
	}
}

func TestKeyGetCmd_Exists(t *testing.T) {
	if keyGetCmd == nil {
		t.Fatal("keyGetCmd should not be nil")
	}
}

func TestKeyDeleteCmd_Exists(t *testing.T) {
	if keyDeleteCmd == nil {
		t.Fatal("keyDeleteCmd should not be nil")
	}
}

func TestKeySignCmd_Exists(t *testing.T) {
	if keySignCmd == nil {
		t.Fatal("keySignCmd should not be nil")
	}
}

func TestKeyRotateCmd_Exists(t *testing.T) {
	if keyRotateCmd == nil {
		t.Fatal("keyRotateCmd should not be nil")
	}
}

func TestKeyEncryptCmd_Exists(t *testing.T) {
	if keyEncryptCmd == nil {
		t.Fatal("keyEncryptCmd should not be nil")
	}
}

func TestKeyDecryptCmd_Exists(t *testing.T) {
	if keyDecryptCmd == nil {
		t.Fatal("keyDecryptCmd should not be nil")
	}
}

func TestKeyImportCmd_Exists(t *testing.T) {
	if keyImportCmd == nil {
		t.Fatal("keyImportCmd should not be nil")
	}
}

func TestKeyExportCmd_Exists(t *testing.T) {
	if keyExportCmd == nil {
		t.Fatal("keyExportCmd should not be nil")
	}
}

func TestKeyCopyCmd_Exists(t *testing.T) {
	if keyCopyCmd == nil {
		t.Fatal("keyCopyCmd should not be nil")
	}
}

func TestKeyVerifyCmd_Exists(t *testing.T) {
	if keyVerifyCmd == nil {
		t.Fatal("keyVerifyCmd should not be nil")
	}
}

func TestBuildKeyAttributesFromFlags_RSA(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 2048, "", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.CN != "test-key" {
		t.Errorf("CN = %v, want test-key", attrs.CN)
	}
	if attrs.KeyAlgorithm != x509.RSA {
		t.Errorf("KeyAlgorithm = %v, want RSA", attrs.KeyAlgorithm)
	}
	if attrs.RSAAttributes == nil {
		t.Error("RSAAttributes should not be nil for RSA key")
	}
	if attrs.RSAAttributes.KeySize != 2048 {
		t.Errorf("RSAAttributes.KeySize = %v, want 2048", attrs.RSAAttributes.KeySize)
	}
	if attrs.Exportable {
		t.Error("Exportable should be false when not specified")
	}
}

func TestBuildKeyAttributesFromFlags_RSA_Exportable(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 2048, "", true)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if !attrs.Exportable {
		t.Error("Exportable should be true when specified")
	}
}

func TestBuildKeyAttributesFromFlags_ECDSA(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, "P-256", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.KeyAlgorithm != x509.ECDSA {
		t.Errorf("KeyAlgorithm = %v, want ECDSA", attrs.KeyAlgorithm)
	}
	if attrs.ECCAttributes == nil {
		t.Error("ECCAttributes should not be nil for ECDSA key")
	}
	if attrs.KeyType != types.KeyTypeSigning {
		t.Errorf("KeyType = %v, want KeyTypeSigning", attrs.KeyType)
	}
}

func TestBuildKeyAttributesFromFlags_ECDSA_P384(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, "P-384", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.ECCAttributes == nil {
		t.Error("ECCAttributes should not be nil for ECDSA key")
	}
}

func TestBuildKeyAttributesFromFlags_ECDSA_P521(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, "P-521", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.ECCAttributes == nil {
		t.Error("ECCAttributes should not be nil for ECDSA key")
	}
}

func TestBuildKeyAttributesFromFlags_Ed25519(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ed25519", 0, "", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.KeyAlgorithm != x509.Ed25519 {
		t.Errorf("KeyAlgorithm = %v, want Ed25519", attrs.KeyAlgorithm)
	}
}

func TestBuildKeyAttributesFromFlags_InvalidKeyType(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "invalid-type", "rsa", 2048, "", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for invalid key type")
	}
}

func TestBuildKeyAttributesFromFlags_InvalidAlgorithm(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "tls", "invalid-alg", 2048, "", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for invalid algorithm")
	}
}

func TestBuildKeyAttributesFromFlags_RSA_SmallKeySize(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 1024, "", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for RSA key size < 2048")
	}
}

func TestBuildKeyAttributesFromFlags_InvalidCurve(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, "invalid-curve", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for invalid curve")
	}
}

func TestBuildSymmetricKeyAttributes_AES128(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", "", 128)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes returned error: %v", err)
	}

	if attrs.CN != "test-key" {
		t.Errorf("CN = %v, want test-key", attrs.CN)
	}
	if attrs.KeyType != types.KeyTypeSecret {
		t.Errorf("KeyType = %v, want KeyTypeSecret", attrs.KeyType)
	}
	if attrs.SymmetricAlgorithm != types.SymmetricAES128GCM {
		t.Errorf("SymmetricAlgorithm = %v, want AES-128-GCM", attrs.SymmetricAlgorithm)
	}
}

func TestBuildSymmetricKeyAttributes_AES192(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", "", 192)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes returned error: %v", err)
	}

	if attrs.SymmetricAlgorithm != types.SymmetricAES192GCM {
		t.Errorf("SymmetricAlgorithm = %v, want AES-192-GCM", attrs.SymmetricAlgorithm)
	}
}

func TestBuildSymmetricKeyAttributes_AES256(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", "", 256)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes returned error: %v", err)
	}

	if attrs.SymmetricAlgorithm != types.SymmetricAES256GCM {
		t.Errorf("SymmetricAlgorithm = %v, want AES-256-GCM", attrs.SymmetricAlgorithm)
	}
}

func TestBuildSymmetricKeyAttributes_InvalidKeySize(t *testing.T) {
	_, err := buildSymmetricKeyAttributes("test-key", "", 64)
	if err == nil {
		t.Error("buildSymmetricKeyAttributes should return error for invalid key size")
	}
}

func TestBuildSymmetricKeyAttributes_WithAlgorithm(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", string(types.SymmetricAES256GCM), 0)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes returned error: %v", err)
	}

	if attrs.SymmetricAlgorithm != types.SymmetricAES256GCM {
		t.Errorf("SymmetricAlgorithm = %v, want AES-256-GCM", attrs.SymmetricAlgorithm)
	}
}

func TestBuildSymmetricKeyAttributes_InvalidAlgorithm(t *testing.T) {
	_, err := buildSymmetricKeyAttributes("test-key", "invalid-algorithm", 0)
	if err == nil {
		t.Error("buildSymmetricKeyAttributes should return error for invalid algorithm")
	}
}

func TestIsSymmetricAlgorithm_Valid(t *testing.T) {
	validAlgorithms := []string{
		string(types.SymmetricAES128GCM),
		string(types.SymmetricAES192GCM),
		string(types.SymmetricAES256GCM),
	}

	for _, alg := range validAlgorithms {
		t.Run(alg, func(t *testing.T) {
			if !isSymmetricAlgorithm(alg) {
				t.Errorf("isSymmetricAlgorithm(%s) = false, want true", alg)
			}
		})
	}
}

func TestIsSymmetricAlgorithm_Invalid(t *testing.T) {
	invalidAlgorithms := []string{
		"rsa",
		"ecdsa",
		"ed25519",
		"invalid",
		"",
	}

	for _, alg := range invalidAlgorithms {
		t.Run(alg, func(t *testing.T) {
			if isSymmetricAlgorithm(alg) {
				t.Errorf("isSymmetricAlgorithm(%s) = true, want false", alg)
			}
		})
	}
}

func TestKeyGenerateCmd_HasFlags(t *testing.T) {
	flags := keyGenerateCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"algorithm",
		"key-algorithm",
		"key-size",
		"curve",
		"exportable",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyGenerateCmd", flag)
		}
	}
}

func TestKeySignCmd_HasFlags(t *testing.T) {
	flags := keySignCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
		"hash",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keySignCmd", flag)
		}
	}
}

func TestKeyEncryptCmd_HasFlags(t *testing.T) {
	flags := keyEncryptCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"key-algorithm",
		"key-size",
		"aad",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyEncryptCmd", flag)
		}
	}
}

func TestKeyDecryptCmd_HasFlags(t *testing.T) {
	flags := keyDecryptCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
		"hash",
		"aad",
		"nonce",
		"tag",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyDecryptCmd", flag)
		}
	}
}

func TestKeyImportCmd_HasFlags(t *testing.T) {
	flags := keyImportCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyImportCmd", flag)
		}
	}
}

func TestKeyExportCmd_HasFlags(t *testing.T) {
	flags := keyExportCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
		"algorithm",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyExportCmd", flag)
		}
	}
}

func TestKeyCopyCmd_HasFlags(t *testing.T) {
	flags := keyCopyCmd.Flags()

	expectedFlags := []string{
		"dest-backend",
		"dest-keydir",
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
		"algorithm",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyCopyCmd", flag)
		}
	}
}

func TestKeyVerifyCmd_HasFlags(t *testing.T) {
	flags := keyVerifyCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
		"hash",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyVerifyCmd", flag)
		}
	}
}

func TestBuildKeyAttributesFromFlags_AllKeyTypes(t *testing.T) {
	keyTypes := []string{"tls", "signing", "encryption", "ca"}

	for _, kt := range keyTypes {
		t.Run(kt, func(t *testing.T) {
			attrs, err := buildKeyAttributesFromFlags("test-key", kt, "rsa", 2048, "", false)
			if err != nil {
				t.Errorf("buildKeyAttributesFromFlags(%s) returned error: %v", kt, err)
			}
			if attrs == nil {
				t.Errorf("buildKeyAttributesFromFlags(%s) returned nil attrs", kt)
			}
		})
	}
}

func TestBuildKeyAttributesFromFlags_RSA_4096(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 4096, "", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.RSAAttributes.KeySize != 4096 {
		t.Errorf("RSAAttributes.KeySize = %v, want 4096", attrs.RSAAttributes.KeySize)
	}
}
