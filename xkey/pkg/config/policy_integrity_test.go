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

package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPolicy returns a fully populated PolicySection for testing.
func testPolicy() *PolicySection {
	return &PolicySection{
		MinPINLength:               8,
		RequireSOPIN:               true,
		RequireUserPIN:             true,
		RequireEncryptedStorage:    true,
		StorageType:                "barrier",
		AllowedBackends:            []string{"tpm2", "pkcs11"},
		DefaultBackend:             "tpm2",
		UserCanChangeOwnPIN:        true,
		UserCanConfigureAutoUnseal: false,
		OrganizationName:           "Test Corp",
		PolicyVersion:              1,
	}
}

// testSalt returns a fixed 16-byte salt for deterministic testing.
func testSalt() []byte {
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
}

// --- IsEnterpriseMode ---

func TestIsEnterpriseMode_WithHMACFile(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, hmacFileName)
	require.NoError(t, os.WriteFile(hmacPath, []byte(`{"version":1}`), 0600))

	result := IsEnterpriseMode(dir)
	assert.True(t, result)
}

func TestIsEnterpriseMode_WithoutHMACFile(t *testing.T) {
	dir := t.TempDir()

	result := IsEnterpriseMode(dir)
	assert.False(t, result)
}

func TestIsEnterpriseMode_WithEmptyHMACFile(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, hmacFileName)
	require.NoError(t, os.WriteFile(hmacPath, []byte{}, 0600))

	// IsEnterpriseMode only checks file existence, not content.
	result := IsEnterpriseMode(dir)
	assert.True(t, result)
}

// --- PolicyHMACPath ---

func TestPolicyHMACPath(t *testing.T) {
	dir := "/some/config/dir"
	expected := filepath.Join(dir, "xkey_policy.hmac")
	assert.Equal(t, expected, PolicyHMACPath(dir))
}

// --- ComputePolicyHMAC ---

func TestComputePolicyHMAC_Valid(t *testing.T) {
	policy := testPolicy()
	salt := testSalt()

	mac, err := ComputePolicyHMAC(policy, "test-so-pin", salt)
	require.NoError(t, err)
	assert.NotNil(t, mac)
	assert.Len(t, mac, 32, "HMAC-SHA256 produces a 32-byte tag")
}

func TestComputePolicyHMAC_Deterministic(t *testing.T) {
	policy := testPolicy()
	salt := testSalt()
	pin := "deterministic-pin"

	mac1, err := ComputePolicyHMAC(policy, pin, salt)
	require.NoError(t, err)

	mac2, err := ComputePolicyHMAC(policy, pin, salt)
	require.NoError(t, err)

	assert.Equal(t, mac1, mac2, "identical inputs must produce identical HMACs")
}

func TestComputePolicyHMAC_DifferentPINProducesDifferentHMAC(t *testing.T) {
	policy := testPolicy()
	salt := testSalt()

	mac1, err := ComputePolicyHMAC(policy, "pin-alpha", salt)
	require.NoError(t, err)

	mac2, err := ComputePolicyHMAC(policy, "pin-bravo", salt)
	require.NoError(t, err)

	assert.NotEqual(t, mac1, mac2,
		"different SO PINs with same policy and salt must produce different HMACs")
}

func TestComputePolicyHMAC_DifferentSaltProducesDifferentHMAC(t *testing.T) {
	policy := testPolicy()
	pin := "same-pin"

	salt1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	salt2 := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
		0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0}

	mac1, err := ComputePolicyHMAC(policy, pin, salt1)
	require.NoError(t, err)

	mac2, err := ComputePolicyHMAC(policy, pin, salt2)
	require.NoError(t, err)

	assert.NotEqual(t, mac1, mac2,
		"different salts with same policy and PIN must produce different HMACs")
}

func TestComputePolicyHMAC_DifferentPolicyProducesDifferentHMAC(t *testing.T) {
	salt := testSalt()
	pin := "same-pin"

	policy1 := testPolicy()
	policy1.MinPINLength = 6

	policy2 := testPolicy()
	policy2.MinPINLength = 12

	mac1, err := ComputePolicyHMAC(policy1, pin, salt)
	require.NoError(t, err)

	mac2, err := ComputePolicyHMAC(policy2, pin, salt)
	require.NoError(t, err)

	assert.NotEqual(t, mac1, mac2,
		"different policy fields with same PIN and salt must produce different HMACs")
}

func TestComputePolicyHMAC_NilPolicy(t *testing.T) {
	salt := testSalt()

	mac, err := ComputePolicyHMAC(nil, "some-pin", salt)
	assert.Nil(t, mac)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyInvalid))
}

func TestComputePolicyHMAC_EmptyPIN(t *testing.T) {
	policy := testPolicy()
	salt := testSalt()

	mac, err := ComputePolicyHMAC(policy, "", salt)
	assert.Nil(t, mac)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicySOPINRequired))
}

func TestComputePolicyHMAC_EmptySalt(t *testing.T) {
	policy := testPolicy()

	mac, err := ComputePolicyHMAC(policy, "some-pin", []byte{})
	assert.Nil(t, mac)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyKeyDerivationFailed))
}

// --- WritePolicyHMAC + LoadPolicyHMAC + VerifyPolicyHMAC roundtrip ---

func TestWriteAndLoadPolicyHMAC_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)
	policy := testPolicy()
	pin := "roundtrip-pin"

	err := WritePolicyHMAC(policy, pin, hmacPath)
	require.NoError(t, err)

	loaded, err := LoadPolicyHMAC(hmacPath)
	require.NoError(t, err)

	assert.Equal(t, 1, loaded.Version)
	assert.Equal(t, "HMAC-SHA256", loaded.Algorithm)
	assert.NotEmpty(t, loaded.Salt, "salt must be populated")
	assert.NotEmpty(t, loaded.HMAC, "HMAC must be populated")
	assert.Len(t, loaded.HMAC, 32, "HMAC-SHA256 tag is 32 bytes")
}

func TestWriteAndVerifyPolicyHMAC_ValidPIN(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)
	policy := testPolicy()
	pin := "correct-pin"

	err := WritePolicyHMAC(policy, pin, hmacPath)
	require.NoError(t, err)

	valid, err := VerifyPolicyHMAC(policy, hmacPath, pin)
	require.NoError(t, err)
	assert.True(t, valid, "verification with the same PIN and policy must succeed")
}

func TestWriteAndVerifyPolicyHMAC_WrongPIN(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)
	policy := testPolicy()

	err := WritePolicyHMAC(policy, "correct", hmacPath)
	require.NoError(t, err)

	valid, err := VerifyPolicyHMAC(policy, hmacPath, "wrong")
	require.NoError(t, err)
	assert.False(t, valid, "verification with a wrong PIN must fail")
}

func TestWriteAndVerifyPolicyHMAC_TamperedPolicy(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)
	policy := testPolicy()
	pin := "tamper-test-pin"

	err := WritePolicyHMAC(policy, pin, hmacPath)
	require.NoError(t, err)

	// Tamper with the policy after writing.
	policy.MinPINLength = 99
	policy.OrganizationName = "Evil Corp"

	valid, err := VerifyPolicyHMAC(policy, hmacPath, pin)
	require.NoError(t, err)
	assert.False(t, valid, "tampered policy must fail HMAC verification")
}

func TestWritePolicyHMAC_NilPolicy(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)

	err := WritePolicyHMAC(nil, "some-pin", hmacPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACSaveFailed))
}

func TestWritePolicyHMAC_EmptyPIN(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)
	policy := testPolicy()

	err := WritePolicyHMAC(policy, "", hmacPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicySOPINRequired))
}

func TestWritePolicyHMAC_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deeply", "nested", "config")
	hmacPath := PolicyHMACPath(nested)
	policy := testPolicy()

	err := WritePolicyHMAC(policy, "create-dir-pin", hmacPath)
	require.NoError(t, err)

	info, err := os.Stat(hmacPath)
	require.NoError(t, err)
	assert.False(t, info.IsDir())
}

func TestWritePolicyHMAC_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)
	policy := testPolicy()

	err := WritePolicyHMAC(policy, "permissions-pin", hmacPath)
	require.NoError(t, err)

	info, err := os.Stat(hmacPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"HMAC file must have 0600 permissions")
}

// --- LoadPolicyHMAC ---

func TestLoadPolicyHMAC_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, "nonexistent.hmac")

	loaded, err := LoadPolicyHMAC(hmacPath)
	assert.Nil(t, loaded)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACMissing))
}

func TestLoadPolicyHMAC_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, hmacFileName)
	require.NoError(t, os.WriteFile(hmacPath, []byte("not valid json{{{"), 0600))

	loaded, err := LoadPolicyHMAC(hmacPath)
	assert.Nil(t, loaded)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACLoadFailed))
}

func TestLoadPolicyHMAC_ZeroVersion(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, hmacFileName)

	record := &PolicyHMAC{
		Version:   0,
		Algorithm: hmacAlgorithm,
		Salt:      testSalt(),
		HMAC:      []byte{0xaa, 0xbb},
	}
	data, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hmacPath, data, 0600))

	loaded, err := LoadPolicyHMAC(hmacPath)
	assert.Nil(t, loaded)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACLoadFailed))
}

func TestLoadPolicyHMAC_EmptySalt(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, hmacFileName)

	record := &PolicyHMAC{
		Version:   1,
		Algorithm: hmacAlgorithm,
		Salt:      []byte{},
		HMAC:      []byte{0xaa, 0xbb},
	}
	data, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hmacPath, data, 0600))

	loaded, err := LoadPolicyHMAC(hmacPath)
	assert.Nil(t, loaded)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACLoadFailed))
}

func TestLoadPolicyHMAC_EmptyHMAC(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, hmacFileName)

	record := &PolicyHMAC{
		Version:   1,
		Algorithm: hmacAlgorithm,
		Salt:      testSalt(),
		HMAC:      []byte{},
	}
	data, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hmacPath, data, 0600))

	loaded, err := LoadPolicyHMAC(hmacPath)
	assert.Nil(t, loaded)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACLoadFailed))
}

// --- VerifyPolicyHMAC error paths ---

func TestVerifyPolicyHMAC_NilPolicy(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)

	valid, err := VerifyPolicyHMAC(nil, hmacPath, "some-pin")
	assert.False(t, valid)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyInvalid))
}

func TestVerifyPolicyHMAC_EmptyPIN(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)
	policy := testPolicy()

	valid, err := VerifyPolicyHMAC(policy, hmacPath, "")
	assert.False(t, valid)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicySOPINRequired))
}

func TestVerifyPolicyHMAC_MissingHMACFile(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, "does-not-exist.hmac")
	policy := testPolicy()

	valid, err := VerifyPolicyHMAC(policy, hmacPath, "some-pin")
	assert.False(t, valid)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACMissing))
}

// --- deriveHMACKey (unexported) ---

func TestDeriveHMACKey_Valid(t *testing.T) {
	salt := testSalt()

	key, err := deriveHMACKey("valid-pin", salt)
	require.NoError(t, err)
	assert.Len(t, key, 32, "derived key must be 32 bytes")
}

func TestDeriveHMACKey_Deterministic(t *testing.T) {
	salt := testSalt()
	pin := "deterministic"

	key1, err := deriveHMACKey(pin, salt)
	require.NoError(t, err)

	key2, err := deriveHMACKey(pin, salt)
	require.NoError(t, err)

	assert.Equal(t, key1, key2, "identical inputs must produce identical keys")
}

func TestDeriveHMACKey_EmptyPIN(t *testing.T) {
	salt := testSalt()

	key, err := deriveHMACKey("", salt)
	assert.Nil(t, key)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyKeyDerivationFailed))
}

func TestDeriveHMACKey_EmptySalt(t *testing.T) {
	key, err := deriveHMACKey("valid-pin", []byte{})
	assert.Nil(t, key)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyKeyDerivationFailed))
}

// --------------------------------------------------------------------------
// WritePolicyHMAC error path tests
// --------------------------------------------------------------------------

// TestWritePolicyHMAC_DirectoryCreationFailure verifies that WritePolicyHMAC
// returns ErrPolicyHMACSaveFailed when the directory cannot be created (file
// exists where directory is needed).
func TestWritePolicyHMAC_DirectoryCreationFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a regular file where MkdirAll expects a directory.
	blocker := filepath.Join(tmpDir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a dir"), 0600))

	hmacPath := filepath.Join(blocker, "nested", hmacFileName)
	policy := testPolicy()

	err := WritePolicyHMAC(policy, "some-pin", hmacPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACSaveFailed),
		"expected ErrPolicyHMACSaveFailed, got %v", err)
}

// TestWritePolicyHMAC_ReadOnlyDirectory verifies that WritePolicyHMAC returns
// ErrPolicyHMACSaveFailed when it cannot create a temp file in a read-only
// directory.
func TestWritePolicyHMAC_ReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("read-only directory test only reliable on Linux")
	}
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user for permission checks")
	}

	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	require.NoError(t, os.MkdirAll(readOnlyDir, 0500))

	t.Cleanup(func() {
		os.Chmod(readOnlyDir, 0700)
	})

	hmacPath := filepath.Join(readOnlyDir, hmacFileName)
	policy := testPolicy()

	err := WritePolicyHMAC(policy, "some-pin", hmacPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACSaveFailed),
		"expected ErrPolicyHMACSaveFailed for read-only directory, got %v", err)
}

// TestWritePolicyHMAC_OverwriteExisting verifies that WritePolicyHMAC can
// overwrite an existing HMAC file with a new salt and tag.
func TestWritePolicyHMAC_OverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	hmacPath := PolicyHMACPath(dir)
	policy := testPolicy()

	// Write once.
	err := WritePolicyHMAC(policy, "first-pin", hmacPath)
	require.NoError(t, err)

	first, err := LoadPolicyHMAC(hmacPath)
	require.NoError(t, err)

	// Write again with a different PIN; salt and HMAC should change.
	err = WritePolicyHMAC(policy, "second-pin", hmacPath)
	require.NoError(t, err)

	second, err := LoadPolicyHMAC(hmacPath)
	require.NoError(t, err)

	// The salt is randomly generated on each write, so it should differ.
	assert.NotEqual(t, first.Salt, second.Salt,
		"overwritten HMAC file should have a new salt")
	assert.NotEqual(t, first.HMAC, second.HMAC,
		"overwritten HMAC file should have a new HMAC tag")
}

// TestLoadPolicyHMAC_ReadPermissionError verifies that LoadPolicyHMAC returns
// ErrPolicyHMACLoadFailed when the file exists but cannot be read.
func TestLoadPolicyHMAC_ReadPermissionError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("permission test only reliable on Linux")
	}
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user for permission checks")
	}

	dir := t.TempDir()
	hmacPath := filepath.Join(dir, hmacFileName)

	// Write a valid HMAC file, then remove read permissions.
	require.NoError(t, os.WriteFile(hmacPath, []byte(`{"version":1}`), 0000))
	t.Cleanup(func() {
		os.Chmod(hmacPath, 0600)
	})

	loaded, err := LoadPolicyHMAC(hmacPath)
	assert.Nil(t, loaded)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACLoadFailed),
		"expected ErrPolicyHMACLoadFailed, got %v", err)
}

// TestLoadPolicyHMAC_NilSaltInFile verifies that LoadPolicyHMAC rejects
// a file with a null salt field (JSON null marshals as nil slice).
func TestLoadPolicyHMAC_NilSaltInFile(t *testing.T) {
	dir := t.TempDir()
	hmacPath := filepath.Join(dir, hmacFileName)

	// Manually construct JSON with null salt.
	jsonData := `{"version":1,"algorithm":"HMAC-SHA256","salt":null,"hmac":"AQID"}`
	require.NoError(t, os.WriteFile(hmacPath, []byte(jsonData), 0600))

	loaded, err := LoadPolicyHMAC(hmacPath)
	assert.Nil(t, loaded)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyHMACLoadFailed),
		"expected ErrPolicyHMACLoadFailed for null salt, got %v", err)
}
