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

package pin

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// fastArgon2idConfig returns an Argon2id config with minimal parameters
// for fast unit test execution.
func fastArgon2idConfig() HashConfig {
	return HashConfig{
		Algorithm: HashArgon2id,
		Time:      1,
		Memory:    1024,
		Threads:   1,
		KeyLen:    32,
		SaltLen:   16,
	}
}

// fastPBKDF2Config returns a PBKDF2-SHA256 config with minimal iterations
// for fast unit test execution.
func fastPBKDF2Config() HashConfig {
	return HashConfig{
		Algorithm:  HashPBKDF2,
		PBKDF2Hash: types.HashSHA256,
		Iterations: 1000,
		KeyLen:     32,
		SaltLen:    16,
	}
}

func TestDefaultHashConfig(t *testing.T) {
	cfg := DefaultHashConfig()
	if cfg.Algorithm != HashArgon2id {
		t.Fatalf("expected algorithm %s, got %s", HashArgon2id, cfg.Algorithm)
	}
	if cfg.Time != 3 {
		t.Fatalf("expected Time=3, got %d", cfg.Time)
	}
	if cfg.Memory != 64*1024 {
		t.Fatalf("expected Memory=65536, got %d", cfg.Memory)
	}
	if cfg.Threads != 4 {
		t.Fatalf("expected Threads=4, got %d", cfg.Threads)
	}
	if cfg.KeyLen != 32 {
		t.Fatalf("expected KeyLen=32, got %d", cfg.KeyLen)
	}
	if cfg.SaltLen != 16 {
		t.Fatalf("expected SaltLen=16, got %d", cfg.SaltLen)
	}
}

func TestDefaultHashConfigIsArgon2id(t *testing.T) {
	cfg := DefaultHashConfig()
	if cfg.Algorithm != HashArgon2id {
		t.Fatalf("default config must use Argon2id, got %s", cfg.Algorithm)
	}
	// PBKDF2 fields should be zero-valued.
	if cfg.PBKDF2Hash != "" {
		t.Fatalf("expected empty PBKDF2Hash, got %s", cfg.PBKDF2Hash)
	}
	if cfg.Iterations != 0 {
		t.Fatalf("expected Iterations=0, got %d", cfg.Iterations)
	}
}

func TestFIPSHashConfig(t *testing.T) {
	cfg := FIPSHashConfig()
	if cfg.Algorithm != HashPBKDF2 {
		t.Fatalf("expected algorithm %s, got %s", HashPBKDF2, cfg.Algorithm)
	}
	if cfg.PBKDF2Hash != types.HashSHA256 {
		t.Fatalf("expected PBKDF2Hash=%s, got %s", types.HashSHA256, cfg.PBKDF2Hash)
	}
	if cfg.Iterations != 600000 {
		t.Fatalf("expected Iterations=600000, got %d", cfg.Iterations)
	}
	if cfg.KeyLen != 32 {
		t.Fatalf("expected KeyLen=32, got %d", cfg.KeyLen)
	}
	if cfg.SaltLen != 16 {
		t.Fatalf("expected SaltLen=16, got %d", cfg.SaltLen)
	}
}

func TestFIPSHashConfigIsPBKDF2(t *testing.T) {
	cfg := FIPSHashConfig()
	if cfg.Algorithm != HashPBKDF2 {
		t.Fatalf("FIPS config must use PBKDF2, got %s", cfg.Algorithm)
	}
	// Argon2id fields should be zero-valued.
	if cfg.Time != 0 {
		t.Fatalf("expected Time=0, got %d", cfg.Time)
	}
	if cfg.Memory != 0 {
		t.Fatalf("expected Memory=0, got %d", cfg.Memory)
	}
	if cfg.Threads != 0 {
		t.Fatalf("expected Threads=0, got %d", cfg.Threads)
	}
}

func TestAutoDetectHashConfigDoesNotPanic(t *testing.T) {
	// AutoDetectHashConfig depends on runtime FIPS detection.
	// We verify it returns a valid config without panicking.
	cfg := AutoDetectHashConfig()
	if cfg.Algorithm != HashArgon2id && cfg.Algorithm != HashPBKDF2 {
		t.Fatalf("expected argon2id or pbkdf2, got %s", cfg.Algorithm)
	}
	if cfg.SaltLen == 0 {
		t.Fatal("expected non-zero SaltLen")
	}
	if cfg.KeyLen == 0 {
		t.Fatal("expected non-zero KeyLen")
	}
}

func TestAutoDetectHashConfigReturnsConsistently(t *testing.T) {
	cfg1 := AutoDetectHashConfig()
	cfg2 := AutoDetectHashConfig()
	if cfg1.Algorithm != cfg2.Algorithm {
		t.Fatalf("consecutive calls returned different algorithms: %s vs %s",
			cfg1.Algorithm, cfg2.Algorithm)
	}
}

func TestHashPINWithConfigArgon2id(t *testing.T) {
	cfg := fastArgon2idConfig()
	record, err := hashPINWithConfig("test-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	if record.Algorithm != string(HashArgon2id) {
		t.Fatalf("expected algorithm %s, got %s", HashArgon2id, record.Algorithm)
	}
	if len(record.Hash) != int(cfg.KeyLen) {
		t.Fatalf("expected hash length %d, got %d", cfg.KeyLen, len(record.Hash))
	}
	if len(record.Salt) != cfg.SaltLen {
		t.Fatalf("expected salt length %d, got %d", cfg.SaltLen, len(record.Salt))
	}
	if record.Params == nil {
		t.Fatal("expected non-nil Params")
	}

	// Verify params deserialize correctly.
	var p argon2idParams
	if err := json.Unmarshal(record.Params, &p); err != nil {
		t.Fatalf("failed to unmarshal argon2id params: %v", err)
	}
	if p.Time != cfg.Time || p.Memory != cfg.Memory || p.Threads != cfg.Threads || p.KeyLen != cfg.KeyLen {
		t.Fatalf("params mismatch: got %+v", p)
	}
}

func TestHashPINWithConfigPBKDF2(t *testing.T) {
	cfg := fastPBKDF2Config()
	record, err := hashPINWithConfig("test-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	if record.Algorithm != string(HashPBKDF2) {
		t.Fatalf("expected algorithm %s, got %s", HashPBKDF2, record.Algorithm)
	}
	if len(record.Hash) != int(cfg.KeyLen) {
		t.Fatalf("expected hash length %d, got %d", cfg.KeyLen, len(record.Hash))
	}
	if len(record.Salt) != cfg.SaltLen {
		t.Fatalf("expected salt length %d, got %d", cfg.SaltLen, len(record.Salt))
	}

	// Verify params deserialize correctly.
	var p pbkdf2Params
	if err := json.Unmarshal(record.Params, &p); err != nil {
		t.Fatalf("failed to unmarshal pbkdf2 params: %v", err)
	}
	if p.Hash != string(types.HashSHA256) {
		t.Fatalf("expected hash %s, got %s", types.HashSHA256, p.Hash)
	}
	if p.Iterations != cfg.Iterations {
		t.Fatalf("expected iterations %d, got %d", cfg.Iterations, p.Iterations)
	}
	if p.KeyLen != cfg.KeyLen {
		t.Fatalf("expected key_len %d, got %d", cfg.KeyLen, p.KeyLen)
	}
}

func TestHashPINWithConfigUnsupportedAlgorithm(t *testing.T) {
	cfg := HashConfig{
		Algorithm: HashAlgorithm("scrypt"),
		SaltLen:   16,
		KeyLen:    32,
	}
	_, err := hashPINWithConfig("test-pin", cfg)
	if !errors.Is(err, ErrUnsupportedHashAlgorithm) {
		t.Fatalf("expected ErrUnsupportedHashAlgorithm, got %v", err)
	}
}

func TestHashPINWithConfigProducesDifferentSalts(t *testing.T) {
	cfg := fastArgon2idConfig()
	r1, err := hashPINWithConfig("same-pin", cfg)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}
	r2, err := hashPINWithConfig("same-pin", cfg)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}
	if bytes.Equal(r1.Salt, r2.Salt) {
		t.Fatal("hashing the same PIN twice must produce different salts")
	}
	if bytes.Equal(r1.Hash, r2.Hash) {
		t.Fatal("hashing the same PIN twice must produce different hashes (different salts)")
	}
}

func TestHashPINWithConfigPBKDF2UnsupportedHash(t *testing.T) {
	cfg := HashConfig{
		Algorithm:  HashPBKDF2,
		PBKDF2Hash: types.HashName("BLAKE2b"),
		Iterations: 1000,
		KeyLen:     32,
		SaltLen:    16,
	}
	_, err := hashPINWithConfig("test-pin", cfg)
	if err == nil {
		t.Fatal("expected error for unsupported PBKDF2 hash")
	}
	var hashErr *ErrUnsupportedPBKDF2Hash
	if !errors.As(err, &hashErr) {
		t.Fatalf("expected ErrUnsupportedPBKDF2Hash, got %T: %v", err, err)
	}
	if hashErr.Hash != "BLAKE2b" {
		t.Fatalf("expected hash name BLAKE2b, got %s", hashErr.Hash)
	}
}

func TestVerifyPINRecordArgon2idCorrectPIN(t *testing.T) {
	cfg := fastArgon2idConfig()
	record, err := hashPINWithConfig("my-secret-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	ok, err := verifyPINRecord("my-secret-pin", record)
	if err != nil {
		t.Fatalf("verifyPINRecord failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed for correct PIN")
	}
}

func TestVerifyPINRecordArgon2idWrongPIN(t *testing.T) {
	cfg := fastArgon2idConfig()
	record, err := hashPINWithConfig("correct-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	ok, err := verifyPINRecord("wrong-pin", record)
	if err != nil {
		t.Fatalf("verifyPINRecord returned unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for wrong PIN")
	}
}

func TestVerifyPINRecordPBKDF2CorrectPIN(t *testing.T) {
	cfg := fastPBKDF2Config()
	record, err := hashPINWithConfig("my-pbkdf2-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	ok, err := verifyPINRecord("my-pbkdf2-pin", record)
	if err != nil {
		t.Fatalf("verifyPINRecord failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed for correct PIN")
	}
}

func TestVerifyPINRecordPBKDF2WrongPIN(t *testing.T) {
	cfg := fastPBKDF2Config()
	record, err := hashPINWithConfig("real-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	ok, err := verifyPINRecord("fake-pin", record)
	if err != nil {
		t.Fatalf("verifyPINRecord returned unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for wrong PIN")
	}
}

func TestVerifyPINRecordUnsupportedAlgorithm(t *testing.T) {
	record := &PINRecord{
		Algorithm: "bcrypt",
		Hash:      []byte("dummy"),
		Salt:      []byte("dummy"),
	}
	ok, err := verifyPINRecord("any-pin", record)
	if !errors.Is(err, ErrUnsupportedHashAlgorithm) {
		t.Fatalf("expected ErrUnsupportedHashAlgorithm, got %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for unsupported algorithm")
	}
}

func TestVerifyArgon2idCorrectPIN(t *testing.T) {
	cfg := fastArgon2idConfig()
	record, err := hashPINWithConfig("argon2-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	ok, err := verifyArgon2id("argon2-pin", record)
	if err != nil {
		t.Fatalf("verifyArgon2id failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed")
	}
}

func TestVerifyArgon2idWrongPIN(t *testing.T) {
	cfg := fastArgon2idConfig()
	record, err := hashPINWithConfig("right-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	ok, err := verifyArgon2id("wrong-pin", record)
	if err != nil {
		t.Fatalf("verifyArgon2id returned unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail")
	}
}

func TestVerifyArgon2idNilParams(t *testing.T) {
	// Simulate a legacy record created before params were stored.
	// verifyArgon2id should fall back to default parameters.
	cfg := HashConfig{
		Algorithm: HashArgon2id,
		Time:      3,
		Memory:    64 * 1024,
		Threads:   4,
		KeyLen:    32,
		SaltLen:   16,
	}
	record, err := hashPINWithConfig("legacy-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	// Clear params to simulate a legacy record.
	record.Params = nil

	ok, err := verifyArgon2id("legacy-pin", record)
	if err != nil {
		t.Fatalf("verifyArgon2id with nil params failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed with default fallback params")
	}
}

func TestVerifyArgon2idEmptyParams(t *testing.T) {
	// Empty params (empty byte slice) should also trigger fallback.
	cfg := HashConfig{
		Algorithm: HashArgon2id,
		Time:      3,
		Memory:    64 * 1024,
		Threads:   4,
		KeyLen:    32,
		SaltLen:   16,
	}
	record, err := hashPINWithConfig("legacy-pin-2", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	record.Params = json.RawMessage{}

	ok, err := verifyArgon2id("legacy-pin-2", record)
	if err != nil {
		t.Fatalf("verifyArgon2id with empty params failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed with default fallback params")
	}
}

func TestVerifyPBKDF2CorrectPIN(t *testing.T) {
	cfg := fastPBKDF2Config()
	record, err := hashPINWithConfig("pbkdf2-secret", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	ok, err := verifyPBKDF2("pbkdf2-secret", record)
	if err != nil {
		t.Fatalf("verifyPBKDF2 failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed")
	}
}

func TestVerifyPBKDF2WrongPIN(t *testing.T) {
	cfg := fastPBKDF2Config()
	record, err := hashPINWithConfig("correct", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	ok, err := verifyPBKDF2("incorrect", record)
	if err != nil {
		t.Fatalf("verifyPBKDF2 returned unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail")
	}
}

func TestVerifyPBKDF2InvalidHashInParams(t *testing.T) {
	cfg := fastPBKDF2Config()
	record, err := hashPINWithConfig("some-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	// Replace params with an unsupported hash function name.
	badParams, err := json.Marshal(pbkdf2Params{
		Hash:       "SHAKE-256",
		Iterations: 1000,
		KeyLen:     32,
	})
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	record.Params = badParams

	ok, err := verifyPBKDF2("some-pin", record)
	if err == nil {
		t.Fatal("expected error for unsupported hash in params")
	}
	var hashErr *ErrUnsupportedPBKDF2Hash
	if !errors.As(err, &hashErr) {
		t.Fatalf("expected ErrUnsupportedPBKDF2Hash, got %T: %v", err, err)
	}
	if ok {
		t.Fatal("expected ok=false when hash function is unsupported")
	}
}

func TestVerifyPBKDF2MalformedParams(t *testing.T) {
	record := &PINRecord{
		Algorithm: string(HashPBKDF2),
		Hash:      []byte("dummy-hash"),
		Salt:      []byte("dummy-salt"),
		Params:    json.RawMessage(`{invalid-json`),
	}
	ok, err := verifyPBKDF2("any-pin", record)
	if err == nil {
		t.Fatal("expected error for malformed params JSON")
	}
	if ok {
		t.Fatal("expected ok=false for malformed params")
	}
}

func TestResolveHashFuncSHA256(t *testing.T) {
	fn, err := resolveHashFunc(types.HashSHA256)
	if err != nil {
		t.Fatalf("resolveHashFunc(SHA256) failed: %v", err)
	}
	h := fn()
	if h.Size() != 32 {
		t.Fatalf("expected SHA-256 digest size 32, got %d", h.Size())
	}
}

func TestResolveHashFuncSHA384(t *testing.T) {
	fn, err := resolveHashFunc(types.HashSHA384)
	if err != nil {
		t.Fatalf("resolveHashFunc(SHA384) failed: %v", err)
	}
	h := fn()
	if h.Size() != 48 {
		t.Fatalf("expected SHA-384 digest size 48, got %d", h.Size())
	}
}

func TestResolveHashFuncSHA512(t *testing.T) {
	fn, err := resolveHashFunc(types.HashSHA512)
	if err != nil {
		t.Fatalf("resolveHashFunc(SHA512) failed: %v", err)
	}
	h := fn()
	if h.Size() != 64 {
		t.Fatalf("expected SHA-512 digest size 64, got %d", h.Size())
	}
}

func TestResolveHashFuncSHA512_256(t *testing.T) {
	fn, err := resolveHashFunc(types.HashSHA512_256)
	if err != nil {
		t.Fatalf("resolveHashFunc(SHA512_256) failed: %v", err)
	}
	h := fn()
	if h.Size() != 32 {
		t.Fatalf("expected SHA-512/256 digest size 32, got %d", h.Size())
	}
}

func TestResolveHashFuncUnsupported(t *testing.T) {
	_, err := resolveHashFunc(types.HashName("MD5"))
	if err == nil {
		t.Fatal("expected error for unsupported hash function")
	}
	var hashErr *ErrUnsupportedPBKDF2Hash
	if !errors.As(err, &hashErr) {
		t.Fatalf("expected ErrUnsupportedPBKDF2Hash, got %T: %v", err, err)
	}
	if hashErr.Hash != "MD5" {
		t.Fatalf("expected hash name MD5, got %s", hashErr.Hash)
	}
}

func TestResolveHashFuncEmptyName(t *testing.T) {
	_, err := resolveHashFunc(types.HashName(""))
	if err == nil {
		t.Fatal("expected error for empty hash name")
	}
	var hashErr *ErrUnsupportedPBKDF2Hash
	if !errors.As(err, &hashErr) {
		t.Fatalf("expected ErrUnsupportedPBKDF2Hash, got %T: %v", err, err)
	}
}

func TestPINRecordJSONRoundTrip(t *testing.T) {
	cfg := fastArgon2idConfig()
	original, err := hashPINWithConfig("roundtrip-pin", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored PINRecord
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if restored.Algorithm != original.Algorithm {
		t.Fatalf("algorithm mismatch: %s vs %s", original.Algorithm, restored.Algorithm)
	}
	if !bytes.Equal(restored.Hash, original.Hash) {
		t.Fatal("hash mismatch after JSON round-trip")
	}
	if !bytes.Equal(restored.Salt, original.Salt) {
		t.Fatal("salt mismatch after JSON round-trip")
	}
	if !bytes.Equal(restored.Params, original.Params) {
		t.Fatal("params mismatch after JSON round-trip")
	}

	// Verify the restored record can still verify the PIN.
	ok, err := verifyPINRecord("roundtrip-pin", &restored)
	if err != nil {
		t.Fatalf("verifyPINRecord after round-trip failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed after JSON round-trip")
	}
}

func TestPINRecordJSONRoundTripPBKDF2(t *testing.T) {
	cfg := fastPBKDF2Config()
	original, err := hashPINWithConfig("pbkdf2-roundtrip", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored PINRecord
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if restored.Algorithm != original.Algorithm {
		t.Fatalf("algorithm mismatch: %s vs %s", original.Algorithm, restored.Algorithm)
	}
	if !bytes.Equal(restored.Hash, original.Hash) {
		t.Fatal("hash mismatch after JSON round-trip")
	}

	ok, err := verifyPINRecord("pbkdf2-roundtrip", &restored)
	if err != nil {
		t.Fatalf("verifyPINRecord after round-trip failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed after JSON round-trip")
	}
}

func TestHashPINWithConfigEmptyPIN(t *testing.T) {
	cfg := fastArgon2idConfig()
	record, err := hashPINWithConfig("", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig with empty PIN failed: %v", err)
	}
	// An empty PIN should still produce a valid record.
	ok, err := verifyPINRecord("", record)
	if err != nil {
		t.Fatalf("verifyPINRecord failed: %v", err)
	}
	if !ok {
		t.Fatal("expected empty PIN to verify successfully")
	}
	// A non-empty PIN must not match.
	ok, err = verifyPINRecord("non-empty", record)
	if err != nil {
		t.Fatalf("verifyPINRecord returned unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected non-empty PIN to fail verification against empty PIN record")
	}
}

func TestHashPINWithConfigAllPBKDF2Hashes(t *testing.T) {
	hashes := []struct {
		name       types.HashName
		digestSize int
	}{
		{types.HashSHA256, 32},
		{types.HashSHA384, 48},
		{types.HashSHA512, 64},
		{types.HashSHA512_256, 32},
	}

	for _, tc := range hashes {
		t.Run(string(tc.name), func(t *testing.T) {
			cfg := HashConfig{
				Algorithm:  HashPBKDF2,
				PBKDF2Hash: tc.name,
				Iterations: 1000,
				KeyLen:     uint32(tc.digestSize),
				SaltLen:    16,
			}
			record, err := hashPINWithConfig("test-all-hashes", cfg)
			if err != nil {
				t.Fatalf("hashPINWithConfig failed for %s: %v", tc.name, err)
			}
			if len(record.Hash) != tc.digestSize {
				t.Fatalf("expected hash length %d, got %d", tc.digestSize, len(record.Hash))
			}
			ok, err := verifyPINRecord("test-all-hashes", record)
			if err != nil {
				t.Fatalf("verifyPINRecord failed for %s: %v", tc.name, err)
			}
			if !ok {
				t.Fatalf("verification failed for %s", tc.name)
			}
		})
	}
}

func TestHashAlgorithmConstants(t *testing.T) {
	if HashArgon2id != "argon2id" {
		t.Fatalf("expected HashArgon2id=%q, got %q", "argon2id", HashArgon2id)
	}
	if HashPBKDF2 != "pbkdf2" {
		t.Fatalf("expected HashPBKDF2=%q, got %q", "pbkdf2", HashPBKDF2)
	}
}

func TestVerifyPINRecordCrossAlgorithm(t *testing.T) {
	// Hash with Argon2id, then manually change the algorithm field to PBKDF2.
	// This should fail because the params won't match PBKDF2 expectations.
	cfg := fastArgon2idConfig()
	record, err := hashPINWithConfig("cross-algo", cfg)
	if err != nil {
		t.Fatalf("hashPINWithConfig failed: %v", err)
	}
	record.Algorithm = string(HashPBKDF2)

	// verifyPBKDF2 should fail because the params have argon2id fields,
	// not pbkdf2 fields (missing hash function name).
	ok, err := verifyPINRecord("cross-algo", record)
	if err != nil {
		// PBKDF2 will try to resolve an empty hash name, which should fail.
		var hashErr *ErrUnsupportedPBKDF2Hash
		if !errors.As(err, &hashErr) {
			t.Fatalf("expected ErrUnsupportedPBKDF2Hash, got %T: %v", err, err)
		}
	}
	if ok {
		t.Fatal("expected verification to fail with mismatched algorithm")
	}
}
