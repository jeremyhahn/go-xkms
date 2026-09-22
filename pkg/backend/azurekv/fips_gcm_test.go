// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build azurekv

package azurekv

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSymmetricEncryptDecrypt_AgreesWithArbitraryIVGCMUsable exercises the
// default Encrypt path (no caller nonce) against whatever this process
// actually is, rather than assuming the pre-FIPS-140-only explicit-nonce
// framing: when this process can construct arbitrary-IV GCM (default and
// fips140=on), Encrypt still produces the zero-value GCMNonceMode -- every
// ciphertext this backend produced before FIPS 140-only support -- and it
// round-trips through Decrypt. Under fips140=only, this same path produces
// GCMNonceModeRandom instead; that substitution, and its own round trip, is
// pinned directly by TestAzureKV_FIPS140Only.
func TestSymmetricEncryptDecrypt_AgreesWithArbitraryIVGCMUsable(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "legacy-explicit-nonce",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	encrypter := newLocalSymmetricKey(t, b, attrs)
	plaintext := []byte("legacy ciphertext, explicit nonce mode")

	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wantMode := types.GCMNonceModeExplicit
	if !aead.ArbitraryIVGCMUsable() {
		wantMode = types.GCMNonceModeRandom
	}
	if encrypted.GCMNonceMode != wantMode {
		t.Fatalf("GCMNonceMode = %q, want %q", encrypted.GCMNonceMode, wantMode)
	}

	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext = %q, want %q", decrypted, plaintext)
	}
}

// TestSymmetricDecrypt_ExplicitNonceModeAgreesWithArbitraryIVGCMUsable pins
// Decrypt's behavior for a GCMNonceModeExplicit ciphertext -- the framing
// every ciphertext this backend produced before FIPS 140-only support --
// against whatever this process actually is: it opens when this process can
// construct arbitrary-IV GCM, and fails closed when it cannot, rather than
// panicking or silently misinterpreting the framing.
func TestSymmetricDecrypt_ExplicitNonceModeAgreesWithArbitraryIVGCMUsable(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "explicit-nonce-mode-probe",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	encrypter := newLocalSymmetricKey(t, b, attrs)

	explicit := &types.EncryptedData{
		Ciphertext:   []byte{0, 0, 0, 0},
		Nonce:        make([]byte, 12),
		Tag:          make([]byte, aead.GCMFullTagSize),
		Algorithm:    string(types.SymmetricAES256GCM),
		GCMNonceMode: types.GCMNonceModeExplicit,
	}

	_, err := encrypter.Decrypt(explicit, nil)
	if aead.ArbitraryIVGCMUsable() {
		// The all-zero tag is not a valid authentication tag for any
		// plaintext, so this must fail authentication rather than succeed
		// -- but it must reach that check, not fail earlier at
		// construction.
		if err == nil {
			t.Fatal("Decrypt of a forged all-zero tag succeeded, want an authentication error")
		}
		return
	}
	if err == nil {
		t.Fatal("Decrypt of a GCMNonceModeExplicit ciphertext succeeded under fips140=only, want a fail-closed error")
	}
}

// TestSymmetricDecrypt_RandomNonceModeRejectsWrongLengthNonce is the
// error-handling counterpart to the random-nonce round trip below: a
// GCMNonceModeRandom ciphertext whose Nonce is not exactly
// aead.GCMRandomNonceSize bytes must be refused rather than passed to
// Open, which would either panic or silently misinterpret the framing.
func TestSymmetricDecrypt_RandomNonceModeRejectsWrongLengthNonce(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "random-nonce-mode-bad-length",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	encrypter := newLocalSymmetricKey(t, b, attrs)

	_, err := encrypter.Decrypt(&types.EncryptedData{
		Ciphertext:   []byte("short"),
		Nonce:        []byte{1, 2, 3}, // too short for aead.GCMRandomNonceSize
		Tag:          make([]byte, aead.GCMFullTagSize),
		Algorithm:    string(types.SymmetricAES256GCM),
		GCMNonceMode: types.GCMNonceModeRandom,
	}, nil)
	if err == nil {
		t.Fatal("Decrypt with a short random-mode nonce succeeded, want an error")
	}
}

// TestAzureKV_FIPS140Only re-execs the test binary under
// GODEBUG=fips140=only to exercise the default Encrypt path -- no caller
// nonce -- end to end: FIPS 140-only substitutes
// cipher.NewGCMWithRandomNonce, Decrypt must recover the plaintext from the
// GCMNonceMode the ciphertext now carries, and a caller-supplied nonce must
// fail closed. (Sealer.go's Seal/Unseal Metadata propagation for
// GCMNonceMode wraps this same Encrypt/Decrypt path; a full Seal/Unseal
// round trip additionally requires the Azure Secrets API the key-vault mock
// does not implement -- see newLocalSymmetricKey -- so that is covered by
// the emulator-backed suite in test/integration/azurekv, not here.)
func TestAzureKV_FIPS140Only(t *testing.T) {
	if mode := os.Getenv("XKMS_AZUREKV_FIPS_SUBPROCESS"); mode != "" {
		if aead.ArbitraryIVGCMUsable() {
			t.Fatal("ArbitraryIVGCMUsable() = true under fips140=only")
		}

		b, _ := testBackend(t)
		defer func() { _ = b.Close() }()

		attrs := &types.KeyAttributes{
			CN:                 "fips-only-default-encrypt",
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AZUREKV,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		encrypter := newLocalSymmetricKey(t, b, attrs)
		plaintext := []byte("fips140=only default encrypt path")

		encrypted, err := encrypter.Encrypt(plaintext, nil)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if encrypted.GCMNonceMode != types.GCMNonceModeRandom {
			t.Fatalf("GCMNonceMode = %q, want %q", encrypted.GCMNonceMode, types.GCMNonceModeRandom)
		}
		if len(encrypted.Nonce) != aead.GCMRandomNonceSize {
			t.Fatalf("Nonce length = %d, want %d", len(encrypted.Nonce), aead.GCMRandomNonceSize)
		}
		if len(encrypted.Tag) != aead.GCMFullTagSize {
			t.Fatalf("Tag length = %d, want %d", len(encrypted.Tag), aead.GCMFullTagSize)
		}

		decrypted, err := encrypter.Decrypt(encrypted, nil)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("plaintext = %q, want %q", decrypted, plaintext)
		}

		// A caller-supplied nonce fails closed rather than relaying the
		// runtime's own refusal from inside Seal.
		if _, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{Nonce: make([]byte, 12)}); err == nil {
			t.Fatal("Encrypt with a caller nonce succeeded under fips140=only, want an error")
		}

		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAzureKV_FIPS140Only$", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_AZUREKV_FIPS_SUBPROCESS=only", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=only subprocess failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("PASS")) {
		t.Fatalf("fips140=only subprocess did not pass:\n%s", out)
	}
	if bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("fips140=only subprocess panicked:\n%s", out)
	}
}
