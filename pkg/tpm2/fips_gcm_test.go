//go:build tpm_simulator
// +build tpm_simulator

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

package tpm2

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSymmetricEncryptDecrypt_AgreesWithArbitraryIVGCMUsable exercises the
// default Encrypt path (no caller nonce) against whatever this process
// actually is -- the default process, GODEBUG=fips140=on, or
// GODEBUG=fips140=only -- rather than assuming the pre-FIPS-140-only
// explicit-nonce framing. Under fips140=only Go's crypto/cipher refuses
// every AES-GCM construction that accepts a process-supplied IV, which
// includes go-tpm's own HMAC session encryption (CFB) when it is enabled;
// createSim(false) below disables that session encryption so this
// test reaches tpm2AESEncrypter's own AES-GCM selection, the one this
// change touches, without tripping over that unrelated TPM-session gap.
func TestSymmetricEncryptDecrypt_AgreesWithArbitraryIVGCMUsable(t *testing.T) {
	_, tpm := createSim(false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "fips-gcm-nonce-mode",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if _, err := tpm2Instance.GenerateSymmetricKey(attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}

	encrypter, err := tpm2Instance.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter: %v", err)
	}

	plaintext := []byte("tpm2 default encrypt path, any FIPS posture")
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
	if len(encrypted.Nonce) == 0 {
		t.Error("Nonce should not be empty")
	}
	if len(encrypted.Tag) == 0 {
		t.Error("Tag should not be empty")
	}

	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext = %q, want %q", decrypted, plaintext)
	}

	// Under fips140=only, a caller-supplied nonce fails closed rather than
	// relaying the runtime's own refusal from inside Seal; outside it,
	// nothing changes for the caller-nonce path.
	_, err = encrypter.Encrypt(plaintext, &types.EncryptOptions{Nonce: make([]byte, 12)})
	if aead.ArbitraryIVGCMUsable() {
		if err != nil {
			t.Fatalf("Encrypt with a caller nonce failed outside fips140=only: %v", err)
		}
	} else if err == nil {
		t.Fatal("Encrypt with a caller nonce succeeded under fips140=only, want an error")
	}
}

// TestSymmetricDecrypt_RandomNonceModeRejectsWrongLengthNonce is the
// error-handling counterpart: a GCMNonceModeRandom ciphertext whose Nonce
// is not exactly aead.GCMRandomNonceSize bytes must be refused rather than
// passed to Open, which would either panic or silently misinterpret the
// framing. This does not depend on the process's FIPS posture: the fields
// are checked before any AEAD construction runs.
func TestSymmetricDecrypt_RandomNonceModeRejectsWrongLengthNonce(t *testing.T) {
	_, tpm := createSim(false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "fips-gcm-nonce-mode-bad-length",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := tpm2Instance.GenerateSymmetricKey(attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}

	encrypter, err := tpm2Instance.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter: %v", err)
	}

	_, err = encrypter.Decrypt(&types.EncryptedData{
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
