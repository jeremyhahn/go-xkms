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

//go:build frost

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

const frostExportTestPassphrase = "correct horse battery staple"

// openTestFrostStore opens cfg's store under the passphrase currently in
// the environment.
func openTestFrostStore(t *testing.T, cfg *Config) *frostLocalStore {
	t.Helper()
	store, err := openFrostLocalStore(newFrostPassphraseCmd(), cfg)
	if err != nil {
		t.Fatalf("openFrostLocalStore: %v", err)
	}
	return store
}

// newTestFrostRecipient creates a participant key directory with a
// recipient key, returning its config and recipient public key.
func newTestFrostRecipient(t *testing.T) (*Config, *ecdsa.PublicKey) {
	t.Helper()
	cfg := newFrostTestConfig(t)
	publicKey, err := ensureFrostRecipientKey(context.Background(), openTestFrostStore(t, cfg))
	if err != nil {
		t.Fatalf("ensureFrostRecipientKey: %v", err)
	}
	return cfg, publicKey
}

// newTestKeyPackageExport generates a 2-of-3 key with the trusted dealer and
// returns participant 1's package in the form dealer keygen exports it.
func newTestKeyPackageExport(t *testing.T) *KeyPackageExport {
	t.Helper()
	packages, pubPkg, err := client.NewFrostTrustedDealer().Generate(client.FrostConfig{
		Threshold:     2,
		Total:         3,
		Algorithm:     client.FrostAlgorithmEd25519,
		ParticipantID: 1,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	shares := make(map[uint32]string, len(pubPkg.VerificationShares))
	for id, vs := range pubPkg.VerificationShares {
		shares[id] = hex.EncodeToString(vs)
	}
	return &KeyPackageExport{
		KeyID:              frostTestKeyID,
		Algorithm:          string(client.FrostAlgorithmEd25519),
		Threshold:          2,
		Total:              3,
		ParticipantID:      packages[0].ParticipantID,
		ParticipantName:    "alice",
		SecretShare:        hex.EncodeToString(packages[0].SecretShare.Value),
		GroupPublicKey:     hex.EncodeToString(pubPkg.GroupPublicKey),
		VerificationShares: shares,
	}
}

// writeEncryptedPackage encrypts export to recipient and writes the file
// dealer keygen would, returning its path and bytes.
func writeEncryptedPackage(t *testing.T, export *KeyPackageExport, recipient *ecdsa.PublicKey) (string, []byte) {
	t.Helper()
	encrypted, err := encryptKeyPackageExport(export, recipient)
	if err != nil {
		t.Fatalf("encryptKeyPackageExport: %v", err)
	}
	data, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	path := filepath.Join(t.TempDir(), "alice_participant_1.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path, data
}

// writeRecipientPEM writes publicKey as the PEM file `frost recipient
// --public-key-file` produces.
func writeRecipientPEM(t *testing.T, dir, name string, publicKey any) string {
	t.Helper()
	data, err := client.EncodePublicKeyPEM(publicKey)
	if err != nil {
		t.Fatalf("EncodePublicKeyPEM: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestFrostRecipient_StableAndEncryptedAtRest(t *testing.T) {
	cfg := newFrostTestConfig(t)
	setFrostPassphraseEnv(t, frostExportTestPassphrase)
	output := filepath.Join(t.TempDir(), "alice.pem")

	first, err := runFrostRecipient(newFrostPassphraseCmd(), cfg, output)
	if err != nil {
		t.Fatalf("runFrostRecipient: %v", err)
	}
	second, err := runFrostRecipient(newFrostPassphraseCmd(), cfg, "")
	if err != nil {
		t.Fatalf("runFrostRecipient (second run): %v", err)
	}
	if first["recipient_id"] != second["recipient_id"] || first["public_key"] != second["public_key"] {
		t.Fatalf("second run printed a different key: %v vs %v", first["recipient_id"], second["recipient_id"])
	}

	publicKey, err := readFrostRecipientPublicKey(output)
	if err != nil {
		t.Fatalf("--public-key-file is not a usable recipient key: %v", err)
	}
	if id, _ := frostRecipientID(publicKey); id != first["recipient_id"] {
		t.Fatalf("--public-key-file key thumbprint = %s, printed %v", id, first["recipient_id"])
	}

	var keyBlobs [][]byte
	for name, data := range secretsDirFiles(t, cfg) {
		if strings.HasPrefix(name, "keys/") && strings.HasSuffix(name, ".key") {
			keyBlobs = append(keyBlobs, data)
		}
	}
	if len(keyBlobs) != 1 {
		t.Fatalf("secrets directory holds %d key blobs, want exactly the recipient key", len(keyBlobs))
	}
	requireEncryptedPKCS8(t, "recipient key", keyBlobs[0])
}

func TestFrostRecipient_Errors(t *testing.T) {
	t.Run("wrong passphrase", func(t *testing.T) {
		setFrostPassphraseEnv(t, frostExportTestPassphrase)
		cfg, _ := newTestFrostRecipient(t)

		setFrostPassphraseEnv(t, "tr0ub4dor&3")
		_, err := runFrostRecipient(newFrostPassphraseCmd(), cfg, "")
		if !errors.Is(err, ErrFrostPassphraseRejected) {
			t.Fatalf("err = %v, want ErrFrostPassphraseRejected", err)
		}
	})
	t.Run("no passphrase", func(t *testing.T) {
		unsetFrostPassphraseEnv(t)
		_, err := runFrostRecipient(newFrostPassphraseCmd(), newFrostTestConfig(t), "")
		if !errors.Is(err, ErrFrostPassphraseRequired) {
			t.Fatalf("err = %v, want ErrFrostPassphraseRequired", err)
		}
	})
	t.Run("unwritable output", func(t *testing.T) {
		setFrostPassphraseEnv(t, frostExportTestPassphrase)
		output := filepath.Join(t.TempDir(), "missing", "alice.pem")
		_, err := runFrostRecipient(newFrostPassphraseCmd(), newFrostTestConfig(t), output)
		if !errors.Is(err, ErrWriteRecipientKeyFailed) {
			t.Fatalf("err = %v, want ErrWriteRecipientKeyFailed", err)
		}
	})
}

func TestFrostPackageExport_IsNotPlaintext(t *testing.T) {
	setFrostPassphraseEnv(t, frostExportTestPassphrase)
	_, recipient := newTestFrostRecipient(t)
	export := newTestKeyPackageExport(t)
	_, data := writeEncryptedPackage(t, export, recipient)

	share, err := hex.DecodeString(export.SecretShare)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	for label, needle := range map[string][]byte{
		"hex share":       []byte(export.SecretShare),
		"raw share":       share,
		"base64url share": []byte(base64.RawURLEncoding.EncodeToString(share)),
		"std base64":      []byte(base64.StdEncoding.EncodeToString(share)),
	} {
		if bytes.Contains(data, needle) {
			t.Fatalf("exported package contains the %s", label)
		}
	}

	var file map[string]any
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := file["secret_share"]; ok {
		t.Fatal("exported package has a top-level secret_share field")
	}
	if parts := strings.Split(file["package"].(string), "."); len(parts) != 5 {
		t.Fatalf("package is not a JWE compact serialization: %d parts", len(parts))
	}
}

func TestFrostPackageExport_ImportRoundTrip(t *testing.T) {
	setFrostPassphraseEnv(t, frostExportTestPassphrase)
	cfg, recipient := newTestFrostRecipient(t)
	export := newTestKeyPackageExport(t)
	path, _ := writeEncryptedPackage(t, export, recipient)

	store := openTestFrostStore(t, cfg)
	got, err := readFrostPackage(context.Background(), store, path)
	if err != nil {
		t.Fatalf("readFrostPackage: %v", err)
	}
	if got.SecretShare != export.SecretShare || got.GroupPublicKey != export.GroupPublicKey ||
		got.KeyID != export.KeyID || got.ParticipantID != export.ParticipantID {
		t.Fatalf("decrypted package differs from the exported one")
	}

	// Store it exactly as frost import does and read it back.
	secretShare, _ := hex.DecodeString(got.SecretShare)
	groupPublicKey, _ := hex.DecodeString(got.GroupPublicKey)
	verificationShares := make(map[uint32][]byte, len(got.VerificationShares))
	for id, vs := range got.VerificationShares {
		verificationShares[id], _ = hex.DecodeString(vs)
	}
	be, err := store.shareBackend(context.Background(), client.FrostAlgorithm(got.Algorithm), got.ParticipantID, got.Threshold, got.Total, nil)
	if err != nil {
		t.Fatalf("shareBackend: %v", err)
	}
	defer closeQuietly(be)
	if err := be.ImportKeyPackage(context.Background(), frostShareAttrs(), &client.FrostKeyPackage{
		ParticipantID:      got.ParticipantID,
		SecretShare:        &client.FrostSecretKeyShare{Value: secretShare},
		GroupPublicKey:     groupPublicKey,
		VerificationShares: verificationShares,
		MinSigners:         uint32(got.Threshold),
		MaxSigners:         uint32(got.Total),
		Algorithm:          client.FrostAlgorithm(got.Algorithm),
	}); err != nil {
		t.Fatalf("ImportKeyPackage: %v", err)
	}
	key, err := be.GetKey(context.Background(), frostShareAttrs())
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if !bytes.Equal(key.(*client.FrostKeyHandle).GroupPublicKey, groupPublicKey) {
		t.Fatal("imported share has a different group public key")
	}
}

func TestFrostPackageExport_ImportRefusals(t *testing.T) {
	setFrostPassphraseEnv(t, frostExportTestPassphrase)
	aliceCfg, alice := newTestFrostRecipient(t)
	bobCfg, _ := newTestFrostRecipient(t)
	export := newTestKeyPackageExport(t)
	alicePath, aliceData := writeEncryptedPackage(t, export, alice)

	t.Run("another participant's key", func(t *testing.T) {
		_, err := readFrostPackage(context.Background(), openTestFrostStore(t, bobCfg), alicePath)
		if !errors.Is(err, ErrFrostPackageRecipientMismatch) {
			t.Fatalf("err = %v, want ErrFrostPackageRecipientMismatch", err)
		}
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		setFrostPassphraseEnv(t, "tr0ub4dor&3")
		_, err := readFrostPackage(context.Background(), openTestFrostStore(t, aliceCfg), alicePath)
		if !errors.Is(err, ErrFrostPassphraseRejected) {
			t.Fatalf("err = %v, want ErrFrostPassphraseRejected", err)
		}
	})

	t.Run("no recipient key", func(t *testing.T) {
		_, err := readFrostPackage(context.Background(), openTestFrostStore(t, newFrostTestConfig(t)), alicePath)
		if !errors.Is(err, ErrFrostRecipientKeyMissing) {
			t.Fatalf("err = %v, want ErrFrostRecipientKeyMissing", err)
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		var encrypted EncryptedKeyPackageExport
		if err := json.Unmarshal(aliceData, &encrypted); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		parts := strings.Split(encrypted.Package, ".")
		ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}
		ciphertext[0] ^= 0x01
		parts[3] = base64.RawURLEncoding.EncodeToString(ciphertext)
		encrypted.Package = strings.Join(parts, ".")

		key, err := loadFrostRecipientKey(context.Background(), openTestFrostStore(t, aliceCfg))
		if err != nil {
			t.Fatalf("loadFrostRecipientKey: %v", err)
		}
		if _, err := decryptKeyPackageExport(&encrypted, key); !errors.Is(err, ErrFrostPackageDecryptFailed) {
			t.Fatalf("err = %v, want ErrFrostPackageDecryptFailed", err)
		}
	})

	t.Run("plaintext package", func(t *testing.T) {
		data, err := json.Marshal(export)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		path := filepath.Join(t.TempDir(), "plaintext.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err = readFrostPackage(context.Background(), openTestFrostStore(t, aliceCfg), path)
		if !errors.Is(err, ErrFrostPackageNotEncrypted) {
			t.Fatalf("err = %v, want ErrFrostPackageNotEncrypted", err)
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		_, err := readFrostPackage(context.Background(), openTestFrostStore(t, aliceCfg), filepath.Join(t.TempDir(), "absent.json"))
		if !errors.Is(err, ErrReadPackageFileFailed) {
			t.Fatalf("err = %v, want ErrReadPackageFileFailed", err)
		}
	})
}

func TestParseFrostRecipients(t *testing.T) {
	dir := t.TempDir()
	keys := make([]string, 4)
	for i := range keys {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		keys[i] = writeRecipientPEM(t, dir, filepath.Base(t.Name())+string(rune('a'+i))+".pem", &key.PublicKey)
	}

	recipients, err := parseFrostRecipients([]string{"1=" + keys[0], " 2 =" + keys[1], "3=" + keys[2]}, 3)
	if err != nil {
		t.Fatalf("parseFrostRecipients: %v", err)
	}
	if len(recipients) != 3 {
		t.Fatalf("got %d recipients, want 3", len(recipients))
	}
	want, err := readFrostRecipientPublicKey(keys[1])
	if err != nil {
		t.Fatalf("readFrostRecipientPublicKey: %v", err)
	}
	if !recipients[2].Equal(want) {
		t.Fatal("participant 2 was given the wrong key")
	}
}

func TestParseFrostRecipients_Errors(t *testing.T) {
	dir := t.TempDir()
	newKey := func(name string, curve elliptic.Curve) string {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		return writeRecipientPEM(t, dir, name, &key.PublicKey)
	}
	a := newKey("a.pem", elliptic.P256())
	b := newKey("b.pem", elliptic.P256())
	p384 := newKey("p384.pem", elliptic.P384())
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a key"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var missing *FrostRecipientMissingError
	tests := []struct {
		name  string
		specs []string
		check func(error) bool
	}{
		{"none given", nil, func(err error) bool { return errors.As(err, &missing) && missing.ID == 1 }},
		{"one missing", []string{"1=" + a}, func(err error) bool { return errors.As(err, &missing) && missing.ID == 2 }},
		{"no separator", []string{a}, func(err error) bool { return errors.Is(err, ErrFrostRecipientSpecInvalid) }},
		{"empty path", []string{"1="}, func(err error) bool { return errors.Is(err, ErrFrostRecipientSpecInvalid) }},
		{"id zero", []string{"0=" + a}, func(err error) bool { return errors.Is(err, ErrFrostRecipientSpecInvalid) }},
		{"id above total", []string{"3=" + a}, func(err error) bool { return errors.Is(err, ErrFrostRecipientSpecInvalid) }},
		{"id not a number", []string{"alice=" + a}, func(err error) bool { return errors.Is(err, ErrFrostRecipientSpecInvalid) }},
		{"duplicate id", []string{"1=" + a, "1=" + b}, func(err error) bool { return errors.Is(err, ErrFrostRecipientDuplicate) }},
		{"same key twice", []string{"1=" + a, "2=" + a}, func(err error) bool { return errors.Is(err, ErrFrostRecipientReused) }},
		{"not P-256", []string{"1=" + p384}, func(err error) bool { return errors.Is(err, ErrFrostRecipientKeyInvalid) }},
		{"not a key", []string{"1=" + garbage}, func(err error) bool { return errors.Is(err, ErrFrostRecipientKeyInvalid) }},
		{"absent file", []string{"1=" + filepath.Join(dir, "absent.pem")}, func(err error) bool { return errors.Is(err, ErrFrostRecipientKeyInvalid) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFrostRecipients(tc.specs, 2)
			if err == nil || !tc.check(err) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestFrostKeygen_DeclaresRecipientFlag(t *testing.T) {
	if frostKeygenCmd.Flags().Lookup("recipient") == nil {
		t.Fatal("keygen has no --recipient flag")
	}
	if frostRecipientCmd.Flags().Lookup(frostPassphraseFlagFile) == nil {
		t.Fatal("recipient does not take the FROST passphrase")
	}
}
