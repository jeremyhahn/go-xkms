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

//go:build frost

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// oidPBES2 identifies PKCS#5 v2.0 password-based encryption (RFC 8018), the
// scheme an encrypted PKCS#8 EncryptedPrivateKeyInfo carries.
var oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

// encryptedPrivateKeyInfo is RFC 5958's EncryptedPrivateKeyInfo.
type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

const frostTestKeyID = "frost-1324"

// newFrostPassphraseCmd returns a command carrying the FROST passphrase
// flags, as keygen/import/round1/round2 do.
func newFrostPassphraseCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "frost-test"}
	addFrostPassphraseFlags(cmd)
	cmd.SetContext(context.Background())
	return cmd
}

// newFrostTestConfig returns a Config whose key directory does not exist
// yet, so the store has to create every directory itself.
func newFrostTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := NewConfig()
	cfg.KeyDir = filepath.Join(t.TempDir(), "keys")
	return cfg
}

// setFrostPassphraseEnv supplies the passphrase through the environment.
func setFrostPassphraseEnv(t *testing.T, passphrase string) {
	t.Helper()
	t.Setenv(frostPassphraseEnvVar, passphrase)
}

// unsetFrostPassphraseEnv removes the passphrase variable for the test,
// restoring it afterwards.
func unsetFrostPassphraseEnv(t *testing.T) {
	t.Helper()
	t.Setenv(frostPassphraseEnvVar, "")
	if err := os.Unsetenv(frostPassphraseEnvVar); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}
}

// withSecretStdin substitutes the stdin the passphrase resolver reads.
func withSecretStdin(t *testing.T, content string) {
	t.Helper()
	original := secretStdin
	secretStdin = strings.NewReader(content)
	t.Cleanup(func() { secretStdin = original })
}

// generateFrostShare stores participant 1's share of a new 2-of-3 key in
// cfg's store under the passphrase currently in the environment, returning
// the group public key.
func generateFrostShare(t *testing.T, cfg *Config) []byte {
	t.Helper()
	be, err := openFrostShareBackend(newFrostPassphraseCmd(), cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
	if err != nil {
		t.Fatalf("openFrostShareBackend: %v", err)
	}
	defer closeQuietly(be)

	key, err := be.GenerateKey(context.Background(), &client.KeyAttributes{
		CN:        frostTestKeyID,
		KeyType:   client.KeyTypeSigning,
		StoreType: client.StoreFrost,
		FrostAttributes: &client.FrostAttributes{
			Algorithm:     client.FrostAlgorithmEd25519,
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
		},
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key.(*client.FrostKeyHandle).GroupPublicKey
}

// frostShareAttrs names the test key for lookups.
func frostShareAttrs() *client.KeyAttributes {
	return &client.KeyAttributes{
		CN:        frostTestKeyID,
		KeyType:   client.KeyTypeSigning,
		StoreType: client.StoreFrost,
	}
}

// secretsDirFiles returns every file in the store's secrets directory,
// keyed by its path relative to that directory.
func secretsDirFiles(t *testing.T, cfg *Config) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	root := filepath.Join(cfg.KeyDir, "frost", "secrets")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%s): %v", root, err)
	}
	return files
}

func TestFrostShareBackend_PassphraseRoundTrip(t *testing.T) {
	cfg := newFrostTestConfig(t)
	setFrostPassphraseEnv(t, "correct horse battery staple")
	groupKey := generateFrostShare(t, cfg)

	// A fresh process: reopen the store and unseal the share.
	be, err := openFrostShareBackend(newFrostPassphraseCmd(), cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
	if err != nil {
		t.Fatalf("reopen openFrostShareBackend: %v", err)
	}
	defer closeQuietly(be)

	key, err := be.GetKey(context.Background(), frostShareAttrs())
	if err != nil {
		t.Fatalf("GetKey (unseals the share): %v", err)
	}
	if got := key.(*client.FrostKeyHandle).GroupPublicKey; !bytes.Equal(got, groupKey) {
		t.Fatalf("group public key = %x, want %x", got, groupKey)
	}
	if _, err := be.GenerateNonces(frostTestKeyID); err != nil {
		t.Fatalf("GenerateNonces (round1 path): %v", err)
	}
}

func TestFrostShareBackend_WrappingKeyIsEncryptedPKCS8(t *testing.T) {
	const passphrase = "correct horse battery staple"
	cfg := newFrostTestConfig(t)
	setFrostPassphraseEnv(t, passphrase)
	generateFrostShare(t, cfg)

	var keyBlobs [][]byte
	for name, data := range secretsDirFiles(t, cfg) {
		if bytes.Contains(data, []byte(passphrase)) {
			t.Fatalf("%s contains the passphrase", name)
		}
		if strings.HasPrefix(name, "keys/") && strings.HasSuffix(name, ".key") {
			keyBlobs = append(keyBlobs, data)
		}
	}
	if len(keyBlobs) != 1 {
		t.Fatalf("secrets directory holds %d key blobs, want exactly the wrapping key", len(keyBlobs))
	}
	requireEncryptedPKCS8(t, "wrapping key", keyBlobs[0])
}

// requireEncryptedPKCS8 fails the test unless der is a PBES2-encrypted
// PKCS#8 EncryptedPrivateKeyInfo, never plaintext PKCS#8.
func requireEncryptedPKCS8(t *testing.T, name string, der []byte) {
	t.Helper()
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		t.Fatalf("%s parses as plaintext PKCS#8; it must be encrypted", name)
	}
	var info encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		t.Fatalf("%s is not an EncryptedPrivateKeyInfo: %v", name, err)
	}
	if len(rest) != 0 {
		t.Fatalf("%s has %d trailing bytes", name, len(rest))
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		t.Fatalf("%s encryption algorithm = %v, want PBES2 %v", name, info.Algorithm.Algorithm, oidPBES2)
	}
	if len(info.EncryptedData) == 0 {
		t.Fatalf("%s has no encrypted payload", name)
	}
}

func TestFrostShareBackend_WrongPassphraseRefused(t *testing.T) {
	cfg := newFrostTestConfig(t)
	setFrostPassphraseEnv(t, "correct horse battery staple")
	generateFrostShare(t, cfg)

	setFrostPassphraseEnv(t, "tr0ub4dor&3")
	be, err := openFrostShareBackend(newFrostPassphraseCmd(), cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
	if err == nil {
		closeQuietly(be)
		t.Fatal("openFrostShareBackend accepted a wrong passphrase")
	}
	if !errors.Is(err, ErrFrostPassphraseRejected) {
		t.Fatalf("err = %v, want ErrFrostPassphraseRejected", err)
	}
}

// TestFrostShareBackend_PlaintextWrappingKeyRefused covers a key directory
// written before go-xkms#1324, whose wrapping key is plaintext PKCS#8: the
// share verbs must refuse it rather than keep sealing under an unprotected
// key.
func TestFrostShareBackend_PlaintextWrappingKeyRefused(t *testing.T) {
	cfg := newFrostTestConfig(t)
	_, secretDir, err := frostStoreDirs(cfg.KeyDir)
	if err != nil {
		t.Fatalf("frostStoreDirs: %v", err)
	}
	secretStorage, err := client.NewFileStorageBackend(secretDir)
	if err != nil {
		t.Fatalf("NewFileStorageBackend: %v", err)
	}
	legacy, err := client.NewSoftwareBackend(&client.SoftwareBackendConfig{KeyStorage: secretStorage})
	if err != nil {
		t.Fatalf("NewSoftwareBackend: %v", err)
	}
	if _, err := legacy.GenerateKey(context.Background(), client.FrostAsymmetricSecretSealKeyAttributes(client.StoreSoftware)); err != nil {
		t.Fatalf("GenerateKey (plaintext wrapping key): %v", err)
	}

	setFrostPassphraseEnv(t, "correct horse battery staple")
	be, err := openFrostShareBackend(newFrostPassphraseCmd(), cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
	if err == nil {
		closeQuietly(be)
		t.Fatal("openFrostShareBackend accepted a plaintext wrapping key")
	}
	if !errors.Is(err, ErrFrostPassphraseRejected) {
		t.Fatalf("err = %v, want ErrFrostPassphraseRejected", err)
	}
}

func TestFrostShareBackend_NoPassphraseRefused(t *testing.T) {
	cfg := newFrostTestConfig(t)
	unsetFrostPassphraseEnv(t)

	be, err := openFrostShareBackend(newFrostPassphraseCmd(), cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
	if err == nil {
		closeQuietly(be)
		t.Fatal("openFrostShareBackend ran with no passphrase and no hardware backend")
	}
	if !errors.Is(err, ErrFrostPassphraseRequired) {
		t.Fatalf("err = %v, want ErrFrostPassphraseRequired", err)
	}
	if _, statErr := os.Stat(cfg.KeyDir); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("key directory was created before the passphrase check: stat err = %v", statErr)
	}
}

func TestFrostShareBackend_UnsupportedBackendRefused(t *testing.T) {
	cfg := newFrostTestConfig(t)
	cfg.Backend = string(client.BackendTypeTPM2)
	setFrostPassphraseEnv(t, "correct horse battery staple")

	be, err := openFrostShareBackend(newFrostPassphraseCmd(), cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
	if err == nil {
		closeQuietly(be)
		t.Fatal("openFrostShareBackend silently ignored --backend tpm2")
	}
	if !errors.Is(err, ErrFrostWrapBackendUnsupported) {
		t.Fatalf("err = %v, want ErrFrostWrapBackendUnsupported", err)
	}
}

func TestFrostStoreDirs_OwnerOnly(t *testing.T) {
	cfg := newFrostTestConfig(t)
	setFrostPassphraseEnv(t, "correct horse battery staple")
	generateFrostShare(t, cfg)

	for _, dir := range []string{
		cfg.KeyDir,
		filepath.Join(cfg.KeyDir, "frost"),
		filepath.Join(cfg.KeyDir, "frost", "public"),
		filepath.Join(cfg.KeyDir, "frost", "secrets"),
	} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat(%s): %v", dir, err)
		}
		if mode := info.Mode().Perm(); mode != 0o700 {
			t.Errorf("%s mode = %#o, want 0700", dir, mode)
		}
	}
}

func TestFrostStoreDirs_TightensExistingFrostDirectories(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	frostDir := filepath.Join(keyDir, "frost")
	publicDir := filepath.Join(frostDir, "public")
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for _, dir := range []string{frostDir, publicDir} {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("Chmod(%s): %v", dir, err)
		}
	}

	if _, _, err := frostStoreDirs(keyDir); err != nil {
		t.Fatalf("frostStoreDirs: %v", err)
	}
	for _, dir := range []string{frostDir, publicDir, filepath.Join(frostDir, "secrets")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat(%s): %v", dir, err)
		}
		if mode := info.Mode().Perm(); mode != 0o700 {
			t.Errorf("%s mode = %#o, want 0700", dir, mode)
		}
	}
}

func TestFrostStoreDirs_KeyDirIsAFile(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(keyDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := frostStoreDirs(keyDir); !errors.Is(err, ErrCreatePublicDirectoryFailed) {
		t.Fatalf("err = %v, want ErrCreatePublicDirectoryFailed", err)
	}
}

func TestFrostPublicBackend_ReadsPublicHalfButCannotUnseal(t *testing.T) {
	cfg := newFrostTestConfig(t)
	setFrostPassphraseEnv(t, "correct horse battery staple")
	groupKey := generateFrostShare(t, cfg)
	unsetFrostPassphraseEnv(t)

	be, err := openFrostPublicBackend(cfg)
	if err != nil {
		t.Fatalf("openFrostPublicBackend: %v", err)
	}
	defer closeQuietly(be)

	pubPkg, metadata, err := be.PublicKeyPackage(context.Background(), frostShareAttrs())
	if err != nil {
		t.Fatalf("PublicKeyPackage: %v", err)
	}
	if !bytes.Equal(pubPkg.GroupPublicKey, groupKey) || metadata.ParticipantID != 1 {
		t.Fatalf("public package = (%x, participant %d), want (%x, participant 1)", pubPkg.GroupPublicKey, metadata.ParticipantID, groupKey)
	}

	if _, err := be.GetKey(context.Background(), frostShareAttrs()); !errors.Is(err, client.ErrPKCS8KeyDecodingFailed) {
		t.Fatalf("GetKey without a passphrase: err = %v, want ErrPKCS8KeyDecodingFailed", err)
	}
}

func TestResolveFrostPassphrase_Sources(t *testing.T) {
	passphraseFile := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(passphraseFile, []byte("from-file\r\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tests := []struct {
		name  string
		stdin string
		flags map[string]string
		env   string
		want  string
	}{
		{name: "stdin", stdin: "from-stdin\n", flags: map[string]string{frostPassphraseFlagStdin: "true"}, env: "from-env", want: "from-stdin"},
		{name: "file", flags: map[string]string{frostPassphraseFlagFile: passphraseFile}, env: "from-env", want: "from-file"},
		{name: "env", env: "from-env ", want: "from-env "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withSecretStdin(t, tt.stdin)
			setFrostPassphraseEnv(t, tt.env)
			cmd := newFrostPassphraseCmd()
			for name, value := range tt.flags {
				if err := cmd.Flags().Set(name, value); err != nil {
					t.Fatalf("Set(%s): %v", name, err)
				}
			}

			passphrase, err := resolveFrostPassphrase(cmd)
			if err != nil {
				t.Fatalf("resolveFrostPassphrase: %v", err)
			}
			defer passphrase.Clear()
			if got := string(passphrase.Bytes()); got != tt.want {
				t.Fatalf("passphrase = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveFrostPassphrase_Errors(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
		flags map[string]string
		env   *string
		want  error
	}{
		{name: "none", want: ErrFrostPassphraseRequired},
		{name: "empty env", env: new(string), want: ErrFrostPassphraseEmpty},
		{name: "empty stdin", stdin: "\n", flags: map[string]string{frostPassphraseFlagStdin: "true"}, want: ErrFrostPassphraseEmpty},
		{name: "missing file", flags: map[string]string{frostPassphraseFlagFile: filepath.Join(t.TempDir(), "absent")}, want: ErrReadFrostPassphraseFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withSecretStdin(t, tt.stdin)
			if tt.env != nil {
				setFrostPassphraseEnv(t, *tt.env)
			} else {
				unsetFrostPassphraseEnv(t)
			}
			cmd := newFrostPassphraseCmd()
			for name, value := range tt.flags {
				if err := cmd.Flags().Set(name, value); err != nil {
					t.Fatalf("Set(%s): %v", name, err)
				}
			}

			if _, err := resolveFrostPassphrase(cmd); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestFrostPassphraseFlags_MutuallyExclusive(t *testing.T) {
	cmd := newFrostPassphraseCmd()
	if err := cmd.Flags().Set(frostPassphraseFlagStdin, "true"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := cmd.Flags().Set(frostPassphraseFlagFile, "/dev/null"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := cmd.ValidateFlagGroups(); err == nil {
		t.Fatal("--passphrase-stdin and --passphrase-file were accepted together")
	}
}

func TestFrostShareVerbs_DeclarePassphraseFlags(t *testing.T) {
	for _, cmd := range []*cobra.Command{frostKeygenCmd, frostImportCmd, frostRound1Cmd, frostRound2Cmd} {
		for _, name := range []string{frostPassphraseFlagStdin, frostPassphraseFlagFile} {
			if cmd.Flags().Lookup(name) == nil {
				t.Errorf("frost %s lacks --%s", cmd.Name(), name)
			}
		}
		if cmd.Flags().Lookup("passphrase") != nil {
			t.Errorf("frost %s accepts the passphrase as a flag value", cmd.Name())
		}
	}
}

func TestTrimLineEnding(t *testing.T) {
	tests := map[string]string{
		"secret\n":   "secret",
		"secret\r\n": "secret",
		"secret\n\n": "secret\n",
		"secret\r":   "secret\r",
		"secret ":    "secret ",
		"":           "",
	}
	for in, want := range tests {
		if got := string(trimLineEnding([]byte(in))); got != want {
			t.Errorf("trimLineEnding(%q) = %q, want %q", in, got, want)
		}
	}
}
