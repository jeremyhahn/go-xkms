package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestImportParamsFile_RoundTripsWrappingPublicKey writes the file that
// key get-import-params --output writes, reads it back through the decode
// path key wrap and key unwrap use, and wraps key material with the
// decoded wrapping public key.
func TestImportParamsFile_RoundTripsWrappingPublicKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := &client.ImportParameters{
		WrappingPublicKey: der,
		ImportToken:       []byte{1, 2, 3},
		Algorithm:         client.WrappingAlgorithm("RSAES_OAEP_SHA_256"),
		KeySpec:           "RSA_2048",
	}

	data, err := encodeImportParams(want)
	if err != nil {
		t.Fatalf("encodeImportParams: %v", err)
	}
	path := filepath.Join(t.TempDir(), "params.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeImportParams(read)
	if err != nil {
		t.Fatalf("decodeImportParams: %v", err)
	}
	if got.Algorithm != want.Algorithm || got.KeySpec != want.KeySpec || !bytes.Equal(got.ImportToken, want.ImportToken) {
		t.Fatalf("decoded params = %+v, want %+v", got, want)
	}

	keyBytes, err := wrappingKeyBytes(got)
	if err != nil {
		t.Fatalf("wrappingKeyBytes: %v", err)
	}
	if !bytes.Equal(keyBytes, der) {
		t.Fatal("wrapping public key did not round-trip")
	}
	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		t.Fatalf("parse wrapping key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("wrapping key type %T", pub)
	}
	material := bytes.Repeat([]byte{0x42}, 32)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, material, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	unwrapped, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
	if err != nil || !bytes.Equal(unwrapped, material) {
		t.Fatalf("unwrap: %v", err)
	}
}
