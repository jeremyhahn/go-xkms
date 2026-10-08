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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestBackendGetKey verifies the Backend.GetKey lifecycle: not-found before
// creation, success (no extractable private key) after creation, and the
// nil-attrs guard clause.
func TestBackendGetKey(t *testing.T) {
	b, _ := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "getkey-test",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	if _, err := b.GetKey(context.Background(), attrs); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("GetKey() before creation error = %v, want ErrKeyNotFound", err)
	}

	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	if _, err := b.GetKey(context.Background(), attrs); err != nil {
		t.Errorf("GetKey() after creation unexpected error = %v", err)
	}

	if _, err := b.GetKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GetKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestGetSignerByIDAndGetDecrypterByID verifies both accessors reject an
// unknown key ID and reject a key that does not exist yet, exercising the
// crypto.Signer/crypto.Decrypter type-assertion guard (Azure Key Vault
// backend keys are never extractable, so GetKey always returns nil here).
func TestGetSignerByIDAndGetDecrypterByID(t *testing.T) {
	b, _ := testBackend(t)

	if _, err := b.GetSignerByID("does-not-exist"); err == nil {
		t.Error("GetSignerByID() expected error for unknown key, got nil")
	}
	if _, err := b.GetDecrypterByID("does-not-exist"); err == nil {
		t.Error("GetDecrypterByID() expected error for unknown key, got nil")
	}

	attrs := &types.KeyAttributes{
		CN:           "signer-by-id",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// GetKey never returns extractable private key material for Azure Key
	// Vault, so the crypto.Signer/crypto.Decrypter type assertion always
	// fails even once the key exists.
	if _, err := b.GetSignerByID(attrs.CN); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetSignerByID() error = %v, want ErrInvalidKeyType", err)
	}
	if _, err := b.GetDecrypterByID(attrs.CN); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetDecrypterByID() error = %v, want ErrInvalidKeyType", err)
	}
}

// TestBackendDeleteKeyCtx verifies the ctx-taking DeleteKey wrapper
// delegates to Delete and actually removes the key's metadata.
func TestBackendDeleteKeyCtx(t *testing.T) {
	b, _ := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "delete-key-ctx",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	if err := b.DeleteKey(context.Background(), attrs); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	exists, err := storage.KeyExists(context.Background(), b.config.KeyStorage, attrs.CN)
	if err != nil {
		t.Fatalf("storage.KeyExists() error = %v", err)
	}
	if exists {
		t.Error("DeleteKey() did not remove metadata")
	}
}

// TestListKeys verifies ListKeys reconstructs KeyAttributes from stored
// metadata, preserving key type and algorithm rather than silently
// dropping them (the "silently dropped field" bug class called out for
// awskms).
func TestListKeys(t *testing.T) {
	b, _ := testBackend(t)

	rsaAttrs := &types.KeyAttributes{
		CN:           "list-keys-rsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	ecAttrs := &types.KeyAttributes{
		CN:           "list-keys-ecdsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.ECDSA,
	}
	if _, err := b.CreateKey(rsaAttrs); err != nil {
		t.Fatalf("CreateKey(rsa) error = %v", err)
	}
	if _, err := b.CreateKey(ecAttrs); err != nil {
		t.Fatalf("CreateKey(ecdsa) error = %v", err)
	}

	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("ListKeys() returned %d keys, want 2", len(keys))
	}

	found := make(map[string]*types.KeyAttributes, len(keys))
	for _, k := range keys {
		found[k.CN] = k
	}

	rsaGot, ok := found[rsaAttrs.CN]
	if !ok {
		t.Fatalf("ListKeys() missing %s", rsaAttrs.CN)
	}
	if rsaGot.KeyType != backend.KEY_TYPE_SIGNING {
		t.Errorf("ListKeys() %s KeyType = %v, want %v (dropped on read)", rsaAttrs.CN, rsaGot.KeyType, backend.KEY_TYPE_SIGNING)
	}
	if rsaGot.KeyAlgorithm != x509.RSA {
		t.Errorf("ListKeys() %s KeyAlgorithm = %v, want RSA (dropped on read)", rsaAttrs.CN, rsaGot.KeyAlgorithm)
	}
	if rsaGot.StoreType != backend.STORE_AZUREKV {
		t.Errorf("ListKeys() %s StoreType = %v, want STORE_AZUREKV", rsaAttrs.CN, rsaGot.StoreType)
	}

	ecGot, ok := found[ecAttrs.CN]
	if !ok {
		t.Fatalf("ListKeys() missing %s", ecAttrs.CN)
	}
	if ecGot.KeyAlgorithm != x509.ECDSA {
		t.Errorf("ListKeys() %s KeyAlgorithm = %v, want ECDSA (dropped on read)", ecAttrs.CN, ecGot.KeyAlgorithm)
	}
}

// TestCreateSecretKey verifies symmetric key creation via the Keys API oct
// type, its idempotency, and its metadata write.
func TestCreateSecretKey(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "secret-key",
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_AZUREKV,
	}

	keyID1, err := b.CreateSecretKey(attrs, 32)
	if err != nil {
		t.Fatalf("CreateSecretKey() error = %v", err)
	}
	if keyID1 == "" {
		t.Fatal("CreateSecretKey() returned empty key ID")
	}
	if _, exists := mockClient.keys[attrs.CN]; !exists {
		t.Error("CreateSecretKey() did not create key in mock vault")
	}

	// Idempotent: second call returns the same key ID without erroring.
	keyID2, err := b.CreateSecretKey(attrs, 32)
	if err != nil {
		t.Fatalf("CreateSecretKey() second call error = %v", err)
	}
	if keyID1 != keyID2 {
		t.Errorf("CreateSecretKey() not idempotent: got %s and %s", keyID1, keyID2)
	}

	if _, err := b.CreateSecretKey(nil, 32); err == nil {
		t.Error("CreateSecretKey(nil) expected error, got nil")
	}
}

// TestEcdsaResultToDER verifies both signature encodings Azure Key Vault
// can return (already-DER, and raw IEEE-P1363 r||s) are normalized, and
// that malformed input is rejected instead of silently truncated.
func TestEcdsaResultToDER(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("ecdsa.Sign() error = %v", err)
	}

	// Already-DER input is returned unchanged.
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}
	got, err := ecdsaResultToDER(der)
	if err != nil {
		t.Fatalf("ecdsaResultToDER(der) error = %v", err)
	}
	if string(got) != string(der) {
		t.Error("ecdsaResultToDER() modified already-DER input")
	}

	// Raw IEEE-P1363 r||s (32 bytes each for P-256) is converted to DER.
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	converted, err := ecdsaResultToDER(raw)
	if err != nil {
		t.Fatalf("ecdsaResultToDER(raw) error = %v", err)
	}
	if !ecdsa.VerifyASN1(&priv.PublicKey, []byte("0123456789abcdef0123456789abcdef"), converted) {
		t.Error("ecdsaResultToDER(raw) produced a DER signature that does not verify")
	}

	// Odd-length input is neither valid DER nor a valid raw r||s pair.
	if _, err := ecdsaResultToDER([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Error("ecdsaResultToDER(odd length) expected error, got nil")
	}

	// Empty input is rejected outright.
	if _, err := ecdsaResultToDER(nil); err == nil {
		t.Error("ecdsaResultToDER(nil) expected error, got nil")
	}
}

// TestGetSigningAlgorithm_AllBranches exercises every hash/padding branch
// getSigningAlgorithm dispatches on, since a wrong mapping here would sign
// with the wrong Azure algorithm identifier without any local signal.
func TestGetSigningAlgorithm_AllBranches(t *testing.T) {
	b, _ := testBackend(t)

	rsaAttrs := func(hash crypto.Hash) *types.KeyAttributes {
		return &types.KeyAttributes{CN: "sig-alg", KeyAlgorithm: x509.RSA, Hash: hash}
	}
	ecAttrs := func(hash crypto.Hash) *types.KeyAttributes {
		return &types.KeyAttributes{CN: "sig-alg", KeyAlgorithm: x509.ECDSA, Hash: hash}
	}

	tests := []struct {
		name  string
		attrs *types.KeyAttributes
		opts  crypto.SignerOpts
		want  azkeys.SignatureAlgorithm
	}{
		{"RSA PSS SHA256", rsaAttrs(0), &rsa.PSSOptions{Hash: crypto.SHA256}, azkeys.SignatureAlgorithmPS256},
		{"RSA PSS SHA384", rsaAttrs(0), &rsa.PSSOptions{Hash: crypto.SHA384}, azkeys.SignatureAlgorithmPS384},
		{"RSA PSS SHA512", rsaAttrs(0), &rsa.PSSOptions{Hash: crypto.SHA512}, azkeys.SignatureAlgorithmPS512},
		{"RSA PSS unknown hash defaults PS256", rsaAttrs(0), &rsa.PSSOptions{Hash: crypto.MD5}, azkeys.SignatureAlgorithmPS256},
		{"RSA PKCS1v15 SHA256", rsaAttrs(crypto.SHA256), crypto.SHA256, azkeys.SignatureAlgorithmRS256},
		{"RSA PKCS1v15 SHA384", rsaAttrs(crypto.SHA384), crypto.SHA384, azkeys.SignatureAlgorithmRS384},
		{"RSA PKCS1v15 SHA512", rsaAttrs(crypto.SHA512), crypto.SHA512, azkeys.SignatureAlgorithmRS512},
		{"RSA PKCS1v15 unknown hash defaults RS256", rsaAttrs(crypto.MD5), crypto.MD5, azkeys.SignatureAlgorithmRS256},
		{"RSA no attrs.Hash defaults RS256", rsaAttrs(0), crypto.SHA256, azkeys.SignatureAlgorithmRS256},
		{"ECDSA SHA256", ecAttrs(crypto.SHA256), crypto.SHA256, azkeys.SignatureAlgorithmES256},
		{"ECDSA SHA384", ecAttrs(crypto.SHA384), crypto.SHA384, azkeys.SignatureAlgorithmES384},
		{"ECDSA SHA512", ecAttrs(crypto.SHA512), crypto.SHA512, azkeys.SignatureAlgorithmES512},
		{"ECDSA unknown hash defaults ES256", ecAttrs(crypto.MD5), crypto.MD5, azkeys.SignatureAlgorithmES256},
		{"ECDSA no attrs.Hash defaults ES256", ecAttrs(0), crypto.SHA256, azkeys.SignatureAlgorithmES256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := b.getSigningAlgorithm(tt.attrs, tt.opts)
			if err != nil {
				t.Fatalf("getSigningAlgorithm() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("getSigningAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}

	// Unsupported key algorithm.
	if _, err := b.getSigningAlgorithm(&types.KeyAttributes{KeyAlgorithm: x509.Ed25519}, crypto.SHA256); err == nil {
		t.Error("getSigningAlgorithm(Ed25519) expected error, got nil")
	}
}

// TestJWKToPublicKey verifies the JWK-to-crypto.PublicKey conversion used
// by the real Key Vault client's GetPublicKey, including its guard clauses
// and unsupported-curve/type rejection.
func TestJWKToPublicKey(t *testing.T) {
	rsaKty := azkeys.KeyTypeRSA
	ecKty := azkeys.KeyTypeEC
	p256 := azkeys.CurveNameP256
	badCurve := azkeys.CurveName("P-999")
	badKty := azkeys.KeyType("bogus")

	tests := []struct {
		name    string
		jwk     *azkeys.JSONWebKey
		wantErr bool
	}{
		{name: "nil jwk", jwk: nil, wantErr: true},
		{name: "nil key type", jwk: &azkeys.JSONWebKey{}, wantErr: true},
		{
			name:    "RSA missing N",
			jwk:     &azkeys.JSONWebKey{Kty: &rsaKty, E: big.NewInt(65537).Bytes()},
			wantErr: true,
		},
		{
			name: "RSA valid",
			jwk: &azkeys.JSONWebKey{
				Kty: &rsaKty,
				N:   big.NewInt(1<<62 + 12345).Bytes(),
				E:   big.NewInt(65537).Bytes(),
			},
		},
		{
			name:    "EC missing X/Y/Crv",
			jwk:     &azkeys.JSONWebKey{Kty: &ecKty},
			wantErr: true,
		},
		{
			name: "EC valid P256",
			jwk: &azkeys.JSONWebKey{
				Kty: &ecKty,
				Crv: &p256,
				X:   big.NewInt(1234567).Bytes(),
				Y:   big.NewInt(7654321).Bytes(),
			},
		},
		{
			name: "EC unsupported curve",
			jwk: &azkeys.JSONWebKey{
				Kty: &ecKty,
				Crv: &badCurve,
				X:   big.NewInt(1).Bytes(),
				Y:   big.NewInt(1).Bytes(),
			},
			wantErr: true,
		},
		{
			name:    "unsupported key type",
			jwk:     &azkeys.JSONWebKey{Kty: &badKty},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := jwkToPublicKey(tt.jwk)
			if tt.wantErr {
				if err == nil {
					t.Error("jwkToPublicKey() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("jwkToPublicKey() unexpected error = %v", err)
			}
			if pub == nil {
				t.Error("jwkToPublicKey() returned nil public key")
			}
		})
	}
}

// TestHasServicePrincipal verifies the tri-field completeness check used to
// decide between ClientSecretCredential and DefaultAzureCredential: a
// partial set of credentials must never be treated as "has service
// principal", or initClient would attempt authentication with missing
// fields.
func TestHasServicePrincipal(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name: "complete",
			config: &Config{
				ClientID: "id", TenantID: "tenant",
				ClientSecret: secrettest.Literal(t, []byte("secret")),
			},
			want: true,
		},
		{name: "empty", config: &Config{}, want: false},
		{name: "missing secret", config: &Config{ClientID: "id", TenantID: "tenant"}, want: false},
		{name: "missing tenant", config: &Config{ClientID: "id", ClientSecret: secrettest.Literal(t, []byte("s"))}, want: false},
		{name: "missing client id", config: &Config{TenantID: "tenant", ClientSecret: secrettest.Literal(t, []byte("s"))}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{config: tt.config}
			if got := b.hasServicePrincipal(); got != tt.want {
				t.Errorf("hasServicePrincipal() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewClientSecretCredential verifies the credential is built from the
// configured service principal without ever needing network access
// (construction alone performs no I/O).
func TestNewClientSecretCredential(t *testing.T) {
	b := &Backend{config: &Config{
		TenantID:     "11111111-1111-1111-1111-111111111111",
		ClientID:     "22222222-2222-2222-2222-222222222222",
		ClientSecret: secrettest.Literal(t, []byte("super-secret")),
	}}

	cred, err := b.newClientSecretCredential(t.Context(), nil)
	if err != nil {
		t.Fatalf("newClientSecretCredential() error = %v", err)
	}
	if cred == nil {
		t.Error("newClientSecretCredential() returned nil credential")
	}
}

// TestInitClient_DefaultCredentialPath verifies initClient's slow path
// builds a client through azidentity.NewDefaultAzureCredential when no
// service principal is configured, and that the fast path short-circuits
// once a client is set (mirroring the double-checked-locking contract).
func TestInitClient_DefaultCredentialPath(t *testing.T) {
	b, err := NewBackend(&Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	if err := b.initClient(context.Background()); err != nil {
		t.Fatalf("initClient() error = %v", err)
	}
	if b.client == nil {
		t.Fatal("initClient() did not set client")
	}

	// Fast path: calling again with a client already set is a no-op.
	existing := b.client
	if err := b.initClient(context.Background()); err != nil {
		t.Fatalf("initClient() second call error = %v", err)
	}
	if b.client != existing {
		t.Error("initClient() replaced an already-initialized client")
	}
}

// TestInitClient_ServicePrincipalPath verifies initClient's slow path
// builds a client through ClientSecretCredential when a full service
// principal is configured.
func TestInitClient_ServicePrincipalPath(t *testing.T) {
	b, err := NewBackend(&Config{
		VaultURL:     "https://test-vault.vault.azure.net/",
		TenantID:     "11111111-1111-1111-1111-111111111111",
		ClientID:     "22222222-2222-2222-2222-222222222222",
		ClientSecret: secrettest.Literal(t, []byte("super-secret")),
		KeyStorage:   storage.New(),
		CertStorage:  storage.New(),
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	if err := b.initClient(context.Background()); err != nil {
		t.Fatalf("initClient() error = %v", err)
	}
	if b.client == nil {
		t.Fatal("initClient() did not set client")
	}
}

// TestConfigString_MasksSecrets verifies Config.String() never leaks the
// tenant ID, client ID, or client secret in full — only a masked suffix (or
// "<not set>") — since this is the representation callers log.
func TestConfigString_MasksSecrets(t *testing.T) {
	c := &Config{
		VaultURL:     "https://test-vault.vault.azure.net/",
		TenantID:     "11111111-2222-3333-4444-555555555555",
		ClientID:     "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		ClientSecret: secrettest.Literal(t, []byte("do-not-leak-me")),
		Debug:        true,
	}

	s := c.String()
	if strings.Contains(s, "do-not-leak-me") {
		t.Error("Config.String() leaked the client secret plaintext")
	}
	if !strings.Contains(s, "5555") {
		t.Error("Config.String() did not mask TenantID with its expected suffix")
	}
	if !strings.Contains(s, "eeee") {
		t.Error("Config.String() did not mask ClientID with its expected suffix")
	}
	if !strings.Contains(s, "****") {
		t.Error("Config.String() did not mask ClientSecret")
	}

	empty := (&Config{VaultURL: "https://test-vault.vault.azure.net/"}).String()
	if !strings.Contains(empty, "<not set>") {
		t.Error("Config.String() did not report unset credentials as <not set>")
	}
}

// TestSignerAndDecrypter_RSAOAEPBranches verifies azurekvDecrypter.Decrypt
// selects RSA15 for nil opts, RSAOAEP/RSAOAEP256 by hash, and rejects an
// unsupported OAEP hash, since a wrong selection here silently changes
// which Azure algorithm is requested.
func TestSignerAndDecrypter_RSAOAEPBranches(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "decrypter-oaep",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	decrypter, err := b.Decrypter(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Decrypter() error = %v", err)
	}
	if decrypter.Public() == nil {
		t.Error("Decrypter().Public() returned nil")
	}

	mockKey := mockClient.keys[attrs.CN]
	rsaPub := mockKey.publicKey.(*rsa.PublicKey)

	encrypt := func(hash crypto.Hash) []byte {
		var ct []byte
		var err error
		switch hash {
		case crypto.SHA1:
			ct, err = rsa.EncryptOAEP(crypto.SHA1.New(), rand.Reader, rsaPub, []byte("secret"), nil)
		default:
			ct, err = rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, []byte("secret"), nil)
		}
		if err != nil {
			t.Fatalf("EncryptOAEP() error = %v", err)
		}
		return ct
	}

	// nil opts -> PKCS#1 v1.5.
	pkcs1ct, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte("secret")) //nolint:staticcheck // SA1019: exercises azurekvDecrypter.Decrypt's nil-opts path, which maps to Azure Key Vault's real EncryptionAlgorithmRSA15
	if err != nil {
		t.Fatalf("EncryptPKCS1v15() error = %v", err)
	}
	if _, err := decrypter.Decrypt(nil, pkcs1ct, nil); err != nil {
		t.Errorf("Decrypt(nil opts) error = %v", err)
	}

	if _, err := decrypter.Decrypt(nil, encrypt(crypto.SHA1), &rsa.OAEPOptions{Hash: crypto.SHA1}); err != nil {
		t.Errorf("Decrypt(SHA1 OAEP) error = %v", err)
	}
	if _, err := decrypter.Decrypt(nil, encrypt(crypto.SHA256), &rsa.OAEPOptions{Hash: crypto.SHA256}); err != nil {
		t.Errorf("Decrypt(SHA256 OAEP) error = %v", err)
	}
	if _, err := decrypter.Decrypt(nil, encrypt(crypto.SHA256), &rsa.OAEPOptions{Hash: crypto.MD5}); err == nil {
		t.Error("Decrypt(unsupported OAEP hash) expected error, got nil")
	}

	// Decrypter on a non-RSA key is rejected before any I/O.
	ecAttrs := &types.KeyAttributes{CN: "decrypter-ec", KeyAlgorithm: x509.ECDSA}
	if _, err := b.Decrypter(context.Background(), ecAttrs); !errors.Is(err, backend.ErrInvalidAlgorithm) {
		t.Errorf("Decrypter(ECDSA) error = %v, want ErrInvalidAlgorithm", err)
	}
	if _, err := b.Decrypter(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("Decrypter(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestBackendRotateKey verifies RotateKey's guard clause and its success
// path against the mock vault.
func TestBackendRotateKey(t *testing.T) {
	b, _ := testBackend(t)

	if err := b.RotateKey(context.Background(), nil); err == nil {
		t.Error("RotateKey(nil) expected error, got nil")
	}

	attrs := &types.KeyAttributes{
		CN:           "rotate-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if err := b.RotateKey(context.Background(), attrs); err != nil {
		t.Errorf("RotateKey() error = %v", err)
	}
}

// TestSignerNilAttrsGuard verifies Signer() rejects nil attrs before
// touching the client.
func TestSignerNilAttrsGuard(t *testing.T) {
	b, _ := testBackend(t)
	if _, err := b.Signer(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("Signer(nil) error = %v, want ErrInvalidAttributes", err)
	}
}
