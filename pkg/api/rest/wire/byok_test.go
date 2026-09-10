// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// jsonTagSet returns the JSON keys a struct marshals.
func jsonTagSet(t *testing.T, v any) map[string]bool {
	t.Helper()
	tags := map[string]bool{}
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		tags[strings.Split(tag, ",")[0]] = true
	}
	return tags
}

// TestByokBodies_AgreeWithTheTransportContract pins every field of the four
// ceremony requests and two responses against the transport contract: each
// transport field has a body field (under the renamed key where the REST body
// spells it differently), and each body field has a transport field, so a
// field one side can express and the other silently drops cannot come back.
func TestByokBodies_AgreeWithTheTransportContract(t *testing.T) {
	notOnTheWire := map[string]bool{"tenant_id": true}
	for _, tc := range []struct {
		name           string
		contract, body any
		renamed        map[string]string // transport key -> body key
		bodyOnly       map[string]bool   // body keys with no transport counterpart, by design
	}{
		{name: "GetImportParametersRequest", contract: transport.GetImportParametersRequest{}, body: GetImportParametersRequest{},
			bodyOnly: map[string]bool{"hash": true, "aes_key_size": true}},
		{name: "GetImportParametersResponse", contract: transport.GetImportParametersResponse{}, body: GetImportParametersResponse{},
			renamed: map[string]string{"wrapping_public_key": "wrapping_public_key_pem"}},
		{name: "WrapKeyRequest", contract: transport.WrapKeyRequest{}, body: WrapKeyRequest{},
			renamed: map[string]string{"wrapping_public_key": "wrapping_public_key_pem"}},
		{name: "WrapKeyResponse", contract: transport.WrapKeyResponse{}, body: WrapKeyResponse{},
			renamed: map[string]string{"wrapped_key_material": "wrapped_key"}, bodyOnly: map[string]bool{"import_token": true}},
		{name: "UnwrapKeyRequest", contract: transport.UnwrapKeyRequest{}, body: UnwrapKeyRequest{},
			renamed: map[string]string{"wrapped_key_material": "wrapped_key", "wrapping_public_key": "wrapping_public_key_pem"}},
		{name: "ImportKeyRequest", contract: transport.ImportKeyRequest{}, body: ImportKeyRequest{},
			renamed: map[string]string{"wrapped_key_material": "wrapped_key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contract := jsonTagSet(t, tc.contract)
			body := jsonTagSet(t, tc.body)
			for key := range contract {
				if notOnTheWire[key] {
					continue
				}
				want := key
				if to, ok := tc.renamed[key]; ok {
					want = to
				}
				assert.Truef(t, body[want], "transport field %q has no body field %q: the REST and QUIC transports would drop it", key, want)
			}
			back := map[string]string{}
			for from, to := range tc.renamed {
				back[to] = from
			}
			for key := range body {
				if tc.bodyOnly[key] {
					continue
				}
				want := key
				if from, ok := back[key]; ok {
					want = from
				}
				assert.Truef(t, contract[want], "body field %q has no transport field %q: no client of the contract can set it", key, want)
			}
		})
	}
}

func testDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return der
}

// TestWrapKeyRequest_EncodesTheWrappingKeyAsPEM proves the DER key of the
// contract reaches the body as PEM text that decodes to the same key, and
// that every other field crosses by name.
func TestWrapKeyRequest_EncodesTheWrappingKeyAsPEM(t *testing.T) {
	der := testDER(t)
	body, err := NewWrapKeyRequest(&transport.WrapKeyRequest{
		Backend: "software", KeyMaterial: []byte("material"), Algorithm: "RSAES_OAEP_SHA_256",
		WrappingPublicKey: der, ImportToken: []byte("tok"), KeySpec: "RSA_2048", TenantID: "t1",
	})
	require.NoError(t, err)
	assert.Contains(t, body.WrappingPublicKeyPEM, "BEGIN PUBLIC KEY")
	back, err := wrappingPublicKeyDER(body.WrappingPublicKeyPEM)
	require.NoError(t, err)
	assert.Equal(t, der, back, "the PEM must decode to the DER that went in")
	assert.Equal(t, "software", body.Backend)
	assert.Equal(t, []byte("material"), body.KeyMaterial)
	assert.Equal(t, "RSAES_OAEP_SHA_256", body.Algorithm)
	assert.Equal(t, []byte("tok"), body.ImportToken)
	assert.Equal(t, "RSA_2048", body.KeySpec)
}

// TestWrapKeyRequest_RefusesAKeyThatIsNotDER proves a wrapping key that is
// not DER PKIX is refused with the typed error rather than sent as text the
// handler cannot decode.
func TestWrapKeyRequest_RefusesAKeyThatIsNotDER(t *testing.T) {
	_, err := NewWrapKeyRequest(&transport.WrapKeyRequest{WrappingPublicKey: []byte("wpk")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWrappingPublicKeyNotDER), "got %v", err)

	body, err := NewWrapKeyRequest(&transport.WrapKeyRequest{Backend: "software"})
	require.NoError(t, err, "an absent wrapping key stays absent")
	assert.Empty(t, body.WrappingPublicKeyPEM)
}

// TestUnwrapKeyRequest_CarriesEveryField proves the unwrap body carries the
// material under the REST name, the key as PEM, and the fields the body used
// to lack.
func TestUnwrapKeyRequest_CarriesEveryField(t *testing.T) {
	der := testDER(t)
	body, err := NewUnwrapKeyRequest(&transport.UnwrapKeyRequest{
		Backend: "software", WrappedKeyMaterial: []byte("wrapped"), Algorithm: "RSAES_OAEP_SHA_256",
		ImportToken: []byte("tok"), WrappingPublicKey: der, KeySpec: "AES_256", Metadata: map[string]string{"k": "v"},
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("wrapped"), body.WrappedKey)
	assert.Contains(t, body.WrappingPublicKeyPEM, "BEGIN PUBLIC KEY")
	assert.Equal(t, "AES_256", body.KeySpec)
	assert.Equal(t, map[string]string{"k": "v"}, body.Metadata)

	_, err = NewUnwrapKeyRequest(&transport.UnwrapKeyRequest{WrappingPublicKey: []byte("not der")})
	assert.True(t, errors.Is(err, ErrWrappingPublicKeyNotDER))
}

// TestImportKeyRequest_CarriesEveryField proves the import body carries the
// material under the REST name and every other field, including the ones the
// body used to lack (partition, metadata) and the exportability choice.
func TestImportKeyRequest_CarriesEveryField(t *testing.T) {
	exportable := false
	body := NewImportKeyRequest(&transport.ImportKeyRequest{
		Backend: "software", KeyID: "k", KeyType: "symmetric", KeySize: 256, Curve: "P-256", Hash: "SHA-256",
		AESKeySize: 256, WrappedKeyMaterial: []byte("wrapped"), Algorithm: "RSAES_OAEP_SHA_256",
		ImportToken: []byte("tok"), Partition: "p1", Metadata: map[string]string{"origin": "test"},
		Exportable: &exportable, Sensitive: true, TenantID: "t1",
	})
	assert.Equal(t, []byte("wrapped"), body.WrappedKey, "the material must reach the body")
	assert.Equal(t, "p1", body.Partition)
	assert.Equal(t, map[string]string{"origin": "test"}, body.Metadata)
	require.NotNil(t, body.Exportable)
	assert.False(t, *body.Exportable)
	assert.True(t, body.Sensitive)
	assert.Equal(t, 256, body.AESKeySize)
	assert.Equal(t, "SHA-256", body.Hash)
}

// TestGetImportParametersResponse_DecodesThePEMToDER proves the response's
// PEM wrapping key comes back as the DER the contract carries, an absent key
// stays absent, and text that is not a key is refused.
func TestGetImportParametersResponse_DecodesThePEMToDER(t *testing.T) {
	der := testDER(t)
	pem, err := wrappingPublicKeyPEM(der)
	require.NoError(t, err)

	resp, err := GetImportParametersResponse{WrappingPublicKeyPEM: pem, ImportToken: []byte("tok"), Algorithm: "RSAES_OAEP_SHA_256", ExpiresAt: "2026-01-01T00:00:00Z", KeySpec: "RSA_2048"}.Transport()
	require.NoError(t, err)
	assert.Equal(t, der, resp.WrappingPublicKey)
	assert.Equal(t, []byte("tok"), resp.ImportToken)
	assert.Equal(t, "RSA_2048", resp.KeySpec)
	assert.Equal(t, "2026-01-01T00:00:00Z", resp.ExpiresAt)

	empty, err := GetImportParametersResponse{Algorithm: "x"}.Transport()
	require.NoError(t, err)
	assert.Empty(t, empty.WrappingPublicKey)

	_, err = GetImportParametersResponse{WrappingPublicKeyPEM: "not a key"}.Transport()
	require.Error(t, err)
}

// TestWrapKeyResponse_Transport proves the wrapped material crosses back
// under the contract's name.
func TestWrapKeyResponse_Transport(t *testing.T) {
	resp := WrapKeyResponse{WrappedKey: []byte("wrapped"), Algorithm: "AES", Metadata: map[string]string{"k": "v"}}.Transport()
	assert.Equal(t, []byte("wrapped"), resp.WrappedKeyMaterial)
	assert.Equal(t, "AES", resp.Algorithm)
	assert.Equal(t, map[string]string{"k": "v"}, resp.Metadata)

	assert.Empty(t, WrapKeyResponse{}.Transport().WrappedKeyMaterial)
}

// TestGetImportParametersRequest_CarriesEveryField pins the request mapping.
func TestGetImportParametersRequest_CarriesEveryField(t *testing.T) {
	body := NewGetImportParametersRequest(&transport.GetImportParametersRequest{Backend: "b", KeyID: "k", Algorithm: "a", KeyType: "rsa", KeySize: 2048, Curve: "P-256"})
	assert.Equal(t, GetImportParametersRequest{Backend: "b", KeyID: "k", Algorithm: "a", KeyType: "rsa", KeySize: 2048, Curve: "P-256"}, body)
}
