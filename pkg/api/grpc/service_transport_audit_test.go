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

//go:build !frost

package grpc

import (
	"context"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// oaepNoneHashRefusal is the service layer's verbatim refusal of hash "NONE"
// for RSA-OAEP (pkg/xkms/servicer_crypto.go). The transport must report exactly
// this, not a paraphrase.
const oaepNoneHashRefusal = `RSA-OAEP requires a hash algorithm; hash "NONE" is not valid`

// newSoftwareBackend builds a self-contained software backend with its own key
// storage, so two of them share no state at all -- in particular, no import
// ceremony. That independence is what makes the unwrap-oracle test below able
// to tell which backend actually served a request.
func newSoftwareBackend(t *testing.T) xkms.Backend {
	t.Helper()

	be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     be,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)
	return ks
}

// setupTwoBackendService registers two independent software backends, "alpha"
// and "beta", plus "no-import" -- a mock backend that does not implement
// backend.ImportExportBackend at all.
func setupTwoBackendService(t *testing.T) *Service {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"alpha":     newSoftwareBackend(t),
			"beta":      newSoftwareBackend(t),
			"no-import": xkmsmocks.NewMockKeyStore(),
		},
		DefaultBackend: "alpha",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)
	return NewService(nil, nil, svc)
}

// importCeremony runs GetImportParameters against one named backend and wraps
// keyMaterial with it, returning the wrapped blob. Both halves name the same
// backend, which is the only combination that can ever be unwrapped.
func importCeremony(t *testing.T, service *Service, backendName, keyID string, keyMaterial []byte) *pb.WrapKeyResponse {
	t.Helper()

	params, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             keyID,
		Backend:           backendName,
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "rsa",
		KeySize:           2048,
	})
	require.NoError(t, err)

	wrapped, err := service.WrapKey(context.Background(), &pb.WrapKeyRequest{
		Backend:           backendName,
		KeyMaterial:       keyMaterial,
		WrappingPublicKey: params.WrappingPublicKey,
		Algorithm:         params.Algorithm,
		ImportToken:       params.ImportToken,
		KeySpec:           params.KeySpec,
	})
	require.NoError(t, err)
	require.NotEmpty(t, wrapped.WrappedKey)
	return wrapped
}

// TestUnwrapKey_UsesOnlyTheNamedBackend is the regression test for the unwrap
// oracle.
//
// UnwrapKey used to iterate every registered backend and return the first that
// answered without an error. Two consequences: the backend that served a
// request was whichever one map iteration reached first, and a caller could
// discover which backend held an unwrapping key purely from which attempt
// succeeded -- while every other configured backend performed an unwrap attempt
// on caller-supplied ciphertext for free.
//
// The shape here is two independent backends holding different key material
// behind their own import ceremonies. The discriminator is not that the call
// succeeds, but *which material comes back*, and that a blob belonging to one
// backend is refused when the other is named.
func TestUnwrapKey_UsesOnlyTheNamedBackend(t *testing.T) {
	service := setupTwoBackendService(t)

	alphaMaterial := []byte("alpha-key-material-32-bytes-long")
	betaMaterial := []byte("beta-key-material-32-bytes-long!")
	require.NotEqual(t, alphaMaterial, betaMaterial)

	alphaWrapped := importCeremony(t, service, "alpha", "shared-key-id", alphaMaterial)
	betaWrapped := importCeremony(t, service, "beta", "shared-key-id", betaMaterial)

	// Each backend answers with its own material, not the other's.
	alphaResp, err := service.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		Backend:           "alpha",
		WrappedKey:        alphaWrapped.WrappedKey,
		Algorithm:         alphaWrapped.Algorithm,
		ImportToken:       alphaWrapped.ImportToken,
		WrappingPublicKey: mustWrappingPub(t, service, "alpha"),
	})
	require.NoError(t, err)
	assert.Equal(t, alphaMaterial, alphaResp.KeyMaterial)

	betaResp, err := service.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		Backend:           "beta",
		WrappedKey:        betaWrapped.WrappedKey,
		Algorithm:         betaWrapped.Algorithm,
		ImportToken:       betaWrapped.ImportToken,
		WrappingPublicKey: mustWrappingPub(t, service, "beta"),
	})
	require.NoError(t, err)
	assert.Equal(t, betaMaterial, betaResp.KeyMaterial)

	// Naming beta with alpha's blob must fail. Under the old loop this
	// succeeded -- alpha was tried too -- and returned alpha's material to a
	// caller who named beta.
	crossed, err := service.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		Backend:           "beta",
		WrappedKey:        alphaWrapped.WrappedKey,
		Algorithm:         alphaWrapped.Algorithm,
		ImportToken:       alphaWrapped.ImportToken,
		WrappingPublicKey: mustWrappingPub(t, service, "beta"),
	})
	require.Error(t, err, "beta does not hold alpha's ceremony and must not answer for it")
	assert.Nil(t, crossed)
	assert.NotContains(t, err.Error(), string(alphaMaterial),
		"a refusal must not leak the material the other backend holds")
}

// TestUnwrapKey_RequiresBackend is the bad-input companion: a request that
// names no backend is refused outright rather than resolved by search.
func TestUnwrapKey_RequiresBackend(t *testing.T) {
	service := setupTwoBackendService(t)

	material := []byte("alpha-key-material-32-bytes-long")
	wrapped := importCeremony(t, service, "alpha", "unnamed-backend-key", material)

	resp, err := service.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
		WrappedKey:        wrapped.WrappedKey,
		Algorithm:         wrapped.Algorithm,
		ImportToken:       wrapped.ImportToken,
		WrappingPublicKey: mustWrappingPub(t, service, "alpha"),
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "backend is required")
}

// TestWrapKey_UsesOnlyTheNamedBackend proves the wrap half is bound to the
// named backend too: naming a backend that cannot import or export is refused
// as Unimplemented, even though another registered backend could have served
// it. The old loop skipped such a backend silently and let a different one
// answer, so the response described work the caller never asked for.
func TestWrapKey_UsesOnlyTheNamedBackend(t *testing.T) {
	service := setupTwoBackendService(t)

	params, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "wrap-binding-key",
		Backend:           "alpha",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "rsa",
		KeySize:           2048,
	})
	require.NoError(t, err)

	resp, err := service.WrapKey(context.Background(), &pb.WrapKeyRequest{
		Backend:           "no-import",
		KeyMaterial:       []byte("this-is-a-32-byte-key-material!!"),
		WrappingPublicKey: params.WrappingPublicKey,
		Algorithm:         params.Algorithm,
		ImportToken:       params.ImportToken,
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())

	// The same request naming a capable backend succeeds, so the refusal above
	// is about the named backend and nothing else.
	resp, err = service.WrapKey(context.Background(), &pb.WrapKeyRequest{
		Backend:           "alpha",
		KeyMaterial:       []byte("this-is-a-32-byte-key-material!!"),
		WrappingPublicKey: params.WrappingPublicKey,
		Algorithm:         params.Algorithm,
		ImportToken:       params.ImportToken,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKey)
}

// TestWrapKey_RequiresBackend is the bad-input companion for the wrap half.
func TestWrapKey_RequiresBackend(t *testing.T) {
	service := setupTwoBackendService(t)

	params, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "wrap-unnamed-key",
		Backend:           "alpha",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "rsa",
		KeySize:           2048,
	})
	require.NoError(t, err)

	resp, err := service.WrapKey(context.Background(), &pb.WrapKeyRequest{
		KeyMaterial:       []byte("this-is-a-32-byte-key-material!!"),
		WrappingPublicKey: params.WrappingPublicKey,
		Algorithm:         params.Algorithm,
		ImportToken:       params.ImportToken,
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "backend is required")
}

// mustWrappingPub runs a throwaway ceremony purely to obtain a well-formed DER
// public key for the named backend. UnwrapKey requires the field to be present
// and parseable; its value does not select the unwrapping key, which is chosen
// by the import token inside the named backend.
func mustWrappingPub(t *testing.T, service *Service, backendName string) []byte {
	t.Helper()
	params, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "throwaway-pub",
		Backend:           backendName,
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "rsa",
		KeySize:           2048,
	})
	require.NoError(t, err)
	return params.WrappingPublicKey
}

// TestEncryptAsym_HashNONERefusedNotPanic is the regression test for a remote
// denial of service.
//
// xkms.ResolveOAEPHash answers (crypto.Hash(0), nil) for the name "NONE" -- a
// legal answer meaning "no digest". This RPC took that answer and called
// hashFunc.New() on it, and crypto.Hash(0).New() panics. A request body of
// {"hash":"NONE"} therefore crashed the serving goroutine. The service layer
// has always refused it; the RPC now routes through that refusal.
//
// The call is made in-process, so a panic would fail the test rather than being
// converted into a status by a recovery interceptor.
func TestEncryptAsym_HashNONERefusedNotPanic(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "none-hash-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	})
	require.NoError(t, err)

	for _, spelling := range []string{"NONE", "none", "None"} {
		resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "none-hash-key",
			Backend:   "software",
			Plaintext: []byte("test data"),
			Hash:      spelling,
		})
		require.Error(t, err, "hash %q must be refused", spelling)
		assert.Nil(t, resp, "a refused request must return no ciphertext")

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Equal(t, oaepNoneHashRefusal, st.Message(),
			"the refusal must be the service layer's, verbatim")
	}

	// The service is still serving: the refusals returned, they did not unwind
	// the goroutine.
	resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
		KeyId:     "none-hash-key",
		Backend:   "software",
		Plaintext: []byte("test data"),
		Hash:      "SHA-256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

// TestGenerateKey_SymmetricAlgorithmNames pins the algorithm vocabulary this
// transport accepts for a symmetric key.
//
// It used to match the literal "symmetric" and nothing else, so every request
// that named its cipher outright -- which is what the service layer's own
// parsing accepts, and what every other transport sends -- was refused as an
// unsupported algorithm.
func TestGenerateKey_SymmetricAlgorithmNames(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	cases := []struct {
		algorithm string
		keySize   int32
		expect    types.SymmetricAlgorithm
	}{
		{"aes-256-gcm", 0, types.SymmetricAES256GCM},
		{"aes256-gcm", 0, types.SymmetricAES256GCM},
		{"AES-128-GCM", 0, types.SymmetricAES128GCM},
		{"aes-192-gcm", 0, types.SymmetricAES192GCM},
		{"chacha20-poly1305", 0, types.SymmetricChaCha20Poly1305},
		{"xchacha20-poly1305", 0, types.SymmetricXChaCha20Poly1305},
		// The bare names carry no cipher, so the key size selects one.
		{"symmetric", 128, types.SymmetricAES128GCM},
		{"secret", 0, types.SymmetricAES256GCM},
	}

	for _, tc := range cases {
		t.Run(tc.algorithm, func(t *testing.T) {
			keyID := "sym-" + tc.algorithm
			resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
				KeyId:     keyID,
				Backend:   "software",
				KeyType:   "secret",
				Algorithm: tc.algorithm,
				KeySize:   tc.keySize,
			})
			require.NoError(t, err)
			assert.Empty(t, resp.PublicKeyPem, "a symmetric key has no public half")

			// The cipher the request named is the cipher that was created.
			list, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{Backend: "software"})
			require.NoError(t, err)

			var found bool
			for _, k := range list.Keys {
				if k.KeyId == keyID {
					found = true
					assert.Equal(t, string(tc.expect), k.Algorithm)
				}
			}
			assert.True(t, found, "generated key %s must be listed", keyID)
		})
	}
}

// TestGenerateKey_UnknownAlgorithmStillRefused is the bad-input companion:
// widening the symmetric vocabulary must not turn the switch into a catch-all.
func TestGenerateKey_UnknownAlgorithmStillRefused(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	for _, algorithm := range []string{"aes-512-gcm", "chacha", "rot13", "aes"} {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "bad-" + algorithm,
			Backend:   "software",
			KeyType:   "secret",
			Algorithm: algorithm,
		})
		require.Error(t, err, "algorithm %q must be refused", algorithm)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	}
}

// TestListKeys_KeyTypeRenderedAsName pins the wire rendering of
// KeyAttributes.KeyType.
//
// types.KeyType is a uint8, so string(attr.KeyType) is an integer-to-rune
// conversion: the wire carried the control character whose code point equals
// the constant instead of the type's name. go vet's stringintconv analyzer does
// not flag it, because it exempts byte-width integer types.
func TestListKeys_KeyTypeRenderedAsName(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:     "typed-key",
		Backend:   "software",
		KeyType:   "signing",
		Algorithm: "rsa",
		KeySize:   2048,
	})
	require.NoError(t, err)

	list, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{Backend: "software"})
	require.NoError(t, err)

	var found bool
	for _, k := range list.Keys {
		if k.KeyId != "typed-key" {
			continue
		}
		found = true
		assert.Equal(t, types.KeyTypeSigning.String(), k.KeyType)
		for _, r := range k.KeyType {
			assert.False(t, unicode.IsControl(r),
				"key_type %q carries a control character, so the uint8 was converted to a rune", k.KeyType)
		}
	}
	require.True(t, found, "the generated key must be listed")

	// GetKey renders it the same way.
	got, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "typed-key",
		Backend: "software",
	})
	require.NoError(t, err)
	require.NotNil(t, got.Key)
	assert.Equal(t, types.KeyTypeSigning.String(), got.Key.KeyType)
	for _, r := range got.Key.KeyType {
		assert.False(t, unicode.IsControl(r),
			"key_type %q carries a control character, so the uint8 was converted to a rune", got.Key.KeyType)
	}
}
