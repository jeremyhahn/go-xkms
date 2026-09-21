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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ===========================================================================
// GenerateKey: the parameters the request carries
// ===========================================================================

// TestGenerateKeyHonoursTheRequestedCurve pins that the named curve is the
// curve that gets generated.
//
// buildKeyAttributes used to answer any curve name it could not parse with
// elliptic.P256() and report success, so a caller that asked for P-384 and
// received a P-256 key had nothing in the response to tell it so. The public
// key the service returns is checked here, not the attributes, because the
// substitution was invisible at the attribute level too -- P-256 is a
// perfectly valid ECCAttributes value.
func TestGenerateKeyHonoursTheRequestedCurve(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	curves := map[string]elliptic.Curve{
		"P-256": elliptic.P256(),
		"P-384": elliptic.P384(),
		"P-521": elliptic.P521(),
	}

	for name, want := range curves {
		t.Run(name, func(t *testing.T) {
			resp, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
				KeyID:     "curve-" + name,
				Backend:   "software",
				Algorithm: "ecdsa",
				Curve:     name,
			})
			require.NoError(t, err)

			block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
			require.NotNil(t, block)
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			require.NoError(t, err)
			ecPub, ok := pub.(*ecdsa.PublicKey)
			require.True(t, ok)
			assert.Equal(t, want, ecPub.Curve)
		})
	}

	t.Run("an unparseable curve is refused", func(t *testing.T) {
		_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID:     "curve-bogus",
			Backend:   "software",
			Algorithm: "ecdsa",
			Curve:     "P-999",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidCurve)
	})
}

// TestBuildKeyAttributesRecordsTheRequestedHash pins that
// GenerateKeyRequest.Hash reaches the key's attributes.
//
// The field was accepted and then never assigned, so every key generated
// through this service named no digest at all whatever the caller asked for.
func TestBuildKeyAttributesRecordsTheRequestedHash(t *testing.T) {
	t.Run("the named hash is recorded", func(t *testing.T) {
		attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
			KeyID:     "hashed",
			Algorithm: "ecdsa",
			Hash:      "SHA-384",
		}, "software", types.StoreSoftware)
		require.NoError(t, err)
		assert.Equal(t, crypto.SHA384, attrs.Hash)
	})

	t.Run("an unspecified hash takes the documented default", func(t *testing.T) {
		attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
			KeyID:     "unhashed",
			Algorithm: "ecdsa",
		}, "software", types.StoreSoftware)
		require.NoError(t, err)
		assert.Equal(t, crypto.SHA256, attrs.Hash)
	})

	t.Run("an unresolvable hash is refused", func(t *testing.T) {
		_, err := buildKeyAttributes(&transport.GenerateKeyRequest{
			KeyID:     "bad-hash",
			Algorithm: "ecdsa",
			Hash:      "SHA-3000",
		}, "software", types.StoreSoftware)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidHashFunction)
	})

	t.Run("the NONE sentinel is not a key attribute", func(t *testing.T) {
		// NONE means "these bytes are already the digest" for one signing
		// operation. Recording it would leave Hash at crypto.Hash(0), whose
		// New method panics wherever the attribute is later used.
		_, err := buildKeyAttributes(&transport.GenerateKeyRequest{
			KeyID:     "none-hash",
			Algorithm: "ecdsa",
			Hash:      "NONE",
		}, "software", types.StoreSoftware)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidHashFunction)
	})
}

// TestGenerateKeyRefusesAnUnresolvableHash checks the same refusal end to end,
// so the validation cannot be lost by a caller that skips buildKeyAttributes.
func TestGenerateKeyRefusesAnUnresolvableHash(t *testing.T) {
	svc := setupDeriveService(t)

	_, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "bad-hash",
		Backend:   "software",
		Algorithm: "ecdsa",
		Hash:      "SHA-3000",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidHashFunction)
}

// TestGenerateKeyUsesTheCanonicalKeyTypeVocabulary pins that a key's purpose
// is read with types.ParseKeyType, the vocabulary every transport already uses
// for the same field.
//
// It used to be read with types.ParseCLIKeyType, which knows six of the
// thirteen purpose names. A request for a "ca", "attestation", "idevid",
// "storage" or "tpm" key silently became a signing key here while the same
// string became the named purpose in the transports that build their own
// attributes -- and the purpose is part of types.KeyAttributes.ID(), so the
// two paths stored the same request's key in two different places. The stored
// identifier is what this checks: ListKeys reads it back from storage.
func TestGenerateKeyUsesTheCanonicalKeyTypeVocabulary(t *testing.T) {
	purposes := []struct {
		keyType string
		want    string
	}{
		{keyType: "ca", want: "CA"},
		{keyType: "attestation", want: "ATTESTATION"},
		{keyType: "storage", want: "STORAGE"},
		{keyType: "tls", want: "TLS"},
		{keyType: "signing", want: "SIGNING"},
	}

	for _, p := range purposes {
		t.Run(p.keyType, func(t *testing.T) {
			svc := setupDeriveService(t)
			ctx := context.Background()
			keyID := "purpose-" + p.keyType

			_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
				KeyID:     keyID,
				Backend:   "software",
				KeyType:   p.keyType,
				Algorithm: "ecdsa",
			})
			require.NoError(t, err)

			list, err := svc.ListKeys(ctx, "software")
			require.NoError(t, err)

			var found *transport.KeyInfo
			for i := range list.Keys {
				if list.Keys[i].KeyID == keyID {
					found = &list.Keys[i]
					break
				}
			}
			require.NotNil(t, found)
			assert.Equal(t, p.want, found.KeyType)
		})
	}
}

// TestGenerateKeyHonoursPartition pins that the partition reaches the key's
// identity. GenerateKeyRequest could not express one at all, so a partitioned
// key could not be created through this service however the caller asked.
func TestGenerateKeyHonoursPartition(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "partitioned",
		Algorithm: "ecdsa",
		Partition: "tenant-a",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, types.Partition("tenant-a"), attrs.Partition)
	assert.Contains(t, attrs.ID(), "tenant-a",
		"the partition is part of the key's identity, so it must appear in the identifier")
}

// TestImportKeyHonoursPartition pins the same for an import.
func TestImportKeyHonoursPartition(t *testing.T) {
	attrs, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:     "partitioned",
		KeyType:   "ecdsa",
		Partition: "tenant-a",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, types.Partition("tenant-a"), attrs.Partition)
	assert.Contains(t, attrs.ID(), "tenant-a")
}

// ===========================================================================
// ListKeys pagination
// ===========================================================================

// TestListKeysPaginates pins that the list options are honoured.
//
// They were accepted and ignored: every caller asking for a page received the
// whole key list with a zero-valued PageResponse describing it as page 0 of 0.
func TestListKeysPaginates(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	const total = 7
	for i := 0; i < total; i++ {
		_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID:     fmt.Sprintf("paged-%02d", i),
			Backend:   "software",
			Algorithm: "ecdsa",
		})
		require.NoError(t, err)
	}

	t.Run("no options returns everything", func(t *testing.T) {
		resp, err := svc.ListKeys(ctx, "software")
		require.NoError(t, err)
		assert.Len(t, resp.Keys, total)
		assert.Equal(t, total, resp.Total)
		assert.False(t, resp.HasMore)
	})

	t.Run("a page is the requested size", func(t *testing.T) {
		resp, err := svc.ListKeys(ctx, "software", transport.WithPage(1), transport.WithPageSize(3))
		require.NoError(t, err)
		assert.Len(t, resp.Keys, 3)
		assert.Equal(t, 1, resp.Page)
		assert.Equal(t, 3, resp.PageSize)
		assert.Equal(t, total, resp.Total)
		assert.True(t, resp.HasMore)
	})

	t.Run("the last page is short and has no more", func(t *testing.T) {
		resp, err := svc.ListKeys(ctx, "software", transport.WithPage(3), transport.WithPageSize(3))
		require.NoError(t, err)
		assert.Len(t, resp.Keys, 1)
		assert.False(t, resp.HasMore)
	})

	t.Run("a page past the end is empty rather than an error", func(t *testing.T) {
		resp, err := svc.ListKeys(ctx, "software", transport.WithPage(99), transport.WithPageSize(3))
		require.NoError(t, err)
		assert.Empty(t, resp.Keys)
		assert.Equal(t, total, resp.Total)
		assert.False(t, resp.HasMore)
	})

	t.Run("pages do not overlap or skip", func(t *testing.T) {
		seen := make(map[string]int)
		for page := 1; page <= 4; page++ {
			resp, err := svc.ListKeys(ctx, "software", transport.WithPage(page), transport.WithPageSize(2))
			require.NoError(t, err)
			for _, k := range resp.Keys {
				seen[k.KeyID]++
			}
		}
		assert.Len(t, seen, total)
		for id, count := range seen {
			assert.Equal(t, 1, count, "key %s appeared on more than one page", id)
		}
	})
}

// ===========================================================================
// WrapKey / UnwrapKey parameter threading
// ===========================================================================

// recordingIEProvider is a key provider that records the import parameters and
// wrapped material it is handed.
//
// A recording double is the right instrument here and a real backend is not:
// the claim under test is "the service passes on what the request carried",
// and no backend in this repository echoes KeySpec or Metadata back out where
// a test could observe it. The claims that need a real backend -- that an
// imported key is the key that was imported -- are tested against one in
// servicer_key_import_test.go.
type recordingIEProvider struct {
	wrappingKey *rsa.PrivateKey

	wrapParams   *backend.ImportParameters
	unwrapParams *backend.ImportParameters
	unwrapped    *backend.WrappedKeyMaterial
	imported     *backend.WrappedKeyMaterial
	importAttrs  *types.KeyAttributes
}

func newRecordingIEProvider(t *testing.T) *recordingIEProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &recordingIEProvider{wrappingKey: key}
}

func (p *recordingIEProvider) Type() types.BackendType { return types.BackendTypeSoftware }

func (p *recordingIEProvider) Capabilities() types.Capabilities { return types.Capabilities{} }

func (p *recordingIEProvider) GenerateKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not supported")
}

func (p *recordingIEProvider) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not supported")
}

func (p *recordingIEProvider) DeleteKey(context.Context, *types.KeyAttributes) error { return nil }

func (p *recordingIEProvider) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	return nil, nil
}

func (p *recordingIEProvider) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not supported")
}

func (p *recordingIEProvider) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not supported")
}

func (p *recordingIEProvider) RotateKey(context.Context, *types.KeyAttributes) error { return nil }

func (p *recordingIEProvider) Close() error { return nil }

func (p *recordingIEProvider) GetImportParameters(_ context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{
		WrappingPublicKey: &p.wrappingKey.PublicKey,
		ImportToken:       []byte("recorded-token"),
		Algorithm:         algorithm,
		KeySpec:           "RECORDED_" + string(attrs.SymmetricAlgorithm),
	}, nil
}

func (p *recordingIEProvider) WrapKey(_ context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	p.wrapParams = params
	return &backend.WrappedKeyMaterial{
		WrappedKey:  append([]byte("wrapped:"), keyMaterial...),
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    map[string]string{"origin": "recording-provider"},
	}, nil
}

func (p *recordingIEProvider) UnwrapKey(_ context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	p.unwrapParams = params
	p.unwrapped = wrapped
	return []byte("unwrapped"), nil
}

func (p *recordingIEProvider) ImportKey(_ context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	p.importAttrs = attrs
	p.imported = wrapped
	return nil
}

func (p *recordingIEProvider) ExportKey(context.Context, *types.KeyAttributes, backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return nil, errors.New("not supported")
}

func (p *recordingIEProvider) ExportKeyMaterial(context.Context, *types.KeyAttributes) ([]byte, error) {
	return nil, errors.New("not supported")
}

var _ backend.ImportExportBackend = (*recordingIEProvider)(nil)

// setupRecordingIEService brings up a service whose only backend records what
// the servicer hands it.
func setupRecordingIEService(t *testing.T) (*XKMSService, *recordingIEProvider) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	provider := newRecordingIEProvider(t)
	store := newMockKeyStore("recording")
	store.backend = provider

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"recording": store},
		DefaultBackend: "recording",
	}))

	svc, err := Get()
	require.NoError(t, err)
	return svc, provider
}

// TestWrapKeyThreadsTheCeremonyFields pins the fields an AWS-KMS-style import
// ceremony reads.
//
// WrapKey dropped the request's KeySpec on the way in and the backend's
// Metadata on the way out, so a transport routed through it could not run
// those ceremonies at all -- which is why the gRPC transport still builds its
// own import parameters.
func TestWrapKeyThreadsTheCeremonyFields(t *testing.T) {
	svc, provider := setupRecordingIEService(t)

	pubDER, err := x509.MarshalPKIXPublicKey(&provider.wrappingKey.PublicKey)
	require.NoError(t, err)

	resp, err := svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend:           "recording",
		KeyMaterial:       []byte("material"),
		Algorithm:         string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
		WrappingPublicKey: pubDER,
		ImportToken:       []byte("token"),
		KeySpec:           "RSA_4096",
	})
	require.NoError(t, err)

	require.NotNil(t, provider.wrapParams)
	assert.Equal(t, "RSA_4096", provider.wrapParams.KeySpec,
		"the key spec names the kind of key being wrapped for and must reach the backend")
	assert.Equal(t, map[string]string{"origin": "recording-provider"}, resp.Metadata,
		"the backend's metadata travels with the blob to ImportKey")
}

// TestWrapKeyRejectsAnUnparseableWrappingKey covers the bad-input side: the
// wrapping key is DER and a request that carries something else must be
// refused before any material is wrapped.
func TestWrapKeyRejectsAnUnparseableWrappingKey(t *testing.T) {
	svc, provider := setupRecordingIEService(t)

	_, err := svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend:           "recording",
		KeyMaterial:       []byte("material"),
		Algorithm:         string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
		WrappingPublicKey: []byte("not DER"),
	})
	require.Error(t, err)
	assert.Nil(t, provider.wrapParams, "nothing may be wrapped once the request is known to be unusable")
}

// TestUnwrapKeyThreadsTheCeremonyFields pins the three fields UnwrapKey used to
// drop: the key spec, the metadata that accompanied the wrapped material, and
// the wrapping public key a backend holding several key pairs needs in order to
// choose the right private one.
func TestUnwrapKeyThreadsTheCeremonyFields(t *testing.T) {
	svc, provider := setupRecordingIEService(t)

	pubDER, err := x509.MarshalPKIXPublicKey(&provider.wrappingKey.PublicKey)
	require.NoError(t, err)

	metadata := map[string]string{"origin": "external"}

	_, err = svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend:            "recording",
		WrappedKeyMaterial: []byte("wrapped"),
		Algorithm:          string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
		ImportToken:        []byte("token"),
		WrappingPublicKey:  pubDER,
		KeySpec:            "AES_256",
		Metadata:           metadata,
	})
	require.NoError(t, err)

	require.NotNil(t, provider.unwrapParams)
	assert.Equal(t, "AES_256", provider.unwrapParams.KeySpec)
	assert.Equal(t, &provider.wrappingKey.PublicKey, provider.unwrapParams.WrappingPublicKey)

	require.NotNil(t, provider.unwrapped)
	assert.Equal(t, metadata, provider.unwrapped.Metadata)
}

// TestUnwrapKeyRejectsAnUnparseableWrappingKey covers the bad-input side. The
// field is optional, so an absent key is fine; a present but unusable one is
// not, and must be reported rather than ignored.
func TestUnwrapKeyRejectsAnUnparseableWrappingKey(t *testing.T) {
	svc, provider := setupRecordingIEService(t)

	_, err := svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend:            "recording",
		WrappedKeyMaterial: []byte("wrapped"),
		Algorithm:          string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
		WrappingPublicKey:  []byte("not DER"),
	})
	require.Error(t, err)
	assert.Nil(t, provider.unwrapParams, "nothing may be unwrapped once the request is known to be unusable")

	svc, provider = setupRecordingIEService(t)
	_, err = svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend:            "recording",
		WrappedKeyMaterial: []byte("wrapped"),
		Algorithm:          string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.NoError(t, err, "the wrapping public key is optional")
	require.NotNil(t, provider.unwrapParams)
	assert.Nil(t, provider.unwrapParams.WrappingPublicKey)
}

// TestImportKeyThreadsMetadata pins that the request's metadata reaches the
// backend's ImportKey. The gRPC ImportKeyRequest message has always carried it
// and the transport struct could not represent it, so every transport routed
// through the servicer dropped it.
func TestImportKeyThreadsMetadata(t *testing.T) {
	svc, provider := setupRecordingIEService(t)

	metadata := map[string]string{"origin": "external", "ceremony": "byok"}

	_, err := svc.ImportKey(context.Background(), &transport.ImportKeyRequest{
		Backend:            "recording",
		KeyID:              "imported",
		KeyType:            "ed25519",
		WrappedKeyMaterial: []byte("wrapped"),
		Algorithm:          string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
		ImportToken:        []byte("token"),
		Metadata:           metadata,
	})
	require.NoError(t, err)

	require.NotNil(t, provider.imported)
	assert.Equal(t, metadata, provider.imported.Metadata)

	require.NotNil(t, provider.importAttrs)
	assert.Equal(t, x509.Ed25519, provider.importAttrs.KeyAlgorithm,
		"the attributes handed to the backend must name the algorithm the request did")
}
