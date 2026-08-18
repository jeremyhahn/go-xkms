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

package quantum

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSealSeedLeavesSourceIntact is the property the four construction sites
// depend on: sealing must copy, because every caller still needs its buffer
// afterwards — for the metadata that gets serialized, or because the buffer
// belongs to its own caller.
func TestSealSeedLeavesSourceIntact(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	before := make([]byte, len(src))
	copy(before, src)

	sealed, err := sealSeed(src)
	require.NoError(t, err)
	defer sealed.Destroy()

	assert.Equal(t, before, src, "sealSeed must not wipe its argument")

	buf, err := sealed.Open()
	require.NoError(t, err)
	defer buf.Destroy()
	assert.Equal(t, before, buf.Bytes(), "the enclave must hold what it was given")
}

func TestSealSeed_RejectsEmpty(t *testing.T) {
	sealed, err := sealSeed(nil)
	require.Error(t, err, "an empty seed cannot be sealed and must not be silently accepted")
	assert.Nil(t, sealed)
}

// TestGeneratedSeedIsEnclavedAndPersistable checks that the split between the
// enclaved in-memory seed and the plaintext seed written to storage keeps both
// intact: an earlier shape shared one backing array, so sealing one zeroed the
// other and the stored key became unreconstructable.
func TestGeneratedSeedIsEnclavedAndPersistable(t *testing.T) {
	tests := []struct {
		name string
		gen  func(*QuantumBackend) (any, *keyMetadata, error)
	}{
		{
			name: "ML-DSA",
			gen: func(b *QuantumBackend) (any, *keyMetadata, error) {
				return wrapMLDSA(b.generateMLDSAKey("ML-DSA-65"))
			},
		},
		{
			name: "ML-KEM",
			gen: func(b *QuantumBackend) (any, *keyMetadata, error) {
				return wrapMLKEM(b.generateMLKEMKey("ML-KEM-768", "enclave-kem"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb, _ := newTestBackend(t)
			defer func() { _ = qb.Close() }()

			key, metadata, err := tt.gen(qb)
			require.NoError(t, err)

			require.NotEmpty(t, metadata.Seed)
			assert.False(t, bytes.Equal(metadata.Seed, make([]byte, len(metadata.Seed))),
				"the persisted seed must not have been zeroed by sealing the in-memory one")

			exported := exportSeed(t, key)
			assert.Equal(t, metadata.Seed, exported,
				"the enclaved seed and the persisted seed must agree")
		})
	}
}

// TestLoadedKeyDoesNotConsumeMetadataSeed covers the reload path: metadata.Seed
// belongs to the caller and several keys may be built from the same metadata.
func TestLoadedKeyDoesNotConsumeMetadataSeed(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("reload-kem", types.QuantumAlgorithmMLKEM768)
	_, err := qb.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	_, metadata, err := qb.generateMLKEMKey("ML-KEM-768", "reload-kem")
	require.NoError(t, err)

	before := make([]byte, len(metadata.Seed))
	copy(before, metadata.Seed)

	first, err := qb.loadMLKEMKey(metadata, "reload-kem")
	require.NoError(t, err)
	assert.Equal(t, before, metadata.Seed, "loading must not wipe metadata.Seed")

	second, err := qb.loadMLKEMKey(metadata, "reload-kem")
	require.NoError(t, err)

	assert.Equal(t, before, first.ExportSecretKey())
	assert.Equal(t, before, second.ExportSecretKey())
}

// wrapMLDSA and wrapMLKEM adapt the concrete generator signatures to the shared
// table above.
func wrapMLDSA(k *MLDSAPrivateKey, m *keyMetadata, err error) (any, *keyMetadata, error) {
	return k, m, err
}

func wrapMLKEM(k *MLKEMPrivateKey, m *keyMetadata, err error) (any, *keyMetadata, error) {
	return k, m, err
}

func exportSeed(t *testing.T, key any) []byte {
	t.Helper()
	switch k := key.(type) {
	case *MLDSAPrivateKey:
		return k.ExportSecretKey()
	case *MLKEMPrivateKey:
		return k.ExportSecretKey()
	default:
		t.Fatalf("unexpected key type %T", key)
		return nil
	}
}

// TestStoreKeyWipesTheSeed pins the persistence window: the plaintext seed that
// has to exist for encoding/json must not outlive the store call.
func TestStoreKeyWipesTheSeed(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	_, metadata, err := qb.generateMLKEMKey("ML-KEM-768", "wipe-kem")
	require.NoError(t, err)
	require.NotEmpty(t, metadata.Seed)

	seed := metadata.Seed
	require.NoError(t, qb.storeKey(context.Background(), "wipe-kem", metadata))

	assert.Equal(t, make([]byte, len(seed)), seed,
		"storeKey must wipe the plaintext seed it serialized")
}

// TestStoredKeyStillLoadsAfterWipe is the other half: wiping the in-memory seed
// must not damage what was written, or every generated key would be lost on
// restart.
func TestStoredKeyStillLoadsAfterWipe(t *testing.T) {
	qb, _ := newTestBackend(t)
	defer func() { _ = qb.Close() }()

	attrs := mlkemAttrs("roundtrip-kem", types.QuantumAlgorithmMLKEM768)
	generated, err := qb.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	loaded, err := qb.GetKey(context.Background(), attrs)
	require.NoError(t, err)

	want := generated.(*MLKEMPrivateKey).ExportSecretKey()
	got := loaded.(*MLKEMPrivateKey).ExportSecretKey()
	require.NotEmpty(t, want)
	assert.Equal(t, want, got,
		"the stored seed must survive the wipe and reconstruct the same key")
}
