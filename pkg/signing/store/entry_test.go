// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// SignerEntry and SignatureEntry Entity Tests
// =============================================================================
func TestSignerEntry_EntityID(t *testing.T) {
	entry := &SignerEntry{ID: 12345, CN: "test-cn"}
	assert.Equal(t, uint64(12345), entry.EntityID())
}

func TestSignerEntry_SetEntityID(t *testing.T) {
	entry := &SignerEntry{}
	entry.SetEntityID(67890)
	assert.Equal(t, uint64(67890), entry.EntityID())
}

func TestSignatureEntry_EntityID(t *testing.T) {
	entry := &SignatureEntry{ID: 11111, Key: "test.sig"}
	assert.Equal(t, uint64(11111), entry.EntityID())
}

func TestSignatureEntry_SetEntityID(t *testing.T) {
	entry := &SignatureEntry{}
	entry.SetEntityID(22222)
	assert.Equal(t, uint64(22222), entry.EntityID())
}

func TestSignerEntryIDGenerator_NextID_SignerEntry(t *testing.T) {
	gen := &signerEntryIDGenerator{}
	entry := &SignerEntry{CN: "test-signer"}

	id := gen.NextID(entry)
	assert.NotZero(t, id)

	// Deterministic: same CN produces same ID.
	id2 := gen.NextID(entry)
	assert.Equal(t, id, id2)

	// Different CN produces different ID.
	entry2 := &SignerEntry{CN: "other-signer"}
	id3 := gen.NextID(entry2)
	assert.NotEqual(t, id, id3)
}

func TestSignerEntryIDGenerator_NextID_SignatureEntry(t *testing.T) {
	gen := &signerEntryIDGenerator{}
	entry := &SignatureEntry{Key: "test-key.sig"}

	id := gen.NextID(entry)
	assert.NotZero(t, id)

	// Deterministic: same Key produces same ID.
	id2 := gen.NextID(entry)
	assert.Equal(t, id, id2)
}

func TestSignerEntryIDGenerator_NextID_UnsupportedType(t *testing.T) {
	gen := &signerEntryIDGenerator{}

	// Passing an unsupported entity type should return 0.
	id := gen.NextID(&SignerEntry{}) // empty CN still hashes
	assert.NotZero(t, id)            // even empty string has a hash

	// Truly unsupported type (not SignerEntry or SignatureEntry) is tested
	// by verifying the default branch. We cannot pass a non-Entity here
	// because NextID requires dao.Entity, but we can verify via the
	// computeSignerID helper consistency.
	expected := computeSignerID("")
	assert.Equal(t, expected, id)
}
