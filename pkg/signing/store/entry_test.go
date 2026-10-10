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
