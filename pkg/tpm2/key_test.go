package tpm2

import (
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

func TestHierarchyValidation(t *testing.T) {
	t.Run("endorsement hierarchy is valid", func(t *testing.T) {
		hierarchy := tpm2.TPMRHEndorsement
		assert.Equal(t, tpm2.TPMRHEndorsement, hierarchy)
	})

	t.Run("owner hierarchy is valid", func(t *testing.T) {
		hierarchy := tpm2.TPMRHOwner
		assert.Equal(t, tpm2.TPMRHOwner, hierarchy)
	})

	t.Run("platform hierarchy is valid", func(t *testing.T) {
		hierarchy := tpm2.TPMRHPlatform
		assert.Equal(t, tpm2.TPMRHPlatform, hierarchy)
	})

	t.Run("null hierarchy is valid", func(t *testing.T) {
		hierarchy := tpm2.TPMRHNull
		assert.Equal(t, tpm2.TPMRHNull, hierarchy)
	})

	t.Run("ParseHierarchy returns endorsement for ENDORSEMENT", func(t *testing.T) {
		h, err := ParseHierarchy("ENDORSEMENT")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMRHEndorsement, h)
	})

	t.Run("ParseHierarchy returns owner for OWNER", func(t *testing.T) {
		h, err := ParseHierarchy("OWNER")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMRHOwner, h)
	})

	t.Run("ParseHierarchy returns platform for PLATFORM", func(t *testing.T) {
		h, err := ParseHierarchy("PLATFORM")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMRHPlatform, h)
	})

	t.Run("ParseHierarchy returns error for invalid hierarchy", func(t *testing.T) {
		_, err := ParseHierarchy("INVALID")
		assert.Equal(t, ErrInvalidHierarchyType, err)
	})

	t.Run("HierarchyName returns ENDORSEMENT for TPMRHEndorsement", func(t *testing.T) {
		name, err := HierarchyName(tpm2.TPMRHEndorsement)
		assert.NoError(t, err)
		assert.Equal(t, "ENDORSEMENT", name)
	})

	t.Run("HierarchyName returns OWNER for TPMRHOwner", func(t *testing.T) {
		name, err := HierarchyName(tpm2.TPMRHOwner)
		assert.NoError(t, err)
		assert.Equal(t, "OWNER", name)
	})

	t.Run("HierarchyName returns PLATFORM for TPMRHPlatform", func(t *testing.T) {
		name, err := HierarchyName(tpm2.TPMRHPlatform)
		assert.NoError(t, err)
		assert.Equal(t, "PLATFORM", name)
	})

	t.Run("HierarchyName returns NULL for TPMRHNull", func(t *testing.T) {
		name, err := HierarchyName(tpm2.TPMRHNull)
		assert.NoError(t, err)
		assert.Equal(t, "NULL", name)
	})
}

func TestSSRKAttributes_NilSSRKConfig(t *testing.T) {
	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{SSRK: nil},
	}
	attrs, err := tpm.SSRKAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrSSRKConfigNil)
}
