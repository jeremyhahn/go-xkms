package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListBackends_Success(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)

	backends, err := svc.ListBackends(context.Background())
	require.NoError(t, err)
	assert.Len(t, backends, 2)

	ids := make(map[string]bool)
	for _, b := range backends {
		ids[b.ID] = true
		assert.NotEmpty(t, b.Type)
		assert.NotNil(t, b.Capabilities)
	}
	assert.True(t, ids["software"])
	assert.True(t, ids["pkcs11"])
}

func TestListBackends_CapabilitiesPopulated(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)

	backends, err := svc.ListBackends(context.Background())
	require.NoError(t, err)

	for _, b := range backends {
		// mockKeyProvider returns Keys:true, Signing:true, Decryption:true
		assert.True(t, b.Capabilities.Keys)
		assert.True(t, b.Capabilities.Signing)
		assert.True(t, b.Capabilities.Decryption)
	}
}

func TestServicerGetBackend_Success(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)

	info, err := svc.GetBackend(context.Background(), "software")
	require.NoError(t, err)
	assert.Equal(t, "software", info.ID)
	assert.NotEmpty(t, info.Type)
}

func TestServicerGetBackend_NotFound(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)

	_, err := svc.GetBackend(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendNotFound))
}

func TestGetBackend_InvalidName(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)

	_, err := svc.GetBackend(context.Background(), "../bad")
	require.Error(t, err)
}
