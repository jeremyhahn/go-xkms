package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

func TestGUIIPCHandler_HandleVaultUnlockKeyFactor_NoFingerprints(t *testing.T) {
	h := &guiIPCHandler{app: newLifecycleApp(t)}

	result, err := h.HandleVaultUnlockKeyFactor("https://kms.example.com", nil)

	require.ErrorIs(t, err, services.ErrBrowserVaultNoKeyFactor)
	assert.Nil(t, result, "a refused unlock must not report a vault state")
}

func TestGUIIPCHandler_HandleVaultUnlockKeyFactor_NoVaultClient(t *testing.T) {
	h := &guiIPCHandler{app: newLifecycleApp(t)}

	result, err := h.HandleVaultUnlockKeyFactor("https://kms.example.com", []string{"SHA256:abc"})

	require.ErrorIs(t, err, services.ErrStaticPWNoClient)
	assert.Nil(t, result)
}
