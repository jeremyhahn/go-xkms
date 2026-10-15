package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// TestApp_InitializeSSHServices_UnopenableStoreDisablesSSH verifies that an
// SSH store that cannot be opened leaves SSH unavailable instead of half
// wired.
func TestApp_InitializeSSHServices_UnopenableStoreDisablesSSH(t *testing.T) {
	app := newWiredApp(t)
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))

	app.initializeSSHServices(notADir, nil)

	_, err := app.sshService.ListKeys()
	assert.ErrorIs(t, err, services.ErrSSHUnavailable)
}

// TestApp_SSHKeysMintOnXKMSBackends verifies that SSH keys are minted on the
// xkms backend the user picks, and that a backend xkms does not have is
// refused without storing a key.
func TestApp_SSHKeysMintOnXKMSBackends(t *testing.T) {
	app := newPIVReadyApp(t)

	key, err := app.sshService.GenerateKey(services.SSHGenerateParams{Name: "laptop", Backend: "software"})
	require.NoError(t, err)
	require.NotNil(t, key)

	_, err = app.sshService.GenerateKey(services.SSHGenerateParams{Name: "ghost", Backend: "no-such-backend"})
	require.Error(t, err)

	keys, err := app.sshService.ListKeys()
	require.NoError(t, err)
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, k.Name)
	}
	assert.Equal(t, []string{"laptop"}, names)
}
