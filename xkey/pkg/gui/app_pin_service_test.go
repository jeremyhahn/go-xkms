package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

func TestApp_InitPINService_NoDataDirLeavesPINUnwired(t *testing.T) {
	app := newLifecycleApp(t)
	app.dataDir = ""

	app.initPINService()

	assert.Empty(t, app.pinService.Strategy(), "no PIN backend may be wired without a data directory")
}

func TestApp_InitPINService_WithoutTPMUsesSoftwareStrategy(t *testing.T) {
	app := newLifecycleApp(t)
	app.dataDir = t.TempDir()

	app.initPINService()

	assert.Equal(t, string(qrdbsdk.PINStrategySoftware), app.pinService.Strategy(),
		"with no TPM the PIN service falls back to the software strategy")
	assert.False(t, app.pinService.IsPINSet(), "a fresh PIN store has no user PIN")
}

func TestApp_InitPINService_UnusableDataDirLeavesPINUnwired(t *testing.T) {
	app := newLifecycleApp(t)
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	app.dataDir = notADir

	app.initPINService()

	assert.Empty(t, app.pinService.Strategy(), "a PIN backend that cannot be resolved must not be wired")
}
