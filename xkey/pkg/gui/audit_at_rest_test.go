package gui

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// TestInitializeDataDir_AuditAtRestIsSealedUnderTheBarrier pins that, once
// the data directory opens with the barrier unsealed, no audit record is
// stored in plaintext anywhere under the xkey home, while the events still
// read back and their hash chain verifies.
func TestInitializeDataDir_AuditAtRestIsSealedUnderTheBarrier(t *testing.T) {
	app := newMinimalApp(t)
	require.NoError(t, app.barrierService.Initialize("test-password", "passphrase"))
	require.NotNil(t, app.barrierService.GetBackend())
	require.NoError(t, app.initializeDataDir())

	const (
		op     = audit.OperationType("canary-op-5d1e9b")
		keyID  = "canary-key-7f3a42"
		device = "canary-device-91c2d8"
		detail = "canary-detail-c04e6f"
	)
	require.NoError(t, app.auditStore.LogCryptoOperation(op, "software", keyID, device, device, true, nil, 7))
	require.NoError(t, app.auditStore.LogServiceEvent(op, map[string]any{"note": detail}))

	home := os.Getenv("XKEY_HOME")
	require.NotEmpty(t, home)
	files := 0
	require.NoError(t, filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files++
		for _, field := range []string{string(op), keyID, device, detail} {
			assert.False(t, bytes.Contains(raw, []byte(field)),
				"%s holds the audit field %q in plaintext", path, field)
		}
		return nil
	}))
	require.Positive(t, files)

	got := app.auditStore.Query(audit.QueryFilter{Operation: op})
	require.Len(t, got, 2)
	assert.Equal(t, keyID, got[0].KeyID)
	assert.Equal(t, detail, got[1].Details["note"])
	require.NoError(t, app.auditStore.VerifyChain(context.Background()))
}
