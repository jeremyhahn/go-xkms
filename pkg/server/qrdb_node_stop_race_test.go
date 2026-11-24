package server

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestQRDBNodeStop_RacesNodeStartGoroutine starts the qrdb storage the way the
// out-of-band CA reader does and stops it at once, a few times over the same
// data directory. Under -race it reports any field the node start goroutine
// writes while stopQRDBNode reads it (#2332).
func TestQRDBNodeStop_RacesNodeStartGoroutine(t *testing.T) {
	dataDir := t.TempDir()
	for i := 0; i < 5; i++ {
		s := &Server{
			config: &config.Config{
				Datastore: config.DatastoreConfig{Path: filepath.Join(dataDir, "storage")},
			},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		require.NoError(t, s.initializeQRDBStorage())
		require.NoError(t, s.closeQRDBStorage())
	}
}
