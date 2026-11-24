package server

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestQRDBNodeStop_RacesNodeStartGoroutine starts the qrdb storage the way the
// out-of-band CA reader does and stops it at once, a few times over the same
// data directory, while another goroutine reads the node lifecycle fields
// through the Server's own accessor (QRDBClient, under s.mu). Under -race it
// fails if initEmbeddedQRDBNode publishes, or stopQRDBNode clears, those
// fields outside s.mu (#2332).
func TestQRDBNodeStop_RacesNodeStartGoroutine(t *testing.T) {
	dataDir := t.TempDir()
	for i := 0; i < 5; i++ {
		s := &Server{
			config: &config.Config{
				Datastore: config.DatastoreConfig{Path: filepath.Join(dataDir, "storage")},
			},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.QRDBClient()
				}
			}
		}()

		require.NoError(t, s.initializeQRDBStorage())
		require.NotNil(t, s.QRDBClient(), "init must publish the qrdb client")
		require.NoError(t, s.closeQRDBStorage())
		require.Nil(t, s.QRDBClient(), "stop must clear the qrdb client")

		close(stop)
		wg.Wait()
	}
}
