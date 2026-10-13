package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestTrustFetch_UnopenableTrustStore(t *testing.T) {
	_, bundlePEM := makeFetchCA(t)
	srv := startFetchServer(t, bundlePEM)
	pin := tlsServerPin(t, srv)

	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	viper.Set("trust.store_path", filepath.Join(blocker, "trust"))
	t.Cleanup(func() { viper.Set("trust.store_path", "") })

	fcmd := newFetchTestCmd()
	out := &bytes.Buffer{}
	fcmd.SetOut(out)
	fcmd.SetErr(&bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, fcmd.Flags(), "spki-pin", pin))

	err := runTrustFetch(fcmd, []string{srv.URL + xkms.TrustFetcherDefaultBundlePath})
	assert.ErrorIs(t, err, ErrTrustStoreOpen)
	assert.Empty(t, out.String(), "no bundle is reported fetched when it cannot be stored")
}
