// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
)

// TestRunTrustBootstrap_FilesBundleUnderBootstrapCA guards #1312: a bundle
// fetched over the network is filed under bootstrap-ca with the server as its
// source, exactly as "xkey trust fetch" and the GUI file it -- never
// auto-classified, which would let the server choose the purpose. The bundle
// is a self-signed CA, which auto-classification would file as user-ca.
func TestRunTrustBootstrap_FilesBundleUnderBootstrapCA(t *testing.T) {
	resetViperForTest(t)

	bundlePEM := newTestCertificatePEM(t, "Bootstrap Purpose CA")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ca/bootstrap" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(bundlePEM)
	}))
	defer srv.Close()

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)
	viper.Set("trust.bootstrap.server_url", srv.URL)
	viper.Set("trust.bootstrap.direct.server_url", srv.URL)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	cmd.Flags().Duration("timeout", 5*time.Second, "timeout")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "method", "direct"))
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, runTrustBootstrap(cmd, nil))
	assert.Contains(t, out.String(), "Certificates imported: 1")

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()

	certs, err := store.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	meta, err := store.Metadata(truststore.Fingerprint(certs[0]))
	require.NoError(t, err)

	parsed, err := url.Parse(srv.URL)
	require.NoError(t, err)
	assert.Equal(t, truststore.PurposeBootstrapCA, meta.Purpose)
	assert.Equal(t, "platform:"+parsed.Host, meta.Source)
}

func TestBootstrapServer(t *testing.T) {
	tests := []struct {
		name string
		cfg  *bootstrap.Config
		want string
	}{
		{
			name: "server URL",
			cfg:  &bootstrap.Config{ServerURL: "https://kms.example.com:8443"},
			want: "https://kms.example.com:8443",
		},
		{
			name: "server URL wins over Noise address",
			cfg: &bootstrap.Config{
				ServerURL: "https://kms.example.com:8443",
				Noise:     &bootstrap.NoiseConfig{ServerAddr: "noise.example.com:8445"},
			},
			want: "https://kms.example.com:8443",
		},
		{
			name: "Noise address when no server URL",
			cfg:  &bootstrap.Config{Noise: &bootstrap.NoiseConfig{ServerAddr: "noise.example.com:8445"}},
			want: "noise.example.com:8445",
		},
		{
			name: "nothing configured",
			cfg:  &bootstrap.Config{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bootstrapServer(tt.cfg))
		})
	}
}
