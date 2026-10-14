package server

import (
	"errors"
	"testing"
	"testing/fstest"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

func TestBuildRESTConfig_InvalidTrustedProxiesFails(t *testing.T) {
	srv := newTestServerForRESTConfig(t, config.ServerConfig{
		Host:           "127.0.0.1",
		RESTPort:       8443,
		TrustedProxies: []string{"not-a-cidr"},
	})

	_, err := srv.buildRESTConfig()
	var initErr *ErrServiceInit
	if !errors.As(err, &initErr) || initErr.Service != "rest trusted proxies" {
		t.Fatalf("buildRESTConfig() with a bad trusted proxy = %v, want ErrServiceInit for rest trusted proxies", err)
	}
}

func TestBuildRESTConfig_EnabledPIVLoginWithMissingAnchorsFails(t *testing.T) {
	srv := newTestServerForRESTConfig(t, config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443})
	srv.tokenIssuer = newTestTokenIssuer(t)
	srv.config.Auth.PIVLogin = &config.PIVLoginConfig{
		Enabled:          true,
		AttestationRoots: "/nonexistent/piv-attestation-root.pem",
	}

	_, err := srv.buildRESTConfig()
	var initErr *ErrServiceInit
	if !errors.As(err, &initErr) || initErr.Service != "piv login attestation anchors" {
		t.Fatalf("buildRESTConfig() = %v, want ErrServiceInit for piv login attestation anchors", err)
	}
}

// TestBuildRESTConfig_UIAssets checks the web UI is mounted with the ui
// section's prefix and redirect when assets are installed, and stays
// unmounted when the configuration disables it.
func TestBuildRESTConfig_UIAssets(t *testing.T) {
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}}
	newServer := func(enabled *bool) *Server {
		srv := newTestServerForRESTConfig(t, config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443})
		srv.SetUIAssets(assets)
		srv.config.UI = config.UIConfig{Enabled: enabled, PathPrefix: "/console", RedirectRoot: true}
		return srv
	}

	restCfg, err := newServer(nil).buildRESTConfig()
	if err != nil {
		t.Fatalf("buildRESTConfig() with UI assets: %v", err)
	}
	ui := restCfg.UI
	if ui == nil || !ui.Enabled || ui.PathPrefix != "/console" || !ui.RedirectRoot || ui.Assets == nil {
		t.Fatalf("UI options = %+v, want enabled at /console with root redirect and the installed assets", ui)
	}

	disabled := false
	restCfg, err = newServer(&disabled).buildRESTConfig()
	if err != nil {
		t.Fatalf("buildRESTConfig() with the UI disabled: %v", err)
	}
	if restCfg.UI != nil {
		t.Fatalf("UI options = %+v, want nil when ui.enabled is false", restCfg.UI)
	}
}
