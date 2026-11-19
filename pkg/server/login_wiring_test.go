package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

type loginWiringTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// loadFirstBootAdminCert reads the administrator certificate first boot
// wrote to the data directory (PersistAdminCredential).
func loadFirstBootAdminCert(t *testing.T, dataDir string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dataDir, "admin-cert.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "admin-cert.pem holds a PEM certificate")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// TestLoginWiring_PIVLoginOverEmbeddedNode is go-xkms#2287 on the wiring
// xkmsd runs: server.New over an embedded go-qrdb node (barrier enabled and
// unsealed), piv_login with allow_unattested, the REST surface built by
// buildRESTConfig, enable_rbac off and on, the first-boot administrator's
// certificate. The login route is public, so its request context carries
// no identity. The certificate lookup resolves through the node's user
// service (Server.QRDBUserStore, nodeCertUsers) and succeeds; the
// refresh-token store must write as the node's service principal. Before
// the fix the login answered 500 with "refresh store put failed:
// qrdb/auth: unauthenticated". The barrier strategy is "none": a
// passphrase seal would need an operator unseal before New returns.
func TestLoginWiring_PIVLoginOverEmbeddedNode(t *testing.T) {
	for _, rbac := range []bool{false, true} {
		name := "rbac_off"
		if rbac {
			name = "rbac_on"
		}
		t.Run(name, func(t *testing.T) {
			xkms.Reset()
			t.Cleanup(xkms.Reset)
			// Debug-level server log, so a rejection names its reason.
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			cfg := qrdbBarrierConfig(t)
			cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
			cfg.Auth.EnableRBAC = rbac
			// No operator JWT key: the built-in token issuer's key verifies
			// the pairs it mints, as on an xkmsd without auth.jwt.public_key_file.
			cfg.Auth.Type = "composite"
			if cfg.Auth.JWT != nil {
				cfg.Auth.JWT.PublicKeyFile = ""
			}
			cfg.TLS.ClientAuth = "request"
			cfg.TLS.ServerCN = "localhost"
			cfg.Auth.PIVLogin = &config.PIVLoginConfig{Enabled: true, AllowUnattested: true}

			s, err := New(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Shutdown() })
			require.NotNil(t, s.qrdbNode, "the wiring under test is the embedded node")
			require.NotNil(t, s.tokenIssuer, "New must build the token issuer")

			// First boot created the system tenant's administrator, bound
			// its certificate and wrote it to the data directory: the
			// "valid admin certificate" of #2287.
			cert := loadFirstBootAdminCert(t, cfg.Datastore.Path)

			restCfg, err := s.buildRESTConfig()
			require.NoError(t, err)
			srv, err := rest.NewServer(restCfg)
			require.NoError(t, err)
			h := srv.Handler()
			do := func(req *http.Request) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				return w
			}

			// (1) PIV login: 200 with a token pair.
			login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/piv", nil)
			login.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			w := do(login)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			var pair loginWiringTokens
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pair))
			require.NotEmpty(t, pair.AccessToken)
			require.NotEmpty(t, pair.RefreshToken)

			// (2) the access token authenticates /auth/me.
			me := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
			me.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			w = do(me)
			require.Equal(t, http.StatusOK, w.Code, "/auth/me rejected the minted access token: %s", w.Body.String())

			// (3) refresh rotates the refresh token. The issuer is asked
			// first, under the same identity-less context, so a refusal
			// names its reason (the handler answers a bare 401).
			direct, err := s.tokenIssuer.Refresh(context.Background(), pair.RefreshToken)
			require.NoError(t, err, "issuer refresh under the public route's context")
			pair.RefreshToken = direct.RefreshToken
			body, err := json.Marshal(map[string]string{"refresh_token": pair.RefreshToken})
			require.NoError(t, err)
			refresh := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
			refresh.Header.Set("Content-Type", "application/json")
			w = do(refresh)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			var rotated loginWiringTokens
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rotated))
			require.NotEmpty(t, rotated.RefreshToken)
			assert.NotEqual(t, pair.RefreshToken, rotated.RefreshToken, "refresh must rotate the refresh token")

			// (4) the re-check still refuses: an administrator disables the
			// account after login, and its next refresh answers 401
			// (go-xkms#2292). The administrator acts through the xkmsd REST
			// API with the access token the rotation minted.
			username := cert.Subject.CommonName
			require.NotEmpty(t, username, "the first-boot admin certificate names its account")
			disable := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+username+"/disable", nil)
			disable.Header.Set("Authorization", "Bearer "+rotated.AccessToken)
			w = do(disable)
			require.Equal(t, http.StatusOK, w.Code, "administrator disable: %s", w.Body.String())

			body, err = json.Marshal(map[string]string{"refresh_token": rotated.RefreshToken})
			require.NoError(t, err)
			refresh = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
			refresh.Header.Set("Content-Type", "application/json")
			w = do(refresh)
			assert.Equal(t, http.StatusUnauthorized, w.Code, "refresh for a disabled user must be refused: %s", w.Body.String())
		})
	}
}

// TestLoginWiring_WebAuthnFinishReachesMint is the WebAuthn side of
// go-xkms#2287 on the same wiring: the finish step of a ceremony calls the
// token generator xkmsd wires (rest.WebAuthnTokenAdapter over the server's
// issuer) with the public route's identity-less context. Before the fix
// Mint failed at the refresh store put.
func TestLoginWiring_WebAuthnFinishReachesMint(t *testing.T) {
	for _, rbac := range []bool{false, true} {
		name := "rbac_off"
		if rbac {
			name = "rbac_on"
		}
		t.Run(name, func(t *testing.T) {
			xkms.Reset()
			t.Cleanup(xkms.Reset)

			cfg := qrdbBarrierConfig(t)
			cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
			cfg.Auth.EnableRBAC = rbac
			cfg.TLS.ServerCN = "localhost"

			s, err := New(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Shutdown() })
			require.NotNil(t, s.qrdbNode, "the wiring under test is the embedded node")
			require.NotNil(t, s.tokenIssuer, "New must build the token issuer")

			gen := rest.NewWebAuthnTokenAdapter(s.tokenIssuer, "")
			access, refresh, err := gen.GenerateTokenPair(context.Background(), webauthn.NewDefaultUserFromEmail("admin@example.com", "admin"))
			require.NoError(t, err)
			require.NotEmpty(t, access)
			require.NotEmpty(t, refresh)
		})
	}
}
