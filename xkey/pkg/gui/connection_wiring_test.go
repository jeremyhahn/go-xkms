// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package gui

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// connectedClient stands in for a connected xkmsd client. The wiring under
// test only hands it to the services; none of its methods is called.
type connectedClient struct {
	transport.Client
}

// newConnectionWiringApp returns an App with the services that follow the
// server connection.
func newConnectionWiringApp() *App {
	return &App{
		pivService:         services.NewPIVService(nil, "software"),
		tenantService:      services.NewTenantService(),
		certificateService: services.NewCertificateService(),
		caService:          services.NewCAService(nil),
		tpmPolicyService:   services.NewTPMPolicyService(),
		staticPWService:    services.NewStaticPasswordService(nil),
		oidcServerService:  services.NewOIDCServerService(nil),
		connectionService:  services.NewConnectionService(),
		sshService:         services.NewSSHService(nil),
		agentService:       services.NewAgentService(),
		log:                slog.Default(),
	}
}

func TestApplyConnectionEvent_ServerOIDCCredentialsFollowTheConnection(t *testing.T) {
	a := newConnectionWiringApp()
	assert.False(t, a.oidcServerService.Connected(), "before a connection there are no server credentials")

	a.applyConnectionEvent(events.EventServerConnected, &connectedClient{})
	assert.True(t, a.oidcServerService.Connected())

	for _, eventType := range []events.EventType{events.EventServerDisconnected, events.EventServerError} {
		a.applyConnectionEvent(events.EventServerConnected, &connectedClient{})
		a.applyConnectionEvent(eventType, nil)
		assert.False(t, a.oidcServerService.Connected(), "%s detaches the server credentials", eventType)
		_, err := a.oidcServerService.ListServerCredentials("")
		assert.ErrorIs(t, err, services.ErrOIDCServerNotConnected)
	}
}

// vaultClient is a connected xkmsd client whose personal vault reports as
// initialized, so a test can see which client the password service follows.
type vaultClient struct {
	transport.Client
}

func (vaultClient) PasswordVaultStatus(context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return &transport.PasswordVaultStatusResponse{Initialized: true}, nil
}

func TestApplyConnectionEvent_PasswordVaultFollowsTheConnection(t *testing.T) {
	a := newConnectionWiringApp()
	_, err := a.staticPWService.VaultStatus()
	assert.ErrorIs(t, err, services.ErrStaticPWNoClient, "before a connection there is no vault to reach")

	a.applyConnectionEvent(events.EventServerConnected, vaultClient{})
	status, err := a.staticPWService.VaultStatus()
	assert.NoError(t, err)
	assert.True(t, status.Initialized, "the vault is served by the connected client")

	a.applyConnectionEvent(events.EventServerDisconnected, nil)
	_, err = a.staticPWService.VaultStatus()
	assert.ErrorIs(t, err, services.ErrStaticPWNoClient, "a disconnect detaches the vault")
}

// caClient is a connected xkmsd client that serves only the CA certificate,
// so a test can see which client the CA service follows.
type caClient struct {
	transport.Client
	certPEM []byte
}

func (c caClient) GetCACertificate(context.Context, *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return &transport.GetCACertificateResponse{CertificatePEM: c.certPEM}, nil
}

// testCACertPEM builds a self-signed CA certificate with the given common name.
func testCACertPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(781),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestApplyConnectionEvent_CAFollowsTheConnection(t *testing.T) {
	a := newConnectionWiringApp()
	_, err := a.caService.GetCAInfo()
	assert.ErrorIs(t, err, services.ErrCAServiceNilClient, "before a connection there is no CA to reach")

	client := caClient{certPEM: testCACertPEM(t, "Connected xkms CA")}
	for _, eventType := range []events.EventType{events.EventServerDisconnected, events.EventServerError} {
		a.applyConnectionEvent(events.EventServerConnected, client)
		info, err := a.caService.GetCAInfo()
		require.NoError(t, err)
		assert.Equal(t, "CN=Connected xkms CA", info.Subject, "the CA is served by the connected client")

		a.applyConnectionEvent(eventType, nil)
		_, err = a.caService.GetCAInfo()
		assert.ErrorIs(t, err, services.ErrCAServiceNilClient, "%s detaches the CA", eventType)
	}
}

func TestInitLocalCA_ServesCAWithNoServer(t *testing.T) {
	a := newConnectionWiringApp()
	_, err := xkmssdk.NewEmbeddedService(xkmssdk.EmbeddedServiceConfig{KeyDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(xkmssdk.Reset)
	before, _ := xkmssdk.Get()

	start := time.Now()
	a.initLocalCA(t.TempDir(), nil)
	t.Cleanup(a.closeLocalCA)
	t.Logf("initLocalCA took %s", time.Since(start))

	info, err := a.caService.GetCAInfo()
	require.NoError(t, err, "with no server connected the local CA serves")
	assert.True(t, info.IsCA)
	assert.Contains(t, info.Subject, "Root CA")

	after, _ := xkmssdk.Get()
	assert.Same(t, before, after, "the local CA leaves the key service singleton untouched")

	a.applyConnectionEvent(events.EventServerConnected, caClient{certPEM: testCACertPEM(t, "Connected xkms CA")})
	info, err = a.caService.GetCAInfo()
	require.NoError(t, err)
	assert.Equal(t, "CN=Connected xkms CA", info.Subject, "a connected server replaces the local CA")

	a.applyConnectionEvent(events.EventServerDisconnected, nil)
	info, err = a.caService.GetCAInfo()
	require.NoError(t, err)
	assert.Contains(t, info.Subject, "Root CA", "a disconnect falls back to the local CA")
}

func TestApplyConnectionEvent_ConnectPutsTPMPoliciesInServerMode(t *testing.T) {
	a := newConnectionWiringApp()
	assert.Equal(t, services.TPMPolicyModeUnavailable, a.tpmPolicyService.GetStatus().Mode)

	a.applyConnectionEvent(events.EventServerConnected, &connectedClient{})
	assert.Equal(t, services.TPMPolicyModeServer, a.tpmPolicyService.GetStatus().Mode)
}

func TestApplyConnectionEvent_DisconnectAndErrorReturnTPMPoliciesToLocal(t *testing.T) {
	for _, eventType := range []events.EventType{events.EventServerDisconnected, events.EventServerError} {
		t.Run(string(eventType), func(t *testing.T) {
			a := newConnectionWiringApp()
			a.applyConnectionEvent(events.EventServerConnected, &connectedClient{})
			a.applyConnectionEvent(eventType, nil)
			assert.Equal(t, services.TPMPolicyModeUnavailable, a.tpmPolicyService.GetStatus().Mode,
				"with no local TPM, a disconnect leaves no TPM policy backend")
		})
	}
}

func TestApplyConnectionEvent_IgnoresOtherEvents(t *testing.T) {
	a := newConnectionWiringApp()
	a.applyConnectionEvent(events.EventBarrierLocked, &connectedClient{})
	assert.Equal(t, services.TPMPolicyModeUnavailable, a.tpmPolicyService.GetStatus().Mode)
}

// newNoTPMApp returns a minimal App on a host with no TPM, with the TPM
// policy and barrier auto-unseal services wired.
func newNoTPMApp(t *testing.T, strategy string) *App {
	t.Helper()
	a := newMinimalApp(t)
	a.tpmUnavailable = true
	a.tpmPolicyService = services.NewTPMPolicyService()
	a.barrierAutoUnsealService = services.NewBarrierAutoUnsealService()
	a.config.BarrierStrategy = strategy
	return a
}

func TestEnsureLocalTPMPolicies_NoTPMLeavesLocalModeUnavailable(t *testing.T) {
	a := newNoTPMApp(t, "passphrase")
	a.ensureLocalTPMPolicies()
	assert.Nil(t, a.tpmPolicyService.Local())
	assert.NotEmpty(t, a.dataDir, "the data directory is resolved even without a TPM")
	assert.Equal(t, services.TPMPolicyModeUnavailable, a.tpmPolicyService.GetStatus().Mode)
}

func TestEnsureLocalTPMPolicies_WithoutServiceIsANoOp(t *testing.T) {
	a := newMinimalApp(t)
	a.ensureLocalTPMPolicies()
	assert.Nil(t, a.tpmPolicyService)
}

func TestAutoUnsealBarrier_WithoutTPMNeedsThePassword(t *testing.T) {
	for _, strategy := range []string{"passphrase", "tpm2"} {
		t.Run(strategy, func(t *testing.T) {
			a := newNoTPMApp(t, strategy)
			assert.False(t, a.autoUnsealBarrier(context.Background()),
				"with no TPM policy service and no TPM, the barrier stays sealed for a manual unseal")
			assert.False(t, a.barrierService.IsUnsealed())
		})
	}
}

// TestApplyConnectionEvent_SSHFollowsTheConnection proves SSH is
// server-backed while a server is connected and local once it is gone.
func TestApplyConnectionEvent_SSHFollowsTheConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"v"}`))
	}))
	t.Cleanup(srv.Close)

	a := newConnectionWiringApp()
	a.connectionService.SetContext(context.Background())
	_, err := a.connectionService.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)

	a.applyConnectionEvent(events.EventServerConnected, a.connectionService.GetClient())
	assert.True(t, a.sshService.Connected(), "a connected server serves SSH")

	require.NoError(t, a.connectionService.Disconnect())
	a.applyConnectionEvent(events.EventServerDisconnected, nil)
	assert.False(t, a.sshService.Connected(), "SSH returns to local when the server goes")
}

// TestApplyConnectionEvent_SSHFailsClosedWithoutServerSSH proves a
// connected server whose SSH API cannot be dialed makes SSH unavailable,
// never quietly local, until the connection goes.
func TestApplyConnectionEvent_SSHFailsClosedWithoutServerSSH(t *testing.T) {
	a := newConnectionWiringApp()
	a.applyConnectionEvent(events.EventServerConnected, &connectedClient{})
	assert.True(t, a.sshService.Connected())
	_, err := a.sshService.ListKeys()
	var unavailable *services.SSHServerUnavailableError
	assert.ErrorAs(t, err, &unavailable)

	a.applyConnectionEvent(events.EventServerDisconnected, nil)
	assert.False(t, a.sshService.Connected())
}
