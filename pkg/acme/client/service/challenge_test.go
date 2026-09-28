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

package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/azure"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/clouddns"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/cloudflare"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/route53"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// occupyPort binds and holds a loopback listener so a test can pass its port
// to a second bind attempt that must fail. The listener stays open for the
// life of the test (closed via t.Cleanup), so unlike a "reserve, release,
// rebind" helper there is no window in which another process can steal the
// port: the same listener that reserved it is still holding it when the
// code under test tries to bind.
func occupyPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	return port
}

// challengeServerPort starts cs and returns the port the kernel assigned it.
// cs must have been constructed with port "0" so Start asks the kernel for
// an unused port directly instead of a helper pre-allocating one and
// releasing it for Start to race against.
func challengeServerPort(t *testing.T, cs *ChallengeServer) string {
	t.Helper()
	require.NoError(t, cs.Start())
	addr, ok := cs.Addr().(*net.TCPAddr)
	require.True(t, ok, "ChallengeServer.Addr() must return a *net.TCPAddr after Start")
	return fmt.Sprintf("%d", addr.Port)
}

// TestNewChallengeServer verifies that a ChallengeServer is constructed with
// the correct token, keyAuth, port, and logger fields.
func TestNewChallengeServer(t *testing.T) {
	logger := testLogger()
	cs := NewChallengeServer("", "8080", "test-token", "test-key-auth", logger)

	require.NotNil(t, cs)
	assert.Equal(t, "test-token", cs.token)
	assert.Equal(t, "test-key-auth", cs.keyAuth)
	assert.Equal(t, "8080", cs.port)
	assert.Empty(t, cs.host, "the defaults-layer host is empty: every interface")
	assert.Equal(t, logger, cs.logger)
	assert.Nil(t, cs.server, "server must be nil before Start is called")
}

// TestNewChallengeServer_EmptyFields verifies construction with empty values.
func TestNewChallengeServer_EmptyFields(t *testing.T) {
	cs := NewChallengeServer("", "", "", "", testLogger())

	require.NotNil(t, cs)
	assert.Empty(t, cs.token)
	assert.Empty(t, cs.keyAuth)
	assert.Empty(t, cs.port)
}

// TestChallengeServer_StartAndShutdown verifies the server starts on a free
// port and shuts down cleanly.
func TestChallengeServer_StartAndShutdown(t *testing.T) {
	cs := NewChallengeServer("", "0", "tok", "keyauth", testLogger())

	err := cs.Start()
	require.NoError(t, err)
	require.NotNil(t, cs.server)

	// Shut down and verify idempotent shutdown
	cs.Shutdown()
	cs.Shutdown() // second call must be a no-op
}

// TestChallengeServer_Start_PortInUse verifies that Start returns an error
// when the port is already bound.
func TestChallengeServer_Start_PortInUse(t *testing.T) {
	port := occupyPort(t)

	cs := NewChallengeServer("", port, "tok", "ka", testLogger())
	err := cs.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen")
}

// TestChallengeServer_HandleChallenge_Success verifies that the server
// responds with the key authorization for a matching token request.
func TestChallengeServer_HandleChallenge_Success(t *testing.T) {
	token := "challenge-token-abc"
	keyAuth := "challenge-token-abc.thumbprint123"

	cs := NewChallengeServer("", "0", token, keyAuth, testLogger())
	port := challengeServerPort(t, cs)
	defer cs.Shutdown()

	url := fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/%s", port, token)
	resp, err := http.Get(url) // nolint:gosec
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, keyAuth, string(body))
}

// TestChallengeServer_HandleChallenge_WrongToken verifies that requesting
// a non-matching token returns 404.
func TestChallengeServer_HandleChallenge_WrongToken(t *testing.T) {
	cs := NewChallengeServer("", "0", "expected-token", "ka", testLogger())
	port := challengeServerPort(t, cs)
	defer cs.Shutdown()

	url := fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/wrong-token", port)
	resp, err := http.Get(url) // nolint:gosec
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestChallengeServer_ShutdownWithoutStart verifies that calling Shutdown
// on a server that was never started does not panic.
func TestChallengeServer_ShutdownWithoutStart(t *testing.T) {
	cs := NewChallengeServer("", "0", "tok", "ka", testLogger())
	// Must not panic
	cs.Shutdown()
}

// TestWriteHTTP01TokenFile_Success verifies that the token file is written
// to the correct path under the webroot.
func TestWriteHTTP01TokenFile_Success(t *testing.T) {
	webroot := t.TempDir()
	token := "test-token-xyz"
	keyAuth := "test-token-xyz.thumbprint"

	err := WriteHTTP01TokenFile(webroot, token, keyAuth, testLogger())
	require.NoError(t, err)

	tokenPath := filepath.Join(webroot, ".well-known", "acme-challenge", token)
	content, err := os.ReadFile(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, keyAuth, string(content))

	// Verify directory permissions
	info, err := os.Stat(filepath.Join(webroot, ".well-known", "acme-challenge"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// TestWriteHTTP01TokenFile_InvalidWebroot verifies that an error is returned
// when the webroot path is not writable.
func TestWriteHTTP01TokenFile_InvalidWebroot(t *testing.T) {
	err := WriteHTTP01TokenFile("/dev/null/impossible", "tok", "ka", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create challenge directory")
}

// TestCleanupHTTP01TokenFile_Success verifies that the token file is removed.
func TestCleanupHTTP01TokenFile_Success(t *testing.T) {
	webroot := t.TempDir()
	token := "cleanup-token"

	// Create the token file first
	require.NoError(t, WriteHTTP01TokenFile(webroot, token, "ka", testLogger()))

	tokenPath := filepath.Join(webroot, ".well-known", "acme-challenge", token)
	_, err := os.Stat(tokenPath)
	require.NoError(t, err, "token file must exist before cleanup")

	CleanupHTTP01TokenFile(webroot, token, testLogger())

	_, err = os.Stat(tokenPath)
	assert.True(t, os.IsNotExist(err), "token file must be removed after cleanup")
}

// TestCleanupHTTP01TokenFile_EmptyWebroot verifies that cleanup with an empty
// webroot is a no-op and does not panic.
func TestCleanupHTTP01TokenFile_EmptyWebroot(t *testing.T) {
	CleanupHTTP01TokenFile("", "tok", testLogger())
}

// TestCleanupHTTP01TokenFile_NonExistentFile verifies cleanup of a file that
// does not exist completes without error.
func TestCleanupHTTP01TokenFile_NonExistentFile(t *testing.T) {
	webroot := t.TempDir()
	CleanupHTTP01TokenFile(webroot, "no-such-token", testLogger())
}

// TestComputeDNS01Response verifies the DNS-01 response computation matches
// RFC 8555 Section 8.4: base64url(SHA-256(keyAuthorization)).
func TestComputeDNS01Response(t *testing.T) {
	keyAuth := "token.thumbprint"
	hash := sha256.Sum256([]byte(keyAuth))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	result := ComputeDNS01Response(keyAuth)
	assert.Equal(t, expected, result)
}

// TestComputeDNS01Response_EmptyInput verifies the response for an empty
// key authorization string.
func TestComputeDNS01Response_EmptyInput(t *testing.T) {
	result := ComputeDNS01Response("")
	hash := sha256.Sum256([]byte(""))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	assert.Equal(t, expected, result)
}

// TestSetupHTTP01Challenge_ServerMode verifies that SetupHTTP01Challenge starts
// an HTTP server when no webroot is configured.
func TestSetupHTTP01Challenge_ServerMode(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				Port: "0",
			},
		},
	}

	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	require.NoError(t, err)
	require.NotNil(t, server)
	defer server.Shutdown()
}

// TestSetupHTTP01Challenge_WebrootMode verifies that SetupHTTP01Challenge
// writes the token file when a webroot is configured.
func TestSetupHTTP01Challenge_WebrootMode(t *testing.T) {
	webroot := t.TempDir()
	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				WebRoot: webroot,
			},
		},
	}

	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	require.NoError(t, err)
	assert.Nil(t, server, "server must be nil in webroot mode")

	tokenPath := filepath.Join(webroot, ".well-known", "acme-challenge", "tok")
	content, err := os.ReadFile(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, "ka", string(content))
}

// TestSetupHTTP01Challenge_DefaultPort verifies that the default port 80 is
// used when no port is specified (expects failure since port 80 requires root).
func TestSetupHTTP01Challenge_DefaultPort(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{},
		},
	}

	// Port 80 typically requires root, so this should fail in non-root tests
	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	if err != nil {
		var setupErr ErrChallengeSetupFailed
		assert.ErrorAs(t, err, &setupErr)
		assert.Equal(t, "http-01", setupErr.ChallengeType)
	} else {
		require.NotNil(t, server)
		server.Shutdown()
	}
}

// TestSetupHTTP01Challenge_PortInUse verifies that SetupHTTP01Challenge returns
// an ErrChallengeSetupFailed when the port is occupied.
func TestSetupHTTP01Challenge_PortInUse(t *testing.T) {
	port := occupyPort(t)

	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				Port: port,
			},
		},
	}

	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	require.Error(t, err)
	assert.Nil(t, server)

	var setupErr ErrChallengeSetupFailed
	assert.ErrorAs(t, err, &setupErr)
	assert.Equal(t, "http-01", setupErr.ChallengeType)
}

// TestSetupHTTP01Challenge_WebrootInvalidPath verifies that
// SetupHTTP01Challenge returns an error when the webroot path is invalid.
func TestSetupHTTP01Challenge_WebrootInvalidPath(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				WebRoot: "/dev/null/impossible",
			},
		},
	}

	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	require.Error(t, err)
	assert.Nil(t, server)
}

// TestSetupDNS01Challenge_ManualMode verifies that SetupDNS01Challenge
// returns a nil challenge and no error when no provider is configured -
// the record must be created manually.
func TestSetupDNS01Challenge_ManualMode(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			DNS01: DNS01Config{
				TTL: 300,
			},
		},
	}

	challenge, err := SetupDNS01Challenge(context.Background(), config, testLogger(), "example.com", "tok", "ka")
	require.NoError(t, err)
	assert.Nil(t, challenge)

	// Cleanup must be safe to call unconditionally, even on a nil challenge.
	assert.NoError(t, challenge.Cleanup(context.Background()))
}

// TestSetupDNS01Challenge_UnsupportedProvider verifies that an unrecognized
// provider name fails fast with a typed error instead of silently doing
// nothing and letting ACME validation fail later.
func TestSetupDNS01Challenge_UnsupportedProvider(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			DNS01: DNS01Config{
				TTL:      60,
				Provider: "no-such-provider",
			},
		},
	}

	challenge, err := SetupDNS01Challenge(context.Background(), config, testLogger(), "example.com", "tok", "ka")
	require.Error(t, err)
	assert.Nil(t, challenge)

	var unsupportedErr ErrUnsupportedDNSProvider
	require.ErrorAs(t, err, &unsupportedErr)
	assert.Equal(t, "no-such-provider", unsupportedErr.Provider)
}

// TestSetupDNS01Challenge_InvalidAmbientCredential verifies that a
// non-boolean "ambient" credential fails fast with a typed error rather than
// silently defaulting.
func TestSetupDNS01Challenge_InvalidAmbientCredential(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			DNS01: DNS01Config{
				Provider:    "route53",
				Credentials: map[string]string{"ambient": "not-a-bool"},
			},
		},
	}

	challenge, err := SetupDNS01Challenge(context.Background(), config, testLogger(), "example.com", "tok", "ka")
	require.Error(t, err)
	assert.Nil(t, challenge)

	var credErr ErrInvalidDNSProviderCredential
	require.ErrorAs(t, err, &credErr)
	assert.Equal(t, "ambient", credErr.Key)
}

// fakeDNSProvider is a Provider test double that records Present/CleanUp
// calls and lets tests exercise success and failure paths without a real
// DNS API.
type fakeDNSProvider struct {
	presentErr error
	cleanUpErr error

	presented []fakeDNSRecord
	cleanedUp []fakeDNSRecord
}

type fakeDNSRecord struct {
	domain string
	fqdn   string
	value  string
}

func (f *fakeDNSProvider) Present(_ context.Context, domain, fqdn, value string) error {
	f.presented = append(f.presented, fakeDNSRecord{domain: domain, fqdn: fqdn, value: value})
	return f.presentErr
}

func (f *fakeDNSProvider) CleanUp(_ context.Context, domain, fqdn, value string) error {
	f.cleanedUp = append(f.cleanedUp, fakeDNSRecord{domain: domain, fqdn: fqdn, value: value})
	return f.cleanUpErr
}

// TestNewDNS01Challenge_Success verifies that a DNS-01 record is presented
// through the provider and that Cleanup later removes it.
func TestNewDNS01Challenge_Success(t *testing.T) {
	provider := &fakeDNSProvider{}

	challenge, err := newDNS01Challenge(context.Background(), provider, "example.com", "_acme-challenge.example.com.", "response-value", testLogger())
	require.NoError(t, err)
	require.NotNil(t, challenge)

	require.Len(t, provider.presented, 1)
	assert.Equal(t, "example.com", provider.presented[0].domain)
	assert.Equal(t, "_acme-challenge.example.com.", provider.presented[0].fqdn)
	assert.Equal(t, "response-value", provider.presented[0].value)

	require.NoError(t, challenge.Cleanup(context.Background()))
	require.Len(t, provider.cleanedUp, 1)
	assert.Equal(t, provider.presented[0], provider.cleanedUp[0])
}

// TestNewDNS01Challenge_PresentFails verifies that a provider failure during
// record creation surfaces as a typed error and returns no challenge to
// clean up.
func TestNewDNS01Challenge_PresentFails(t *testing.T) {
	provider := &fakeDNSProvider{presentErr: assert.AnError}

	challenge, err := newDNS01Challenge(context.Background(), provider, "example.com", "_acme-challenge.example.com.", "response-value", testLogger())
	require.Error(t, err)
	assert.Nil(t, challenge)

	var setupErr ErrChallengeSetupFailed
	require.ErrorAs(t, err, &setupErr)
	assert.Equal(t, "dns-01", setupErr.ChallengeType)
}

// TestDNS01Challenge_CleanupFails verifies that a provider failure during
// cleanup surfaces as a typed error.
func TestDNS01Challenge_CleanupFails(t *testing.T) {
	provider := &fakeDNSProvider{cleanUpErr: assert.AnError}

	challenge, err := newDNS01Challenge(context.Background(), provider, "example.com", "_acme-challenge.example.com.", "response-value", testLogger())
	require.NoError(t, err)
	require.NotNil(t, challenge)

	err = challenge.Cleanup(context.Background())
	require.Error(t, err)

	var cleanupErr ErrChallengeCleanupFailed
	require.ErrorAs(t, err, &cleanupErr)
	assert.Equal(t, "dns-01", cleanupErr.ChallengeType)
}

// TestBuildDNS01ProviderConfig_Route53 verifies that credentials are mapped
// into the route53 provider's Config struct by field name.
// TestBuildDNS01Provider_MissingCredentials verifies that a supported
// provider name with no credentials and no ambient opt-in reaches the real
// provider constructor and has its validation failure translated into
// ErrChallengeSetupFailed, rather than buildDNS01Provider silently returning
// a half-configured provider.
func TestBuildDNS01Provider_MissingCredentials(t *testing.T) {
	cfg := DNS01Config{Provider: "route53"}

	provider, err := buildDNS01Provider(context.Background(), cfg)
	require.Error(t, err)
	assert.Nil(t, provider)

	var setupErr ErrChallengeSetupFailed
	require.ErrorAs(t, err, &setupErr)
	assert.Equal(t, "dns-01", setupErr.ChallengeType)
}

func TestBuildDNS01ProviderConfig_Route53(t *testing.T) {
	cfg := DNS01Config{
		Provider: "route53",
		TTL:      120,
		Credentials: map[string]string{
			"accessKeyId":     "AKIA...",
			"secretAccessKey": "secret",
			"region":          "us-east-1",
			"hostedZoneId":    "Z123",
		},
	}

	providerConfig, err := buildDNS01ProviderConfig(cfg)
	require.NoError(t, err)

	route53Config, ok := providerConfig.(route53.Config)
	require.True(t, ok)
	assert.Equal(t, "AKIA...", route53Config.AccessKeyID)
	assert.Equal(t, "secret", route53Config.SecretAccessKey)
	assert.Equal(t, "us-east-1", route53Config.Region)
	assert.Equal(t, "Z123", route53Config.HostedZoneID)
	assert.Equal(t, 120, route53Config.TTL)
	assert.False(t, route53Config.Ambient)
}

// TestBuildDNS01ProviderConfig_Cloudflare verifies that credentials are
// mapped into the cloudflare provider's Config struct by field name.
func TestBuildDNS01ProviderConfig_Cloudflare(t *testing.T) {
	cfg := DNS01Config{
		Provider: "cloudflare",
		TTL:      60,
		Credentials: map[string]string{
			"apiToken": "token-value",
			"zoneId":   "zone-123",
		},
	}

	providerConfig, err := buildDNS01ProviderConfig(cfg)
	require.NoError(t, err)

	cloudflareConfig, ok := providerConfig.(cloudflare.Config)
	require.True(t, ok)
	assert.Equal(t, "token-value", cloudflareConfig.APIToken)
	assert.Equal(t, "zone-123", cloudflareConfig.ZoneID)
	assert.Equal(t, 60, cloudflareConfig.TTL)
}

// TestBuildDNS01ProviderConfig_Azure verifies that credentials are mapped
// into the azure provider's Config struct by field name, including the
// ambient boolean flag.
func TestBuildDNS01ProviderConfig_Azure(t *testing.T) {
	cfg := DNS01Config{
		Provider: "azure",
		TTL:      90,
		Credentials: map[string]string{
			"subscriptionId":    "sub-1",
			"resourceGroupName": "rg-1",
			"ambient":           "true",
		},
	}

	providerConfig, err := buildDNS01ProviderConfig(cfg)
	require.NoError(t, err)

	azureConfig, ok := providerConfig.(azure.Config)
	require.True(t, ok)
	assert.Equal(t, "sub-1", azureConfig.SubscriptionID)
	assert.Equal(t, "rg-1", azureConfig.ResourceGroupName)
	assert.True(t, azureConfig.Ambient)
	assert.Equal(t, int64(90), azureConfig.TTL)
}

// TestBuildDNS01ProviderConfig_CloudDNS verifies that credentials are mapped
// into the clouddns provider's Config struct by field name.
func TestBuildDNS01ProviderConfig_CloudDNS(t *testing.T) {
	cfg := DNS01Config{
		Provider: "clouddns",
		TTL:      45,
		Credentials: map[string]string{
			"project":            "my-project",
			"serviceAccountJson": `{"type":"service_account"}`,
		},
	}

	providerConfig, err := buildDNS01ProviderConfig(cfg)
	require.NoError(t, err)

	cloudDNSConfig, ok := providerConfig.(clouddns.Config)
	require.True(t, ok)
	assert.Equal(t, "my-project", cloudDNSConfig.Project)
	assert.Equal(t, `{"type":"service_account"}`, string(cloudDNSConfig.ServiceAccountJSON))
	assert.Equal(t, int64(45), cloudDNSConfig.TTL)
}

// TestBuildDNS01ProviderConfig_UnsupportedProvider verifies the fail-fast
// typed error for a provider name this project does not implement.
func TestBuildDNS01ProviderConfig_UnsupportedProvider(t *testing.T) {
	cfg := DNS01Config{Provider: "unknown-dns-provider"}

	_, err := buildDNS01ProviderConfig(cfg)
	require.Error(t, err)

	var unsupportedErr ErrUnsupportedDNSProvider
	require.ErrorAs(t, err, &unsupportedErr)
	assert.Equal(t, "unknown-dns-provider", unsupportedErr.Provider)
}

// TestChallengeServer_ConcurrentRequests verifies the server handles
// concurrent requests correctly.
func TestChallengeServer_ConcurrentRequests(t *testing.T) {
	token := "concurrent-token"
	keyAuth := "concurrent-ka"

	cs := NewChallengeServer("", "0", token, keyAuth, testLogger())
	port := challengeServerPort(t, cs)
	defer cs.Shutdown()

	// Allow server to fully start
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()

			url := fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/%s", port, token)
			resp, err := http.Get(url) // nolint:gosec
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, keyAuth, string(body))
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestChallengeServer_BindsConfiguredHost pins that the configured host
// reaches the listener: with Host set the server binds that address only,
// joined with net.JoinHostPort so an IPv6 host is bracketed. Before this the
// address was ":"+port for every configuration, the wildcard decision the
// owner ruling of 2026-08-26 forbids as a literal (go-xkms#140).
func TestChallengeServer_BindsConfiguredHost(t *testing.T) {
	cs := NewChallengeServer("127.0.0.1", "0", "tok", "ka", testLogger())
	port := challengeServerPort(t, cs)
	defer cs.Shutdown()

	assert.Equal(t, net.JoinHostPort("127.0.0.1", "0"), cs.server.Addr)

	tcpAddr, ok := cs.Addr().(*net.TCPAddr)
	require.True(t, ok, "ChallengeServer.Addr() must return a *net.TCPAddr")
	assert.Equal(t, "127.0.0.1", tcpAddr.IP.String(), "the listener must bind the configured host, not the wildcard")

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/tok", port)) // nolint:gosec
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestSetupHTTP01Challenge_UsesConfiguredHost pins the config-to-listener
// path: challenge.http01.host is what the started server binds.
func TestSetupHTTP01Challenge_UsesConfiguredHost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Challenge.HTTP01.Host = "127.0.0.1"
	cfg.Challenge.HTTP01.Port = "0"

	srv, err := SetupHTTP01Challenge(cfg, testLogger(), "tok", "ka")
	require.NoError(t, err)
	require.NotNil(t, srv)
	defer srv.Shutdown()

	assert.Equal(t, "127.0.0.1", srv.host)
	assert.Equal(t, net.JoinHostPort("127.0.0.1", "0"), srv.server.Addr)

	tcpAddr, ok := srv.Addr().(*net.TCPAddr)
	require.True(t, ok, "ChallengeServer.Addr() must return a *net.TCPAddr")
	assert.Equal(t, "127.0.0.1", tcpAddr.IP.String())
}
