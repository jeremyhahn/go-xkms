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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// ===========================================================================
// Part 5: Final coverage push from 89.1% to 90%+
// ===========================================================================

// ---------------------------------------------------------------------------
// Helper: generate a self-signed x509 certificate for trust store tests.
// ---------------------------------------------------------------------------

func fcp5GenerateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "fcp5-test-cert-" + time.Now().Format("150405.000"),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// ---------------------------------------------------------------------------
// Helper: create an APIExplorerService with all required dependencies.
// ---------------------------------------------------------------------------

func fcp5NewExplorer(t *testing.T, opts ...func(*ExplorerConfig)) *APIExplorerService {
	t.Helper()
	cfg := &ExplorerConfig{
		TokenStore:   tokenstore.NewMemoryTokenStore(),
		Registry:     serverregistry.NewMemoryServerRegistry(),
		TrustStore:   storage.NewMemory(),
		HistoryStore: storage.NewMemory(),
	}
	for _, fn := range opts {
		fn(cfg)
	}
	explorer, err := NewAPIExplorerService(cfg)
	require.NoError(t, err)
	return explorer
}

// ---------------------------------------------------------------------------
// ListAvailableTokens: OIDC branch coverage
// ---------------------------------------------------------------------------

func TestFCP5_ListAvailableTokens_OIDCWithEmail(t *testing.T) {
	oidcSvc := NewOIDCService(slog.Default())
	oidcTokenStore := oidc.NewMemoryTokenStore()
	oidcSvc.tokenStore = oidcTokenStore
	oidcSvc.providers["test-provider"] = &OIDCProviderEntry{
		Name:   "test-provider",
		Issuer: "https://example.com",
		Scopes: []string{"openid"},
	}

	err := oidcTokenStore.Save("https://example.com", &oidc.TokenResponse{
		AccessToken: "oidc-access-token-123",
		ExpiresIn:   3600,
	})
	require.NoError(t, err)

	explorer := fcp5NewExplorer(t, func(c *ExplorerConfig) {
		c.OIDCService = oidcSvc
	})

	tokens := explorer.ListAvailableTokens()

	found := false
	for _, tok := range tokens {
		if tok.Source == "oidc" && tok.Token == "oidc-access-token-123" {
			found = true
			assert.Contains(t, tok.Label, "test-provider")
			assert.Equal(t, "oidc:test-provider", tok.ID)
		}
	}
	assert.True(t, found, "expected OIDC token in list")
}

func TestFCP5_ListAvailableTokens_OIDCNoAccessToken(t *testing.T) {
	oidcSvc := NewOIDCService(slog.Default())
	oidcTokenStore := oidc.NewMemoryTokenStore()
	oidcSvc.tokenStore = oidcTokenStore
	oidcSvc.providers["empty-provider"] = &OIDCProviderEntry{
		Name:   "empty-provider",
		Issuer: "https://no-token.example.com",
	}

	err := oidcTokenStore.Save("https://no-token.example.com", &oidc.TokenResponse{
		AccessToken: "",
	})
	require.NoError(t, err)

	explorer := fcp5NewExplorer(t, func(c *ExplorerConfig) {
		c.OIDCService = oidcSvc
	})

	tokens := explorer.ListAvailableTokens()
	for _, tok := range tokens {
		assert.NotEqual(t, "oidc", tok.Source, "empty access token should be skipped")
	}
}

func TestFCP5_ListAvailableTokens_OIDCDuplicate(t *testing.T) {
	oidcSvc := NewOIDCService(slog.Default())
	oidcTokenStore := oidc.NewMemoryTokenStore()
	oidcSvc.tokenStore = oidcTokenStore
	oidcSvc.providers["dup-provider"] = &OIDCProviderEntry{
		Name:   "dup-provider",
		Issuer: "https://dup.example.com",
	}

	err := oidcTokenStore.Save("https://dup.example.com", &oidc.TokenResponse{
		AccessToken: "dup-token",
		ExpiresIn:   3600,
	})
	require.NoError(t, err)

	explorer := fcp5NewExplorer(t, func(c *ExplorerConfig) {
		c.OIDCService = oidcSvc
	})

	tokens := explorer.ListAvailableTokens()
	oidcCount := 0
	for _, tok := range tokens {
		if tok.Source == "oidc" {
			oidcCount++
		}
	}
	assert.Equal(t, 1, oidcCount, "should appear only once")
}

func TestFCP5_ListAvailableTokens_Closed(t *testing.T) {
	explorer := fcp5NewExplorer(t)
	explorer.closed.Store(true)
	tokens := explorer.ListAvailableTokens()
	assert.Nil(t, tokens)
}

// ---------------------------------------------------------------------------
// TrustService: ExportBrowserTrustBundle + GetBrowserBundleStatus
// ---------------------------------------------------------------------------

func TestFCP5_TrustService_ExportBrowserTrustBundle_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	cert := fcp5GenerateSelfSignedCert(t)
	err = store.AddCertificateWithOptions(cert, &truststore.AddCertificateOptions{
		Tags: []string{TagBrowserExport},
	})
	require.NoError(t, err)

	svc := NewTrustService(store)
	bundlePath := filepath.Join(tmpDir, "bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	data, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "CERTIFICATE")

	manifestPath := filepath.Join(tmpDir, browserBundleManifestFile)
	manifestData, err := os.ReadFile(manifestPath)
	require.NoError(t, err)

	var manifest bundleManifest
	err = json.Unmarshal(manifestData, &manifest)
	require.NoError(t, err)
	assert.Equal(t, 1, manifest.CertCount)
}

func TestFCP5_TrustService_ExportBrowserTrustBundle_NoCerts(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	svc := NewTrustService(store)
	count, err := svc.ExportBrowserTrustBundle(filepath.Join(tmpDir, "bundle.pem"))
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestFCP5_TrustService_ExportBrowserTrustBundle_NilStore(t *testing.T) {
	svc := NewTrustService(nil)
	count, err := svc.ExportBrowserTrustBundle("/tmp/nonexistent")
	assert.Error(t, err)
	assert.Equal(t, 0, count)
}

func TestFCP5_TrustService_ExportBrowserTrustBundle_BootstrapCA(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	cert := fcp5GenerateSelfSignedCert(t)
	err = store.AddCertificateWithOptions(cert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeBootstrapCA,
	})
	require.NoError(t, err)

	svc := NewTrustService(store)
	count, err := svc.ExportBrowserTrustBundle(filepath.Join(tmpDir, "bundle.pem"))
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestFCP5_TrustService_GetBrowserBundleStatus_NoBundle(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	svc := NewTrustService(store)
	status := svc.GetBrowserBundleStatus(filepath.Join(tmpDir, "nonexistent.pem"))
	assert.False(t, status.Exists)
}

func TestFCP5_TrustService_GetBrowserBundleStatus_WithBundle(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	cert := fcp5GenerateSelfSignedCert(t)
	err = store.AddCertificateWithOptions(cert, &truststore.AddCertificateOptions{
		Tags: []string{TagBrowserExport},
	})
	require.NoError(t, err)

	svc := NewTrustService(store)
	bundlePath := filepath.Join(tmpDir, "bundle.pem")
	_, err = svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)

	status := svc.GetBrowserBundleStatus(bundlePath)
	assert.True(t, status.Exists)
	assert.Equal(t, 1, status.CertCount)
	assert.False(t, status.Stale)
}

func TestFCP5_TrustService_GetBrowserBundleStatus_Stale(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	cert := fcp5GenerateSelfSignedCert(t)
	err = store.AddCertificateWithOptions(cert, &truststore.AddCertificateOptions{
		Tags: []string{TagBrowserExport},
	})
	require.NoError(t, err)

	svc := NewTrustService(store)
	bundlePath := filepath.Join(tmpDir, "bundle.pem")
	_, err = svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)

	// Add another cert to make the manifest stale.
	cert2 := fcp5GenerateSelfSignedCert(t)
	err = store.AddCertificateWithOptions(cert2, &truststore.AddCertificateOptions{
		Tags: []string{TagBrowserExport},
	})
	require.NoError(t, err)

	status := svc.GetBrowserBundleStatus(bundlePath)
	assert.True(t, status.Exists)
	assert.True(t, status.Stale)
}

func TestFCP5_TrustService_GetBrowserBundleStatus_NoManifest(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	bundlePath := filepath.Join(tmpDir, "bundle.pem")
	err = os.WriteFile(bundlePath, []byte("test"), 0o600)
	require.NoError(t, err)

	svc := NewTrustService(store)
	status := svc.GetBrowserBundleStatus(bundlePath)
	assert.True(t, status.Exists)
	assert.True(t, status.Stale)
}

func TestFCP5_TrustService_GetBrowserBundleStatus_CorruptManifest(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	bundlePath := filepath.Join(tmpDir, "bundle.pem")
	err = os.WriteFile(bundlePath, []byte("test"), 0o600)
	require.NoError(t, err)

	manifestPath := filepath.Join(tmpDir, browserBundleManifestFile)
	err = os.WriteFile(manifestPath, []byte("not-json"), 0o600)
	require.NoError(t, err)

	svc := NewTrustService(store)
	status := svc.GetBrowserBundleStatus(bundlePath)
	assert.True(t, status.Exists)
	assert.True(t, status.Stale)
}

func TestFCP5_TrustService_EligibleFingerprints_NilStore(t *testing.T) {
	svc := NewTrustService(nil)
	assert.Nil(t, svc.eligibleFingerprints())
}

func TestFCP5_TrustService_EligibleFingerprints_WithCerts(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(tmpDir, "trust"),
	})
	require.NoError(t, err)
	defer store.Close()

	cert := fcp5GenerateSelfSignedCert(t)
	err = store.AddCertificateWithOptions(cert, &truststore.AddCertificateOptions{
		Tags: []string{TagBrowserExport},
	})
	require.NoError(t, err)

	svc := NewTrustService(store)
	fps := svc.eligibleFingerprints()
	assert.Len(t, fps, 1)
}

// ---------------------------------------------------------------------------
// PlatformPolicyService: ExportPolicy, GetStatus, VerifyPolicy, Initialize
// ---------------------------------------------------------------------------

func TestFCP5_PlatformPolicyService_ExportPolicy_Configured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	now := time.Now()
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "abcd1234", 7: "ef567890"},
		CreatedAt: now,
		UpdatedAt: now,
	})

	result, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.Contains(t, result, "Platform Policy")
	assert.Contains(t, result, "sha256")
	assert.Contains(t, result, "pcr_selections")
	assert.Contains(t, result, "pcr_digests")
}

func TestFCP5_PlatformPolicyService_ExportPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	_, err := svc.ExportPolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestFCP5_PlatformPolicyService_ExportPolicy_NoDigests(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	now := time.Now()
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		CreatedAt: now,
		UpdatedAt: now,
	})

	result, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.Contains(t, result, "Platform Policy")
	assert.NotContains(t, result, "pcr_digests")
}

func TestFCP5_PlatformPolicyService_GetStatus_Configured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	now := time.Now()
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "abcd1234"},
		CreatedAt: now,
		UpdatedAt: now,
	})

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Configured)
	assert.Equal(t, "sha256", status.Bank)
}

func TestFCP5_PlatformPolicyService_GetStatus_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.Configured)
}

func TestFCP5_PlatformPolicyService_VerifyPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	_, err := svc.VerifyPolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestFCP5_PlatformPolicyService_VerifyPolicy_NoTPM(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "abcd1234"},
	})

	valid, err := svc.VerifyPolicy()
	assert.Error(t, err)
	assert.False(t, valid)
}

func TestFCP5_PlatformPolicyService_GetPolicyPCRs_Configured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0, 1, 7},
		Bank: "sha384",
	})

	pcrs, bank, err := svc.GetPolicyPCRs()
	require.NoError(t, err)
	assert.Equal(t, []int{0, 1, 7}, pcrs)
	assert.Equal(t, "sha384", bank)
}

func TestFCP5_PlatformPolicyService_GetPolicyPCRs_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	_, _, err := svc.GetPolicyPCRs()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestFCP5_PlatformPolicyService_GetPlatformPolicyAsPCRPolicy(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	now := time.Now()
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "abcd1234", 7: "ef567890"},
		CreatedAt: now,
		UpdatedAt: now,
	})

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "Platform Policy", policy.Name)
	assert.True(t, policy.IsPlatformPolicy)
	assert.Len(t, policy.PCRSelections, 2)
	assert.Len(t, policy.PCRDigests, 2)
}

func TestFCP5_PlatformPolicyService_GetPlatformPolicyAsPCRPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	assert.Nil(t, policy)
}

func TestFCP5_PlatformPolicyService_Initialize_FileNotFound(t *testing.T) {
	svc := NewPlatformPolicyService("/nonexistent/path/policy.json")
	err := svc.Initialize()
	require.NoError(t, err)
}

func TestFCP5_PlatformPolicyService_Initialize_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.json")

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	data, err := json.Marshal(def)
	require.NoError(t, err)
	err = os.WriteFile(policyPath, data, 0o600)
	require.NoError(t, err)

	svc := NewPlatformPolicyService(policyPath)
	err = svc.Initialize()
	require.NoError(t, err)

	loaded := svc.policy.Load()
	require.NotNil(t, loaded)
	assert.Equal(t, []int{0, 7}, loaded.PCRs)
}

func TestFCP5_PlatformPolicyService_Initialize_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.json")
	err := os.WriteFile(policyPath, []byte("not-json"), 0o600)
	require.NoError(t, err)

	svc := NewPlatformPolicyService(policyPath)
	err = svc.Initialize()
	assert.ErrorIs(t, err, ErrPolicyLoadFailed)
}

func TestFCP5_PlatformPolicyService_SavePolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "subdir", "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	err := svc.savePolicy(&PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	data, err := os.ReadFile(policyPath)
	require.NoError(t, err)

	var loaded PlatformPolicyDefinition
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)
	assert.Equal(t, "sha256", loaded.Bank)
}

// ---------------------------------------------------------------------------
// BrowserService: knownBrowsers, openSystemBrowser, saveConfig
// ---------------------------------------------------------------------------

func TestFCP5_KnownBrowsers_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-specific test")
	}

	browsers := knownBrowsers()
	assert.NotEmpty(t, browsers)

	names := make(map[string]bool)
	for _, b := range browsers {
		names[b.Name] = true
	}
	assert.True(t, names["Firefox"])
}

func TestFCP5_BrowserService_OpenSystemBrowser(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "browser.json")
	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	// Override the exec function to use "true" which exits immediately.
	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	err = svc.openSystemBrowser(context.Background(), "https://example.com")
	assert.NoError(t, err)
}

func TestFCP5_BrowserService_OpenSystemBrowser_Failure(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "browser.json")
	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/nonexistent/binary/that/does/not/exist")
	}

	err = svc.openSystemBrowser(context.Background(), "https://example.com")
	assert.Error(t, err)
}

func TestFCP5_BrowserService_SaveConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "subdir", "browser.json")
	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	err = svc.saveConfig(BrowserConfig{DefaultBrowser: "firefox"})
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	var cfg BrowserConfig
	err = json.Unmarshal(data, &cfg)
	require.NoError(t, err)
	assert.Equal(t, "firefox", cfg.DefaultBrowser)
}

// ---------------------------------------------------------------------------
// SealProtectionService: resetAutoLockTimer callback
// ---------------------------------------------------------------------------

func TestFCP5_APIExplorer_Execute_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer ts.Close()

	explorer := fcp5NewExplorer(t)

	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/test",
	})
	require.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)
	assert.Contains(t, resp.Body, "internal server error")
}

func TestFCP5_APIExplorer_Execute_WithBody(t *testing.T) {
	receivedBody := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1024)
		n, _ := r.Body.Read(body)
		receivedBody = string(body[:n])
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	explorer := fcp5NewExplorer(t)

	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "POST",
		URL:    ts.URL + "/api/test",
		Body:   `{"key":"value"}`,
	})
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, receivedBody, `"key":"value"`)
}

func TestFCP5_APIExplorer_Execute_WithCustomHeaders(t *testing.T) {
	receivedHeaders := make(map[string]string)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders["X-Custom"] = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	explorer := fcp5NewExplorer(t)

	resp, err := explorer.Execute(&ExplorerRequest{
		Method:  "GET",
		URL:     ts.URL + "/api/test",
		Headers: map[string]string{"X-Custom": "test-value"},
	})
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "test-value", receivedHeaders["X-Custom"])
}

func TestFCP5_APIExplorer_Execute_Closed(t *testing.T) {
	explorer := fcp5NewExplorer(t)
	explorer.closed.Store(true)
	_, execErr := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "http://localhost/test",
	})
	assert.ErrorIs(t, execErr, ErrExplorerClosed)
}

func TestFCP5_APIExplorer_Execute_NilRequest(t *testing.T) {
	explorer := fcp5NewExplorer(t)
	resp, err := explorer.Execute(nil)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "request is required")
}

func TestFCP5_APIExplorer_Execute_InvalidURL(t *testing.T) {
	explorer := fcp5NewExplorer(t)
	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "not-a-url",
	})
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "invalid URL")
}

func TestFCP5_APIExplorer_Execute_ConnectionRefused(t *testing.T) {
	explorer := fcp5NewExplorer(t)
	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "http://127.0.0.1:1/api/test",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Error)
	assert.True(t, resp.DurationMs >= 0)
}

// ---------------------------------------------------------------------------
// APIExplorerService: recordHistory success path
// ---------------------------------------------------------------------------

func TestFCP5_APIExplorer_RecordHistory(t *testing.T) {
	histBackend := storage.NewMemory()
	explorer := fcp5NewExplorer(t, func(c *ExplorerConfig) {
		c.HistoryStore = histBackend
	})

	explorer.recordHistory(
		&ExplorerRequest{Method: "GET", URL: "http://example.com/api/test"},
		&ExplorerResponse{StatusCode: 200, Body: "ok"},
	)

	keys, err := histBackend.List(context.Background(), historyKeyPrefix)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(keys), 1)
}

// ---------------------------------------------------------------------------
// APIExplorerService: DeleteHistoryEntry
// ---------------------------------------------------------------------------

func TestFCP5_APIExplorer_DeleteHistoryEntry_Success(t *testing.T) {
	explorer := fcp5NewExplorer(t)

	explorer.recordHistory(
		&ExplorerRequest{Method: "GET", URL: "http://example.com"},
		&ExplorerResponse{StatusCode: 200},
	)

	entries, err := explorer.GetHistory()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	err = explorer.DeleteHistoryEntry(entries[0].ID)
	assert.NoError(t, err)

	remaining, err := explorer.GetHistory()
	require.NoError(t, err)
	assert.Len(t, remaining, 0)
}

func TestFCP5_APIExplorer_DeleteHistoryEntry_NotFound(t *testing.T) {
	explorer := fcp5NewExplorer(t)
	err := explorer.DeleteHistoryEntry("nonexistent-id")
	assert.ErrorIs(t, err, ErrExplorerHistoryNotFound)
}

// ---------------------------------------------------------------------------
// SetupWizardService: GenerateSetupPINs, IsSetupComplete
// ---------------------------------------------------------------------------

func TestFCP5_SetupWizardService_GenerateSetupPINs_Success(t *testing.T) {
	svc := NewSetupWizardService()
	pins, err := svc.GenerateSetupPINs()
	require.NoError(t, err)
	require.NotNil(t, pins)
	assert.Len(t, pins.SOPin, 16)
	assert.Len(t, pins.UserPin, 12)
	assert.NotEqual(t, pins.SOPin, pins.UserPin)
}

func TestFCP5_SetupWizardService_IsSetupComplete_NoConfigFunc(t *testing.T) {
	svc := NewSetupWizardService()
	assert.True(t, svc.IsSetupComplete())
}

func TestFCP5_SetupWizardService_IsSetupComplete_NilConfig(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData { return nil })
	assert.True(t, svc.IsSetupComplete())
}

func TestFCP5_SetupWizardService_IsSetupComplete_NotComplete(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})
	assert.False(t, svc.IsSetupComplete())
}

func TestFCP5_SetupWizardService_IsSetupComplete_Complete(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: true}
	})
	assert.True(t, svc.IsSetupComplete())
}

// ---------------------------------------------------------------------------
// AdminService: GetBackendInfo
// ---------------------------------------------------------------------------

func TestFCP5_AdminService_GetBackendInfo_EmptyID(t *testing.T) {
	svc := NewAdminService()
	_, err := svc.GetBackendInfo("")
	assert.ErrorIs(t, err, ErrAdminBackendNotFound)
}

func TestFCP5_AdminService_GetBackendInfo_NotFound(t *testing.T) {
	svc := NewAdminService()
	_, err := svc.GetBackendInfo("nonexistent")
	assert.ErrorIs(t, err, ErrAdminBackendNotFound)
}

// ---------------------------------------------------------------------------
// Barrier: bestStrategyUnlocked
// ---------------------------------------------------------------------------

func TestFCP5_BarrierService_BestStrategyUnlocked_SoftwareAlwaysAvailable(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	strategy, err := svc.bestStrategyUnlocked()
	require.NoError(t, err)
	require.NotNil(t, strategy)
	assert.Equal(t, "software", strategy.ID)
	assert.True(t, strategy.Available)
}

func TestFCP5_BarrierService_BestStrategyUnlocked_AfterProbe(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	svc.ProbeStrategies()
	strategy, err := svc.bestStrategyUnlocked()
	require.NoError(t, err)
	require.NotNil(t, strategy)
	assert.Equal(t, "software", strategy.ID)
	assert.False(t, strategy.HardwareBacked)
}

// ---------------------------------------------------------------------------
// validateConfig (browser_service.go)
// ---------------------------------------------------------------------------

func TestFCP5_ValidateConfig_Valid(t *testing.T) {
	assert.NoError(t, validateConfig(BrowserConfig{DefaultBrowser: "firefox"}))
}

func TestFCP5_ValidateConfig_CustomCommand(t *testing.T) {
	assert.NoError(t, validateConfig(BrowserConfig{CustomCommand: "/usr/bin/custom"}))
}

func TestFCP5_ValidateConfig_Empty(t *testing.T) {
	assert.ErrorIs(t, validateConfig(BrowserConfig{}), ErrBrowserInvalidConfig)
}

// ---------------------------------------------------------------------------
// PlatformPolicyService: validatePCRSelection, validatePCRBank
// ---------------------------------------------------------------------------

func TestFCP5_ValidatePCRSelection_Empty(t *testing.T) {
	assert.ErrorIs(t, validatePCRSelection(nil), ErrPolicyInvalidPCRs)
}

func TestFCP5_ValidatePCRSelection_Valid(t *testing.T) {
	assert.NoError(t, validatePCRSelection([]int{0, 7, 14}))
}

func TestFCP5_ValidatePCRBank_Empty(t *testing.T) {
	assert.ErrorIs(t, validatePCRBank(""), ErrPolicyInvalidBank)
}

func TestFCP5_ValidatePCRBank_Valid(t *testing.T) {
	assert.NoError(t, validatePCRBank("sha256"))
}

// ---------------------------------------------------------------------------
// APIExplorerService: NewAPIExplorerService validation
// ---------------------------------------------------------------------------

func TestFCP5_NewAPIExplorerService_NilConfig(t *testing.T) {
	_, err := NewAPIExplorerService(nil)
	assert.ErrorIs(t, err, ErrExplorerNilConfig)
}

func TestFCP5_NewAPIExplorerService_NilTokenStore(t *testing.T) {
	_, err := NewAPIExplorerService(&ExplorerConfig{})
	assert.ErrorIs(t, err, ErrExplorerNilTokenStore)
}

func TestFCP5_NewAPIExplorerService_NilRegistry(t *testing.T) {
	_, err := NewAPIExplorerService(&ExplorerConfig{
		TokenStore: tokenstore.NewMemoryTokenStore(),
	})
	assert.ErrorIs(t, err, ErrExplorerNilRegistry)
}

func TestFCP5_NewAPIExplorerService_NilTrustStore(t *testing.T) {
	_, err := NewAPIExplorerService(&ExplorerConfig{
		TokenStore: tokenstore.NewMemoryTokenStore(),
		Registry:   serverregistry.NewMemoryServerRegistry(),
	})
	assert.ErrorIs(t, err, ErrExplorerNilTrustStore)
}

func TestFCP5_NewAPIExplorerService_NilHistoryStore(t *testing.T) {
	_, err := NewAPIExplorerService(&ExplorerConfig{
		TokenStore: tokenstore.NewMemoryTokenStore(),
		Registry:   serverregistry.NewMemoryServerRegistry(),
		TrustStore: storage.NewMemory(),
	})
	assert.ErrorIs(t, err, ErrExplorerNilHistoryStore)
}

// ---------------------------------------------------------------------------
// PlatformPolicyService: getPolicyClient, SetClient
// ---------------------------------------------------------------------------

func TestFCP5_PlatformPolicyService_GetPolicyClient_NotSet(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	_, err := svc.getPolicyClient()
	assert.ErrorIs(t, err, ErrPolicyNoClient)
}

func TestFCP5_PlatformPolicyService_VerifyPolicyRemote_EmptyName(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	_, err := svc.VerifyPolicyRemote("")
	assert.ErrorIs(t, err, ErrPolicyInvalidName)
}

func TestFCP5_PlatformPolicyService_ExportPolicyRemote_EmptyName(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	_, err := svc.ExportPolicyRemote("")
	assert.ErrorIs(t, err, ErrPolicyInvalidName)
}

func TestFCP5_PlatformPolicyService_VerifyPolicyRemote_NoClient(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	_, err := svc.VerifyPolicyRemote("test-policy")
	assert.ErrorIs(t, err, ErrPolicyNoClient)
}

func TestFCP5_PlatformPolicyService_ExportPolicyRemote_NoClient(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	_, err := svc.ExportPolicyRemote("test-policy")
	assert.ErrorIs(t, err, ErrPolicyNoClient)
}
