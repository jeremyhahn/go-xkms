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
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeCloudTester substitutes the compiled-in provider probes so the
// connection test logic can be exercised without network access.
type fakeCloudTester struct {
	mu         sync.Mutex
	available  map[CloudProvider]bool
	errs       map[CloudProvider]error
	calls      []CloudProvider
	lastConfig map[string]string
}

func newFakeCloudTester(providers ...CloudProvider) *fakeCloudTester {
	f := &fakeCloudTester{
		available: make(map[CloudProvider]bool, len(providers)),
		errs:      make(map[CloudProvider]error, len(providers)),
	}
	for _, p := range providers {
		f.available[p] = true
	}
	return f
}

// allCloudProviders returns every provider the Add Backend dialog offers.
func allCloudProviders() []CloudProvider {
	return []CloudProvider{
		CloudProviderAWSKMS,
		CloudProviderGCPKMS,
		CloudProviderAzureKV,
		CloudProviderVault,
	}
}

func newFakeCloudTesterAll() *fakeCloudTester {
	return newFakeCloudTester(allCloudProviders()...)
}

func (f *fakeCloudTester) failWith(provider CloudProvider, err error) *fakeCloudTester {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[provider] = err
	return f
}

func (f *fakeCloudTester) IsAvailable(provider CloudProvider) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available[provider]
}

func (f *fakeCloudTester) TestConnection(ctx context.Context, provider CloudProvider, config map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, provider)
	f.lastConfig = config
	return f.errs[provider]
}

func (f *fakeCloudTester) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// validCloudConfig returns a well-formed configuration for a provider. The
// endpoints are syntactically valid but point at hosts that do not exist.
func validCloudConfig(provider CloudProvider) map[string]string {
	switch provider {
	case CloudProviderAWSKMS:
		return map[string]string{
			"region":            "us-east-1",
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY",
		}
	case CloudProviderGCPKMS:
		return map[string]string{
			"project":  "my-project",
			"location": "us-central1",
			"keyring":  "my-keyring",
		}
	case CloudProviderAzureKV:
		return map[string]string{
			"vault_url":     "https://myvault.vault.azure.net",
			"tenant_id":     "8a4de9b1-0000-4000-8000-1234567890ab",
			"client_id":     "2b7c1a55-0000-4000-8000-0987654321ba",
			"client_secret": "s3cr3t-client-secret-value",
		}
	case CloudProviderVault:
		return map[string]string{
			"address": "https://vault.invalid:8200",
			"token":   "hvs.THISISNOTAREALTOKEN",
		}
	default:
		return map[string]string{}
	}
}

// backendTypeFor maps a provider to the backend type string the frontend
// passes to TestBackendConnection.
func backendTypeFor(provider CloudProvider) string {
	return string(provider)
}

// ---------------------------------------------------------------------------
// cloudTester: dispatch, availability, and timeout bounding
// ---------------------------------------------------------------------------

func TestCloudTester_IsAvailableReflectsCompiledProbes(t *testing.T) {
	tester := NewCloudConnectionTester()
	for _, provider := range allCloudProviders() {
		_, compiled := cloudProbes[provider]
		assert.Equal(t, compiled, tester.IsAvailable(provider),
			"availability for %s must match the compiled-in probe set", provider)
	}
}

func TestCloudTester_TestConnectionRunsProbe(t *testing.T) {
	var gotConfig map[string]string
	tester := newCloudTester(map[CloudProvider]CloudProbe{
		CloudProviderAWSKMS: func(_ context.Context, config map[string]string) error {
			gotConfig = config
			return nil
		},
	}, time.Second)

	err := tester.TestConnection(context.Background(), CloudProviderAWSKMS, map[string]string{"region": "us-east-1"})
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", gotConfig["region"])
	assert.True(t, tester.IsAvailable(CloudProviderAWSKMS))
}

func TestCloudTester_TestConnectionPropagatesProbeError(t *testing.T) {
	probeErr := errors.New("api error AccessDeniedException")
	tester := newCloudTester(map[CloudProvider]CloudProbe{
		CloudProviderVault: func(_ context.Context, _ map[string]string) error { return probeErr },
	}, time.Second)

	err := tester.TestConnection(context.Background(), CloudProviderVault, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, probeErr)
}

func TestCloudTester_TestConnectionProviderNotCompiled(t *testing.T) {
	tester := newCloudTester(map[CloudProvider]CloudProbe{}, time.Second)

	err := tester.TestConnection(context.Background(), CloudProviderGCPKMS, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCloudProviderNotBuilt)
	assert.False(t, tester.IsAvailable(CloudProviderGCPKMS))
}

func TestCloudTester_TestConnectionUnknownProvider(t *testing.T) {
	tester := newCloudTester(map[CloudProvider]CloudProbe{}, time.Second)

	err := tester.TestConnection(context.Background(), CloudProvider("oracle-kms"), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCloudProviderUnknown)
	assert.Contains(t, err.Error(), "oracle-kms")
}

func TestCloudTester_TestConnectionTimesOutOnCooperativeProbe(t *testing.T) {
	tester := newCloudTester(map[CloudProvider]CloudProbe{
		CloudProviderAzureKV: func(ctx context.Context, _ map[string]string) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, 20*time.Millisecond)

	start := time.Now()
	err := tester.TestConnection(context.Background(), CloudProviderAzureKV, nil)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
	// Either the probe observed cancellation first or the watchdog fired;
	// both must surface a deadline, never a success.
	assert.True(t,
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrCloudProbeTimeout),
		"expected a deadline error, got %v", err)
}

func TestCloudTester_TestConnectionBoundsProbeThatIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	tester := newCloudTester(map[CloudProvider]CloudProbe{
		CloudProviderAWSKMS: func(_ context.Context, _ map[string]string) error {
			<-release
			return nil
		},
	}, 20*time.Millisecond)

	start := time.Now()
	err := tester.TestConnection(context.Background(), CloudProviderAWSKMS, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCloudProbeTimeout)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestCloudTester_TestConnectionHonorsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tester := newCloudTester(map[CloudProvider]CloudProbe{
		CloudProviderVault: func(ctx context.Context, _ map[string]string) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, time.Minute)

	err := tester.TestConnection(ctx, CloudProviderVault, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestCloudTester_TestConnectionAcceptsNilContext(t *testing.T) {
	tester := newCloudTester(map[CloudProvider]CloudProbe{
		CloudProviderVault: func(ctx context.Context, _ map[string]string) error {
			if ctx == nil {
				return errors.New("probe received a nil context")
			}
			if _, ok := ctx.Deadline(); !ok {
				return errors.New("probe context has no deadline")
			}
			return nil
		},
	}, time.Second)

	//nolint:staticcheck // exercising the nil-context guard on purpose.
	require.NoError(t, tester.TestConnection(nil, CloudProviderVault, nil))
}

func TestNewCloudTester_DefaultsTimeoutAndCopiesProbes(t *testing.T) {
	probes := map[CloudProvider]CloudProbe{
		CloudProviderAWSKMS: func(context.Context, map[string]string) error { return nil },
	}
	tester := newCloudTester(probes, 0)
	assert.Equal(t, cloudConnectionTimeout, tester.timeout)

	// Mutating the source map must not change the tester's probe set.
	delete(probes, CloudProviderAWSKMS)
	assert.True(t, tester.IsAvailable(CloudProviderAWSKMS))
}

// ---------------------------------------------------------------------------
// Configuration validation and redaction helpers
// ---------------------------------------------------------------------------

func TestMissingCloudConfig(t *testing.T) {
	tests := []struct {
		name      string
		provider  CloudProvider
		config    map[string]string
		wantKey   string
		wantLabel string
		wantMiss  bool
	}{
		{name: "awskms complete", provider: CloudProviderAWSKMS, config: map[string]string{"region": "us-east-1"}},
		{name: "awskms missing region", provider: CloudProviderAWSKMS, config: map[string]string{}, wantKey: "region", wantLabel: "Region", wantMiss: true},
		{name: "awskms blank region", provider: CloudProviderAWSKMS, config: map[string]string{"region": "   "}, wantKey: "region", wantLabel: "Region", wantMiss: true},
		{name: "gcpkms missing project", provider: CloudProviderGCPKMS, config: map[string]string{}, wantKey: "project", wantLabel: "Project ID", wantMiss: true},
		{name: "gcpkms missing location", provider: CloudProviderGCPKMS, config: map[string]string{"project": "p"}, wantKey: "location", wantLabel: "Location", wantMiss: true},
		{name: "gcpkms missing keyring", provider: CloudProviderGCPKMS, config: map[string]string{"project": "p", "location": "l"}, wantKey: "keyring", wantLabel: "Key Ring", wantMiss: true},
		{name: "gcpkms complete", provider: CloudProviderGCPKMS, config: map[string]string{"project": "p", "location": "l", "keyring": "k"}},
		{name: "azurekv missing url", provider: CloudProviderAzureKV, config: map[string]string{}, wantKey: "vault_url", wantLabel: "Vault URL", wantMiss: true},
		{name: "vault missing address", provider: CloudProviderVault, config: map[string]string{}, wantKey: "address", wantLabel: "Vault address", wantMiss: true},
		{name: "unknown provider has no requirements", provider: CloudProvider("nope"), config: map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			field, missing := missingCloudConfig(tt.provider, tt.config)
			assert.Equal(t, tt.wantMiss, missing)
			assert.Equal(t, tt.wantKey, field.Key)
			assert.Equal(t, tt.wantLabel, field.Label)
		})
	}
}

func TestRedactCloudSecrets(t *testing.T) {
	config := map[string]string{
		"region":            "us-east-1",
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY",
		"token":             "hvs.SUPERSECRETTOKEN",
		"client_secret":     "azure-client-secret",
		"mount_path":        "kv",
	}

	msg := "auth failed for AKIAIOSFODNN7EXAMPLE using wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY " +
		"and hvs.SUPERSECRETTOKEN and azure-client-secret in us-east-1 (mount kv)"
	got := redactCloudSecrets(msg, config)

	assert.NotContains(t, got, "AKIAIOSFODNN7EXAMPLE")
	assert.NotContains(t, got, "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY")
	assert.NotContains(t, got, "hvs.SUPERSECRETTOKEN")
	assert.NotContains(t, got, "azure-client-secret")
	// Non-credential values stay so the message remains actionable.
	assert.Contains(t, got, "us-east-1")
	assert.Contains(t, got, "(mount kv)")
	assert.Equal(t, 4, strings.Count(got, "[redacted]"))
}

func TestRedactCloudSecrets_IgnoresShortAndEmptyValues(t *testing.T) {
	config := map[string]string{"token": "ab", "client_secret": ""}
	msg := "connection refused to https://vault.example.com:8200"
	assert.Equal(t, msg, redactCloudSecrets(msg, config))
}

func TestCloudProviderName(t *testing.T) {
	assert.Equal(t, "AWS KMS", cloudProviderName(CloudProviderAWSKMS))
	assert.Equal(t, "GCP Cloud KMS", cloudProviderName(CloudProviderGCPKMS))
	assert.Equal(t, "Azure Key Vault", cloudProviderName(CloudProviderAzureKV))
	assert.Equal(t, "HashiCorp Vault", cloudProviderName(CloudProviderVault))
	assert.Equal(t, "unknown-provider", cloudProviderName(CloudProvider("unknown-provider")))
}

// ---------------------------------------------------------------------------
// AdminService cloud connection tests
// ---------------------------------------------------------------------------

func TestAdminService_CloudConnection_SuccessRequiresRealProbe(t *testing.T) {
	for _, provider := range allCloudProviders() {
		t.Run(string(provider), func(t *testing.T) {
			tester := newFakeCloudTesterAll()
			svc := NewAdminService()
			svc.SetCloudTester(tester)

			result := svc.TestBackendConnection(backendTypeFor(provider), validCloudConfig(provider))
			require.NotNil(t, result)
			assert.True(t, result.Success)
			assert.Contains(t, result.Message, "Successfully connected to "+cloudProviderName(provider))
			assert.Equal(t, 1, tester.callCount(), "the provider must actually be probed")
		})
	}
}

func TestAdminService_CloudConnection_AuthFailure(t *testing.T) {
	authErrors := map[CloudProvider]error{
		CloudProviderAWSKMS:  errors.New("AWS KMS ListKeys: api error UnrecognizedClientException: The security token included in the request is invalid"),
		CloudProviderGCPKMS:  errors.New("GCP Cloud KMS key ring: rpc error: code = PermissionDenied desc = caller lacks cloudkms.cryptoKeys.list"),
		CloudProviderAzureKV: errors.New("Azure Key Vault list keys: GET https://myvault.vault.azure.net/keys: 403 Forbidden"),
		CloudProviderVault:   errors.New("HashiCorp Vault transit mount transit: Error making API request: permission denied"),
	}

	for provider, authErr := range authErrors {
		t.Run(string(provider), func(t *testing.T) {
			tester := newFakeCloudTesterAll().failWith(provider, authErr)
			svc := NewAdminService()
			svc.SetCloudTester(tester)

			result := svc.TestBackendConnection(backendTypeFor(provider), validCloudConfig(provider))
			require.NotNil(t, result)
			assert.False(t, result.Success)
			assert.Contains(t, result.Message, "Connection to "+cloudProviderName(provider)+" failed")
		})
	}
}

func TestAdminService_CloudConnection_UnreachableEndpoint(t *testing.T) {
	for _, provider := range allCloudProviders() {
		t.Run(string(provider), func(t *testing.T) {
			tester := newFakeCloudTesterAll().failWith(provider,
				errors.New("dial tcp 203.0.113.7:443: connect: connection refused"))
			svc := NewAdminService()
			svc.SetCloudTester(tester)

			result := svc.TestBackendConnection(backendTypeFor(provider), validCloudConfig(provider))
			require.NotNil(t, result)
			assert.False(t, result.Success)
			assert.Contains(t, result.Message, "connection refused")
		})
	}
}

func TestAdminService_CloudConnection_Timeout(t *testing.T) {
	for _, provider := range allCloudProviders() {
		t.Run(string(provider), func(t *testing.T) {
			tester := newFakeCloudTesterAll().failWith(provider,
				&SentinelCauseError{Sentinel: ErrCloudProbeTimeout, Cause: context.DeadlineExceeded})
			svc := NewAdminService()
			svc.SetCloudTester(tester)

			result := svc.TestBackendConnection(backendTypeFor(provider), validCloudConfig(provider))
			require.NotNil(t, result)
			assert.False(t, result.Success)
			assert.Contains(t, result.Message, "timed out")
		})
	}
}

func TestAdminService_CloudConnection_MissingRequiredConfig(t *testing.T) {
	tests := []struct {
		name        string
		backendType string
		config      map[string]string
		wantMessage string
	}{
		{name: "awskms without region", backendType: "awskms", config: map[string]string{}, wantMessage: "Region is required"},
		{name: "gcpkms without project", backendType: "gcpkms", config: map[string]string{}, wantMessage: "Project ID is required"},
		{name: "gcpkms without location", backendType: "gcpkms", config: map[string]string{"project": "p"}, wantMessage: "Location is required"},
		{name: "gcpkms without keyring", backendType: "gcpkms", config: map[string]string{"project": "p", "location": "l"}, wantMessage: "Key Ring is required"},
		{name: "azurekv without vault url", backendType: "azurekv", config: map[string]string{}, wantMessage: "Vault URL is required"},
		{name: "vault without address", backendType: "vault", config: map[string]string{}, wantMessage: "Vault address is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tester := newFakeCloudTesterAll()
			svc := NewAdminService()
			svc.SetCloudTester(tester)

			result := svc.TestBackendConnection(tt.backendType, tt.config)
			require.NotNil(t, result)
			assert.False(t, result.Success)
			assert.Equal(t, tt.wantMessage, result.Message)
			assert.Zero(t, tester.callCount(), "an incomplete configuration must not reach the provider")
		})
	}
}

func TestAdminService_CloudConnection_ProviderNotCompiledIn(t *testing.T) {
	for _, provider := range allCloudProviders() {
		t.Run(string(provider), func(t *testing.T) {
			// A tester with no providers available models a build without
			// the provider's backend tag.
			svc := NewAdminService()
			svc.SetCloudTester(newFakeCloudTester())

			result := svc.TestBackendConnection(backendTypeFor(provider), validCloudConfig(provider))
			require.NotNil(t, result)
			assert.False(t, result.Success)
			assert.Contains(t, result.Message, "not compiled into this build")
		})
	}
}

func TestAdminService_CloudConnection_NoTesterConfigured(t *testing.T) {
	svc := &AdminService{}

	for _, provider := range allCloudProviders() {
		result := svc.TestBackendConnection(backendTypeFor(provider), validCloudConfig(provider))
		require.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "not configured")
	}
}

// TestAdminService_CloudConnection_NeverReportsSuccessWithoutProbing is the
// regression guard for the stub that reported "configuration valid" as a
// success for any non-empty configuration. A well-formed configuration that
// points nowhere must fail.
func TestAdminService_CloudConnection_NeverReportsSuccessWithoutProbing(t *testing.T) {
	unreachable := errors.New("dial tcp: lookup nowhere.invalid: no such host")

	for _, provider := range allCloudProviders() {
		t.Run(string(provider), func(t *testing.T) {
			tester := newFakeCloudTesterAll().failWith(provider, unreachable)
			svc := NewAdminService()
			svc.SetCloudTester(tester)

			result := svc.TestBackendConnection(backendTypeFor(provider), validCloudConfig(provider))
			require.NotNil(t, result)
			assert.False(t, result.Success)
			assert.NotContains(t, result.Message, "configuration valid")
			assert.NotContains(t, result.Message, "not implemented")
			assert.Equal(t, 1, tester.callCount())
		})
	}
}

// TestAdminService_CloudConnection_DoesNotLeakCredentials ensures a provider
// error that echoes a credential is redacted before it reaches the GUI.
func TestAdminService_CloudConnection_DoesNotLeakCredentials(t *testing.T) {
	config := validCloudConfig(CloudProviderVault)
	tester := newFakeCloudTesterAll().failWith(CloudProviderVault,
		errors.New("permission denied for token "+config["token"]))

	svc := NewAdminService()
	svc.SetCloudTester(tester)

	result := svc.TestBackendConnection("vault", config)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotContains(t, result.Message, config["token"])
	assert.Contains(t, result.Message, "[redacted]")
}

// ---------------------------------------------------------------------------
// AdminService cloud availability
// ---------------------------------------------------------------------------

func TestAdminService_CloudAvailability_NoTester(t *testing.T) {
	svc := &AdminService{}

	assert.False(t, svc.isAWSKMSAvailable())
	assert.False(t, svc.isGCPKMSAvailable())
	assert.False(t, svc.isAzureKVAvailable())
	assert.False(t, svc.isVaultAvailable())
}

func TestAdminService_CloudAvailability_ReflectsTester(t *testing.T) {
	svc := NewAdminService()
	svc.SetCloudTester(newFakeCloudTester(CloudProviderVault, CloudProviderGCPKMS))

	assert.False(t, svc.isAWSKMSAvailable())
	assert.True(t, svc.isGCPKMSAvailable())
	assert.False(t, svc.isAzureKVAvailable())
	assert.True(t, svc.isVaultAvailable())
}

func TestAdminService_GetAvailableBackendTypes_CloudHonesty(t *testing.T) {
	svc := NewAdminService()
	svc.SetCloudTester(newFakeCloudTester(CloudProviderAWSKMS))

	types := make(map[string]AvailableBackendType)
	for _, bt := range svc.GetAvailableBackendTypes() {
		types[bt.Type] = bt
	}

	require.Contains(t, types, "awskms")
	assert.True(t, types["awskms"].Available)
	assert.False(t, types["gcpkms"].Available)
	assert.False(t, types["azurekv"].Available)
	assert.False(t, types["vault"].Available)
}

func TestNewAdminService_WiresCompiledCloudTester(t *testing.T) {
	svc := NewAdminService()
	require.NotNil(t, svc.cloudTester)

	for _, provider := range allCloudProviders() {
		_, compiled := cloudProbes[provider]
		assert.Equal(t, compiled, svc.isCloudProviderAvailable(provider))
	}
}

// TestRegisterCloudProbe exercises the seam the build-tag guarded probe files
// use: registering a probe makes the provider genuinely available.
func TestRegisterCloudProbe(t *testing.T) {
	const provider = CloudProvider("registration-probe")
	require.NotContains(t, cloudProbes, provider)
	t.Cleanup(func() { delete(cloudProbes, provider) })

	var called bool
	registerCloudProbe(provider, func(context.Context, map[string]string) error {
		called = true
		return nil
	})

	tester := NewCloudConnectionTester()
	require.True(t, tester.IsAvailable(provider))
	require.NoError(t, tester.TestConnection(context.Background(), provider, nil))
	assert.True(t, called)
}
