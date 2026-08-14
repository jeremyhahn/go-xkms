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
	"time"
)

// Cloud connection tester errors.
var (
	ErrCloudProviderUnknown     = errors.New("cloud_tester: unknown cloud provider")
	ErrCloudProviderNotBuilt    = errors.New("cloud_tester: provider not compiled into this build")
	ErrCloudTesterNotConfigured = errors.New("cloud_tester: connection tester not configured")
	ErrCloudProbeTimeout        = errors.New("cloud_tester: connection test timed out")
	ErrCloudConfigMissing       = errors.New("cloud_tester: required configuration missing")
)

// CloudProvider identifies a cloud key-management provider that xkey can
// register as a backend.
type CloudProvider string

// Cloud providers with a hardware-backed key management service.
const (
	CloudProviderAWSKMS  CloudProvider = "awskms"
	CloudProviderGCPKMS  CloudProvider = "gcpkms"
	CloudProviderAzureKV CloudProvider = "azurekv"
	CloudProviderVault   CloudProvider = "vault"
)

// cloudConnectionTimeout bounds a single cloud liveness probe. The GUI blocks
// on the connection test, so the probe must always return within this budget.
const cloudConnectionTimeout = 15 * time.Second

// cloudProviderNames maps a provider to the display name shown to the user.
var cloudProviderNames = map[CloudProvider]string{
	CloudProviderAWSKMS:  "AWS KMS",
	CloudProviderGCPKMS:  "GCP Cloud KMS",
	CloudProviderAzureKV: "Azure Key Vault",
	CloudProviderVault:   "HashiCorp Vault",
}

// cloudProviderName returns the display name for a provider, falling back to
// the provider identifier for providers without a registered name.
func cloudProviderName(provider CloudProvider) string {
	if name, ok := cloudProviderNames[provider]; ok {
		return name
	}
	return string(provider)
}

// CloudConnectionTester verifies live connectivity to a cloud key-management
// provider. Implementations perform a read-only, authenticated call against
// the provider; they never create, modify, or delete key material.
type CloudConnectionTester interface {
	// TestConnection performs a read-only liveness and authorization call
	// against the provider using the supplied backend configuration. It
	// returns nil only when the provider answered successfully.
	TestConnection(ctx context.Context, provider CloudProvider, config map[string]string) error

	// IsAvailable reports whether this build can reach the provider, which
	// requires the provider's backend to be compiled in.
	IsAvailable(provider CloudProvider) bool
}

// CloudProbe performs the provider-specific read-only liveness call.
type CloudProbe func(ctx context.Context, config map[string]string) error

// cloudProbes holds the liveness probes compiled into this build. Each
// provider registers its probe from an init function in a file guarded by the
// provider's build tag, so a provider that is not compiled in is genuinely
// reported as unavailable rather than assumed to work.
var cloudProbes = map[CloudProvider]CloudProbe{}

// registerCloudProbe records the liveness probe for a provider. It is called
// during package initialization, before any tester is constructed.
func registerCloudProbe(provider CloudProvider, probe CloudProbe) {
	cloudProbes[provider] = probe
}

// cloudTester is the production CloudConnectionTester. It dispatches to the
// provider probes compiled into this build.
type cloudTester struct {
	probes  map[CloudProvider]CloudProbe
	timeout time.Duration
}

// Compile-time check that cloudTester satisfies the tester contract.
var _ CloudConnectionTester = (*cloudTester)(nil)

// NewCloudConnectionTester returns a tester for the cloud providers compiled
// into this build.
func NewCloudConnectionTester() CloudConnectionTester {
	return newCloudTester(cloudProbes, cloudConnectionTimeout)
}

// newCloudTester builds a tester over an explicit probe set. Tests use it to
// substitute probes without reaching the network.
func newCloudTester(probes map[CloudProvider]CloudProbe, timeout time.Duration) *cloudTester {
	copied := make(map[CloudProvider]CloudProbe, len(probes))
	for provider, probe := range probes {
		copied[provider] = probe
	}
	if timeout <= 0 {
		timeout = cloudConnectionTimeout
	}
	return &cloudTester{probes: copied, timeout: timeout}
}

// IsAvailable reports whether a probe for the provider is compiled in.
func (t *cloudTester) IsAvailable(provider CloudProvider) bool {
	_, ok := t.probes[provider]
	return ok
}

// TestConnection runs the provider probe under a bounded context. The probe
// runs on its own goroutine so a provider SDK that ignores context
// cancellation can never block the GUI past the timeout.
func (t *cloudTester) TestConnection(ctx context.Context, provider CloudProvider, config map[string]string) error {
	probe, ok := t.probes[provider]
	if !ok {
		if _, known := cloudProviderNames[provider]; !known {
			return &DetailError{Err: ErrCloudProviderUnknown, Detail: ": " + string(provider)}
		}
		return &DetailError{Err: ErrCloudProviderNotBuilt, Detail: ": " + string(provider)}
	}

	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	// Buffered so the probe goroutine always completes its send and exits,
	// even after the timeout has already been reported to the caller.
	done := make(chan error, 1)
	go func() {
		done <- probe(ctx, config)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return &SentinelCauseError{Sentinel: ErrCloudProbeTimeout, Cause: ctx.Err()}
	}
}

// cloudConfigField describes a configuration value a provider requires before
// a connection test can be attempted.
type cloudConfigField struct {
	Key   string
	Label string
}

// cloudRequiredConfig lists the configuration each provider needs before a
// probe is worth attempting. The labels match the Add Backend form fields.
var cloudRequiredConfig = map[CloudProvider][]cloudConfigField{
	CloudProviderAWSKMS: {
		{Key: "region", Label: "Region"},
	},
	CloudProviderGCPKMS: {
		{Key: "project", Label: "Project ID"},
		{Key: "location", Label: "Location"},
		{Key: "keyring", Label: "Key Ring"},
	},
	CloudProviderAzureKV: {
		{Key: "vault_url", Label: "Vault URL"},
	},
	CloudProviderVault: {
		{Key: "address", Label: "Vault address"},
	},
}

// missingCloudConfig returns the first required field that is absent from the
// supplied configuration.
func missingCloudConfig(provider CloudProvider, config map[string]string) (cloudConfigField, bool) {
	for _, field := range cloudRequiredConfig[provider] {
		if strings.TrimSpace(config[field.Key]) == "" {
			return field, true
		}
	}
	return cloudConfigField{}, false
}

// cloudSecretKeys are configuration keys whose values are credentials. Their
// values must never reach a user-visible message or a log line.
var cloudSecretKeys = []string{
	"access_key_id",
	"secret_access_key",
	"session_token",
	"client_secret",
	"client_id",
	"tenant_id",
	"token",
	"credentials_json",
}

// cloudSecretMinLength is the shortest credential value that is redacted.
// Redacting very short values would corrupt unrelated text in the message.
const cloudSecretMinLength = 4

// redactCloudSecrets removes credential values that a provider error may have
// echoed back, so the connection test message never discloses a secret.
func redactCloudSecrets(msg string, config map[string]string) string {
	for _, key := range cloudSecretKeys {
		value := config[key]
		if len(value) < cloudSecretMinLength {
			continue
		}
		msg = strings.ReplaceAll(msg, value, "[redacted]")
	}
	return msg
}
