//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createSimNoStore creates a TPM2 instance backed by the software simulator
// with nil BlobStore and nil Backend. It is used to verify that capability
// and config queries work without any persistent storage configured.
func createSimNoStore(t *testing.T) TrustedPlatformModule {
	t.Helper()

	logger := slog.Default()

	config := &Config{
		EncryptSession: false,
		UseEntropy:     false,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity:                []string{},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         "SHA-256",
			Handle:       uint32(0x81010002),
			KeyAlgorithm: "RSA",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: "SHA256-RSAPSS",
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  "RSA",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		PlatformSRK: &PlatformSRKConfig{
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    nil, // intentionally nil
		Backend:      nil, // intentionally nil
		FQDN:         "node1.example.com",
	}

	tpm, err := NewTPM2(params)
	if err == ErrNotInitialized {
		require.NoError(t, tpm.Provision(nil), "provisioning TPM with nil stores must succeed")
		return tpm
	}
	require.NoError(t, err, "NewTPM2 with nil stores must succeed")
	return tpm
}

// TestFixedPropertiesWithNilStore verifies that FixedProperties succeeds when
// the TPM was created with nil BlobStore and nil Backend. Capability queries
// communicate directly with the TPM transport and must never touch the store.
func TestFixedPropertiesWithNilStore(t *testing.T) {
	tpm := createSimNoStore(t)
	defer func() { _ = tpm.Close() }()

	props, err := tpm.FixedProperties()
	require.NoError(t, err, "FixedProperties must succeed with nil stores")

	// The IBM software simulator always reports these values.
	assert.NotEmpty(t, props.Manufacturer, "Manufacturer must be populated")
	assert.NotEmpty(t, props.Family, "Family must be populated")
	assert.True(t, props.FwMajor > 0 || props.FwMinor >= 0,
		"Firmware version fields must be present")
	assert.Greater(t, props.ActiveSessionsMax, uint32(0),
		"ActiveSessionsMax must be non-zero")
	assert.Greater(t, props.MaxCommandSize, uint32(0),
		"MaxCommandSize must be non-zero")
}

// TestFixedPropertiesWithNilStore_FirmwareVersion verifies that firmware
// version fields returned by FixedProperties are non-negative integers when
// the TPM was created without any persistent storage.
func TestFixedPropertiesWithNilStore_FirmwareVersion(t *testing.T) {
	tpm := createSimNoStore(t)
	defer func() { _ = tpm.Close() }()

	props, err := tpm.FixedProperties()
	require.NoError(t, err)

	// FwMajor and FwMinor are int64; the simulator always returns non-negative values.
	assert.GreaterOrEqual(t, props.FwMajor, int64(0), "FwMajor must be non-negative")
	assert.GreaterOrEqual(t, props.FwMinor, int64(0), "FwMinor must be non-negative")
}

// TestConfigWithNilStore verifies that Config() returns a valid, non-nil
// configuration when the TPM was created with nil BlobStore and nil Backend.
func TestConfigWithNilStore(t *testing.T) {
	tpm := createSimNoStore(t)
	defer func() { _ = tpm.Close() }()

	cfg := tpm.Config()
	require.NotNil(t, cfg, "Config must not be nil with nil stores")

	assert.True(t, cfg.UseSimulator, "UseSimulator must reflect the params passed in")
	assert.Equal(t, "SHA-256", cfg.Hash, "Hash must reflect the params passed in")
	assert.NotNil(t, cfg.EK, "EK config must be populated")
	assert.Equal(t, uint32(0x81010001), cfg.EK.Handle, "EK handle must match params")
}

// TestDeviceWithNilStore verifies that Device() returns the configured device
// path when the TPM was created with nil BlobStore and nil Backend.
func TestDeviceWithNilStore(t *testing.T) {
	tpm := createSimNoStore(t)
	defer func() { _ = tpm.Close() }()

	device := tpm.Device()
	assert.Equal(t, "/dev/tpmrm0", device,
		"Device must return the configured path even with nil stores")
}
