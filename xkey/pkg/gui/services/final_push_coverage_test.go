package services

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// ---------------------------------------------------------------------------
// Mock types scoped to TestFP_ tests
// ---------------------------------------------------------------------------

// fpMockTrustStore implements truststore.TrustStore with configurable errors.
type fpMockTrustStore struct {
	containsResult     bool
	containsErr        error
	addCertWithOptsErr error
}

func (m *fpMockTrustStore) AddCertificate(_ *x509.Certificate) error { return nil }
func (m *fpMockTrustStore) AddCertificateWithOptions(_ *x509.Certificate, _ *truststore.AddCertificateOptions) error {
	return m.addCertWithOptsErr
}
func (m *fpMockTrustStore) AddPEM(_ []byte) (int, error) { return 0, nil }
func (m *fpMockTrustStore) ImportPEM(_ []byte, _ *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	return truststore.ImportResult{}, nil
}
func (m *fpMockTrustStore) RemoveCertificate(_ string) error { return nil }
func (m *fpMockTrustStore) Certificates() ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *fpMockTrustStore) CertificatesByPurpose(_ truststore.CertPurpose) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *fpMockTrustStore) CertPool() (*x509.CertPool, error) { return nil, nil }
func (m *fpMockTrustStore) Contains(_ string) (bool, error) {
	return m.containsResult, m.containsErr
}
func (m *fpMockTrustStore) Count() (int, error)                                 { return 0, nil }
func (m *fpMockTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) { return nil, nil }
func (m *fpMockTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error { return nil }
func (m *fpMockTrustStore) SetSource(_ string, _ string) error                  { return nil }
func (m *fpMockTrustStore) SetSystemInstalled(_ string, _ bool) error           { return nil }
func (m *fpMockTrustStore) SetTags(_ string, _ []string) error                  { return nil }
func (m *fpMockTrustStore) Close() error                                        { return nil }
func (m *fpMockTrustStore) Reload() error                                       { return nil }

// fpMockStaticPWStore implements staticpw.Store (libpw.Store) with configurable
// List() behavior to exercise barrier-sealed detection.
type fpMockStaticPWStore struct {
	listErr error
}

func (m *fpMockStaticPWStore) Add(_ *xkms.StaticPassword) error           { return nil }
func (m *fpMockStaticPWStore) Get(_ string) (*xkms.StaticPassword, error) { return nil, nil }
func (m *fpMockStaticPWStore) List() ([]*xkms.StaticPassword, error)      { return nil, m.listErr }
func (m *fpMockStaticPWStore) Update(_ *xkms.StaticPassword) error        { return nil }
func (m *fpMockStaticPWStore) Delete(_ string) error                      { return nil }
func (m *fpMockStaticPWStore) ForceDelete(_ string) error                 { return nil }
func (m *fpMockStaticPWStore) ListByFolder(_ string) ([]*xkms.StaticPassword, error) {
	return nil, nil
}
func (m *fpMockStaticPWStore) ListFolders() ([]string, error) { return nil, nil }
func (m *fpMockStaticPWStore) ListByFolderDirect(_ string) ([]*xkms.StaticPassword, error) {
	return nil, nil
}
func (m *fpMockStaticPWStore) MoveToFolder(_ string, _ string) error {
	return nil
}
func (m *fpMockStaticPWStore) Close() error                { return nil }
func (m *fpMockStaticPWStore) CreateFolder(_ string) error { return nil }
func (m *fpMockStaticPWStore) RemoveFolder(_ string) error { return nil }

// ---------------------------------------------------------------------------
// 1. BarrierService: SetBaseBackendFactory + createBaseBackend factory error
// Targets:
//   barrier_service.go L92 (SetBaseBackendFactory body - 1 stmt)
//   barrier_service.go L329 (createBaseBackend custom factory path - 1 stmt)
//   barrier_service.go L192-194 (createBaseBackend error in Initialize - 1 stmt)
// ---------------------------------------------------------------------------

// TestFP_SetupWizardService_FactoryReset_PanicRecovery triggers the panic
// recovery defer block in FactoryReset (L1014-1019). A panicking configFunc
// is injected so the call at L1057 panics and the recovery at L1015-1018
// catches it, logging via slog.Error (global logger) and returning a
// formatted error.
func TestFP_SetupWizardService_FactoryReset_PanicRecovery(t *testing.T) {
	// Override the config directory to a temp dir so os.Remove at L1051
	// does not touch the real config file.
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	svc := &SetupWizardService{}
	svc.configDir = tmpDir

	// Set configFunc to a function that panics. configSave must also be
	// non-nil so the condition at L1056 is true, entering the block
	// where configFunc is called.
	svc.configFunc = func() *GUIConfigData {
		panic("fp_test: intentional panic for coverage")
	}
	svc.configSave = func(_ *GUIConfigData) error {
		return nil
	}

	// FactoryReset is credential-gated. Without a PIN service that accepts this
	// PIN the call is refused before reaching what this test covers (#313).
	svc.SetPINService(newWizardPINService(&wizardMockPINBackend{
		strategy: qrdbsdk.PINStrategySoftware, soPIN: "test-so-pin", soPINSet: true,
	}))

	err := svc.FactoryReset("test-so-pin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic in FactoryReset")
	assert.Contains(t, err.Error(), "fp_test: intentional panic for coverage")
}

// ---------------------------------------------------------------------------
// 4. TrustService: SeedEmbeddedRoots AddCertificateWithOptions error
// Targets:
//   trust_service.go L307-309 (AddCertificateWithOptions error - 1 stmt)
// ---------------------------------------------------------------------------

// TestFP_TrustService_SeedEmbeddedRoots_AddCertError uses a mock trust
// store that returns false for Contains (so the cert is not skipped) and
// returns an error for AddCertificateWithOptions. The android_hardware
// purpose is used because it is the only embedded purpose with actual
// root certificates loaded from the embedded filesystem.
func TestFP_TrustService_SeedEmbeddedRoots_AddCertError(t *testing.T) {
	addErr := errors.New("fp_test: add certificate failed")
	store := &fpMockTrustStore{
		containsResult:     false,
		addCertWithOptsErr: addErr,
	}
	svc := NewTrustService(store)

	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	assert.Equal(t, 0, count)
	assert.ErrorIs(t, err, addErr)
}

// ---------------------------------------------------------------------------
// 5. SetupWizardService: ApplySetup barrier auto-unseal (success path)
// Targets:
//   setup_wizard_service.go L558-560 (enter barrier auto-unseal block - 2 stmts)
//   setup_wizard_service.go L560-562 (UseUserPinAsMaster path - 1 stmt)
//   setup_wizard_service.go L563-564 (CanSeal + if condition - 2 stmts)
//   setup_wizard_service.go L564-566 (policyType + platform check - 2 stmts)
//   setup_wizard_service.go L569-574 (req + SealData call - 2 stmts)
//   setup_wizard_service.go L577-579 (success: set blobID - 1 stmt)
//   setup_wizard_service.go L600-602 (config save with blobID - 1 stmt)
// ---------------------------------------------------------------------------

// TestFP_SetupWizard_ApplySetup_BarrierAutoUnseal exercises the barrier
// auto-unseal code path in ApplySetup without a local TPM policy service:
// setup completes, warns that the barrier needs a manual unlock on restart,
// and leaves auto-unseal off for a passphrase barrier.
func TestFP_SetupWizard_ApplySetup_BarrierAutoUnseal(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	// Create a real BarrierService that uses software strategy.
	barrierSvc := NewBarrierService(tmpDir, slog.Default())

	// Create a SealService with a software sealer that actually works.
	sealDir := t.TempDir()
	sealSvc := NewSealService(sealDir)
	wireSealMockClient(sealSvc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true})
	sealSvc.SetContext(context.Background())
	sealSvc.SetDefaultBackend("software")

	// Create the wizard with the required dependencies.
	svc := &SetupWizardService{}
	svc.configDir = tmpDir
	svc.barrierSvc = barrierSvc
	svc.sealSvc = sealSvc

	cfg := &GUIConfigData{SetupComplete: false}
	svc.configFunc = func() *GUIConfigData { return cfg }
	svc.configSave = func(c *GUIConfigData) error {
		*cfg = *c
		return nil
	}

	choices := &SetupChoices{
		Mode:               "standalone",
		SOPin:              "123456",
		UserPin:            "654321",
		StorageType:        "barrier",
		BarrierPassword:    "barrier-test-pw",
		UseUserPinAsMaster: true, // Covers L560-562
		SealerBackend:      "passphrase",
		EnableAutoUnseal:   true, // Enters auto-unseal block
	}

	result, err := svc.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success, "ApplySetup should succeed; errors: %v", result.Errors)

	assert.True(t, cfg.BarrierInitialized)
	assert.Equal(t, "passphrase", cfg.BarrierStrategy)
	assert.False(t, cfg.BarrierAutoUnsealEnabled, "no TPM policy service: no auto-unseal")
	assert.True(t, containsSubstring(result.Warnings, "barrier auto-unseal"),
		"expected a barrier auto-unseal warning, got %v", result.Warnings)
}

// ---------------------------------------------------------------------------
// 7. StaticPasswordService: ListPasswords barrier sealed error detection
// Targets:
//   staticpw_service.go L179-181 (barrier sealed error detection - 1 stmt)
// ---------------------------------------------------------------------------

// TestFP_StaticPW_ListPasswords_BarrierSealed exercises the barrier-sealed
// error detection in ListPasswords. When the underlying store returns an
// error with the message "seal: barrier is sealed", the service wraps it
// as ErrStaticPWBarrierSealed.
func TestFP_StaticPW_ListPasswords_BarrierSealed(t *testing.T) {
	mockStore := &fpMockStaticPWStore{
		listErr: errors.New("seal: barrier is sealed"),
	}
	svc := NewStaticPasswordService(mockStore)

	entries, err := svc.ListPasswords()
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrStaticPWBarrierSealed)
}

// TestFP_BarrierService_Initialize_FactoryError verifies that Initialize
// propagates an error from the custom BaseBackendFactory. The factory is
// called at barrier_service.go L191 via createBaseBackend (L329) which
// enters the custom factory path because SetBaseBackendFactory (L92) was
// called. The barrier directory does not exist, so the existence-check
// branch at L158 is skipped.
func TestFP_BarrierService_Initialize_FactoryError(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	factoryErr := errors.New("factory error: backend unavailable")

	// SetBaseBackendFactory covers L92 (body of the setter).
	svc.SetBaseBackendFactory(func(_ string) (xkms.StorageBackend, error) {
		// Returning an error exercises:
		//   - L329 (createBaseBackend enters factory branch)
		//   - L192 (Initialize handles error from createBaseBackend)
		return nil, factoryErr
	})

	err := svc.Initialize("test-password-123", "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, factoryErr)
}
