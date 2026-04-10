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
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// tpcbPanicTPM embeds mockTPM but overrides specific methods to panic,
// allowing us to exercise panic recovery defer blocks in TPMService methods.
// ---------------------------------------------------------------------------

type tpcbPanicTPM struct {
	mockTPM
	panicOnSetHierarchyAuth bool
	panicOnEKCert           bool
	panicOnDictionaryReset  bool
	panicOnCertifyKey       bool
	panicOnRandomBytes      bool
}

func (m *tpcbPanicTPM) SetHierarchyAuth(_, _ types.Password, _ *tpm2.TPMHandle) error {
	if m.panicOnSetHierarchyAuth {
		panic("tpcbPanicTPM: SetHierarchyAuth panic")
	}
	return m.setHierarchyAuthErr
}

func (m *tpcbPanicTPM) EKCertificate() (*x509.Certificate, error) {
	if m.panicOnEKCert {
		panic("tpcbPanicTPM: EKCertificate panic")
	}
	return m.ekCert, m.ekCertErr
}

func (m *tpcbPanicTPM) DictionaryAttackLockoutReset(_ []byte) error {
	if m.panicOnDictionaryReset {
		panic("tpcbPanicTPM: DictionaryAttackLockoutReset panic")
	}
	return m.lockoutResetErr
}

func (m *tpcbPanicTPM) RandomBytes(_ int) ([]byte, error) {
	if m.panicOnRandomBytes {
		panic("tpcbPanicTPM: RandomBytes panic")
	}
	return m.randomBytesVal, m.randomBytesErr
}

func newTPCBPanicMock() *tpcbPanicTPM {
	return &tpcbPanicTPM{
		mockTPM: *defaultMockTPM(),
	}
}

func newTPCBTPMService(tpm tpm2pkg.TrustedPlatformModule) *TPMService {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	if tpm != nil {
		accessor := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return tpm })
		svc.SetTPMAccessor(accessor)
	}
	return svc
}

// ---------------------------------------------------------------------------
// TPM: changeHierarchyAuth panic recovery -- SetHierarchyAuth panics
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ChangeOwnerAuth_PanicRecovery(t *testing.T) {
	mock := newTPCBPanicMock()
	mock.panicOnSetHierarchyAuth = true
	svc := newTPCBTPMService(mock)

	err := svc.ChangeOwnerAuth("", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic in changeHierarchyAuth")
}

func TestTPMPhoneCoverageBoost_ChangeEndorsementAuth_PanicRecovery(t *testing.T) {
	mock := newTPCBPanicMock()
	mock.panicOnSetHierarchyAuth = true
	svc := newTPCBTPMService(mock)

	err := svc.ChangeEndorsementAuth("", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic in changeHierarchyAuth")
}

func TestTPMPhoneCoverageBoost_ChangeLockoutAuth_PanicRecovery(t *testing.T) {
	mock := newTPCBPanicMock()
	mock.panicOnSetHierarchyAuth = true
	svc := newTPCBTPMService(mock)

	err := svc.ChangeLockoutAuth("", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic in changeHierarchyAuth")
}

// ---------------------------------------------------------------------------
// TPM: VerifyTPM panic recovery -- EKCertificate panics
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_GetVerificationStatus_PanicRecovery(t *testing.T) {
	mock := newTPCBPanicMock()
	mock.panicOnEKCert = true
	svc := newTPCBTPMService(mock)

	// GetVerificationStatus delegates to VerifyTPM which calls EKCertificate.
	// The panic in EKCertificate is caught by VerifyTPM's recover block.
	status, err := svc.GetVerificationStatus()
	require.Error(t, err)
	assert.Nil(t, status)
	assert.Contains(t, err.Error(), "panic in VerifyTPM")
}

// ---------------------------------------------------------------------------
// TPM: ForceResetLockout panic recovery
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ForceResetLockout_PanicRecovery(t *testing.T) {
	mock := newTPCBPanicMock()
	mock.panicOnDictionaryReset = true
	svc := newTPCBTPMService(mock)

	err := svc.ForceResetLockout("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic in ForceResetLockout")
}

// ---------------------------------------------------------------------------
// TPM: CertifyKey panic recovery -- RandomBytes panics
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_CertifyKey_PanicRecovery(t *testing.T) {
	mock := newTPCBPanicMock()
	mock.panicOnRandomBytes = true
	svc := newTPCBTPMService(mock)

	result, err := svc.CertifyKey("0x81000001")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "panic in CertifyKey")
}

// ---------------------------------------------------------------------------
// TPM: GetPolicy -- edge case with multiple policies, searching for last
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_GetPolicy_FoundAmongMany(t *testing.T) {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	dir := t.TempDir()
	svc.SetDataDir(dir)

	policies := []PCRPolicy{
		{Name: "first-policy", Description: "first"},
		{Name: "second-policy", Description: "second"},
		{Name: "target-policy", Description: "target"},
	}
	require.NoError(t, svc.savePolicies(policies))

	policy, err := svc.GetPolicy("target-policy")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "target-policy", policy.Name)
	assert.Equal(t, "target", policy.Description)
}

func TestTPMPhoneCoverageBoost_GetPolicy_NotFoundAmongMany(t *testing.T) {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	dir := t.TempDir()
	svc.SetDataDir(dir)

	policies := []PCRPolicy{
		{Name: "alpha", Description: "a"},
		{Name: "beta", Description: "b"},
	}
	require.NoError(t, svc.savePolicies(policies))

	policy, err := svc.GetPolicy("nonexistent")
	assert.Nil(t, policy)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// TPM: GetCompositePolicy -- edge case with multiple policies
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_GetCompositePolicy_FoundAmongMany(t *testing.T) {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	dir := t.TempDir()
	svc.SetDataDir(dir)

	policies := []CompositePolicy{
		{Name: "comp-a"},
		{Name: "comp-b"},
		{Name: "comp-target"},
	}
	require.NoError(t, svc.saveCompositePolicies(policies))

	policy, err := svc.GetCompositePolicy("comp-target")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "comp-target", policy.Name)
}

func TestTPMPhoneCoverageBoost_GetCompositePolicy_NotFoundAmongMany(t *testing.T) {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	dir := t.TempDir()
	svc.SetDataDir(dir)

	policies := []CompositePolicy{
		{Name: "comp-x"},
		{Name: "comp-y"},
	}
	require.NoError(t, svc.saveCompositePolicies(policies))

	policy, err := svc.GetCompositePolicy("nonexistent")
	assert.Nil(t, policy)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// TPM: ListPolicies with valid saved data
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ListPolicies_WithSavedData(t *testing.T) {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	dir := t.TempDir()
	svc.SetDataDir(dir)

	policies := []PCRPolicy{
		{Name: "p1", Description: "first"},
		{Name: "p2", Description: "second"},
	}
	require.NoError(t, svc.savePolicies(policies))

	result, err := svc.ListPolicies()
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "p1", result[0].Name)
	assert.Equal(t, "p2", result[1].Name)
}

// ---------------------------------------------------------------------------
// TPM: ListPolicyAssignments with valid saved data
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ListPolicyAssignments_WithSavedData(t *testing.T) {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	dir := t.TempDir()
	svc.SetDataDir(dir)

	assignments := []PolicyAssignment{
		{PolicyName: "pa-1", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
		{PolicyName: "pa-2", KeyHandle: "0x81000002", AssignedAt: "2025-01-01T00:00:00Z"},
	}
	data, err := json.MarshalIndent(assignments, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, policyAssignmentsFile), data, 0600))

	result, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "pa-1", result[0].PolicyName)
	assert.Equal(t, "pa-2", result[1].PolicyName)
}

// ---------------------------------------------------------------------------
// TPM: ListCompositePolicies with valid saved data
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ListCompositePolicies_WithSavedData(t *testing.T) {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	dir := t.TempDir()
	svc.SetDataDir(dir)

	policies := []CompositePolicy{
		{Name: "cp-alpha"},
		{Name: "cp-beta"},
	}
	require.NoError(t, svc.saveCompositePolicies(policies))

	result, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "cp-alpha", result[0].Name)
}

// ---------------------------------------------------------------------------
// TPM: ListKeys always returns empty (current implementation)
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ListKeys_AlwaysEmpty(t *testing.T) {
	mock := defaultMockTPM()
	svc := newTPCBTPMService(mock)
	svc.SetDataDir(t.TempDir())

	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
	assert.IsType(t, []TPMKey{}, keys)
}

// ---------------------------------------------------------------------------
// TPM: ForceClearTPM -- nil request and sudo unavailable (basic validation)
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ForceClearTPM_NilRequest(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ForceClearTPM(nil)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil clear request")
}

// ---------------------------------------------------------------------------
// TPM: changeHierarchyAuth with isTPMAuthError branch
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ChangeHierarchyAuth_AuthError(t *testing.T) {
	mock := newTPCBPanicMock()
	mock.panicOnSetHierarchyAuth = false
	mock.setHierarchyAuthErr = &tpmAuthError{msg: "bad_auth: authorization failed"}
	svc := newTPCBTPMService(mock)

	// Set audit logger to verify the auth failure logging path
	logger := &mockAuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.ChangeOwnerAuth("wrong", "new")
	require.Error(t, err)
	// Verify audit log was called for auth failure
	assert.NotEmpty(t, logger.tpmOps)
}

// tpmAuthError implements error and contains "bad_auth" to trigger isTPMAuthError.
type tpmAuthError struct {
	msg string
}

func (e *tpmAuthError) Error() string {
	return e.msg
}

// ---------------------------------------------------------------------------
// TPM: changeHierarchyAuth non-auth error path with audit logging
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_ChangeHierarchyAuth_NonAuthError(t *testing.T) {
	mock := newTPCBPanicMock()
	mock.panicOnSetHierarchyAuth = false
	mock.setHierarchyAuthErr = ErrTPMNotAvailable // generic error
	svc := newTPCBTPMService(mock)

	logger := &mockAuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.ChangeEndorsementAuth("old", "new")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
	// Audit log should record the operation failure
	assert.NotEmpty(t, logger.tpmOps)
}

// ---------------------------------------------------------------------------
// Phone: SetAttestationPolicy -- device not found after config load
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneSetAttestationPolicy_DeviceNotFound(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tmpDir := tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Phone-A", Address: "AA:BB:CC:DD:EE:FF"},
		},
	})
	_ = tmpDir

	err := svc.SetAttestationPolicy("NonExistentPhone")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: SetAttestationPolicy -- no last attestation data
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneSetAttestationPolicy_NoLastAttestation(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Phone-B", Address: "11:22:33:44:55:66"},
		},
	})

	err := svc.SetAttestationPolicy("Phone-B")
	assert.ErrorIs(t, err, ErrPhonePolicyNotSet)
}

// ---------------------------------------------------------------------------
// Phone: ClearAttestationPolicy -- device not found after config load
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneClearAttestationPolicy_DeviceNotFound(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Phone-C", Address: "AA:AA:AA:AA:AA:AA"},
		},
	})

	err := svc.ClearAttestationPolicy("MissingPhone")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: GetAttestationPolicy -- device found with nil policy
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneGetAttestationPolicy_NilPolicy(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Phone-D", Address: "BB:BB:BB:BB:BB:BB"},
		},
	})

	policy, err := svc.GetAttestationPolicy("Phone-D")
	require.NoError(t, err)
	assert.Nil(t, policy)
}

// ---------------------------------------------------------------------------
// Phone: GetAttestationPolicy -- config load failure
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneGetAttestationPolicy_ConfigLoadFails(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	// Set HOME to a dir where no config file exists and no .xkey directory
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	// No .xkey/devices.yaml file => loadConfig returns error
	_, err := svc.GetAttestationPolicy("AnyDevice")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: GetDeviceStatus -- empty name
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneGetDeviceStatus_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	status, err := svc.GetDeviceStatus("")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: GetDeviceStatus -- non-empty name returns not connected
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneGetDeviceStatus_NotConnected(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	status, err := svc.GetDeviceStatus("SomeDevice")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPhoneNotConnected)
}

// ---------------------------------------------------------------------------
// Phone: Unpair -- device is default and other devices exist
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneUnpair_DefaultDeviceReassigned(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		DefaultDevice: "Phone-Remove",
		Devices: []phoneConfigDevice{
			{Name: "Phone-Remove", Address: "11:11:11:11:11:11"},
			{Name: "Phone-Keep", Address: "22:22:22:22:22:22"},
		},
	})

	err := svc.Unpair("Phone-Remove")
	require.NoError(t, err)

	// Verify the config was updated: default device should be reassigned
	cfg, cfgErr := svc.loadConfig()
	require.NoError(t, cfgErr)
	assert.Equal(t, "Phone-Keep", cfg.DefaultDevice)
	assert.Len(t, cfg.Devices, 1)
}

// ---------------------------------------------------------------------------
// Phone: Unpair -- device is default and no other devices remain
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneUnpair_DefaultDeviceCleared(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		DefaultDevice: "OnlyPhone",
		Devices: []phoneConfigDevice{
			{Name: "OnlyPhone", Address: "33:33:33:33:33:33"},
		},
	})

	err := svc.Unpair("OnlyPhone")
	require.NoError(t, err)

	cfg, cfgErr := svc.loadConfig()
	require.NoError(t, cfgErr)
	assert.Equal(t, "", cfg.DefaultDevice)
	assert.Empty(t, cfg.Devices)
}

// ---------------------------------------------------------------------------
// Phone: Unpair -- device not found
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneUnpair_DeviceNotFound(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "ExistingPhone", Address: "44:44:44:44:44:44"},
		},
	})

	err := svc.Unpair("NonExistentPhone")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: Unpair -- empty name
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneUnpair_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	err := svc.Unpair("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: ListDevices -- with multiple devices and connected device matching
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneListDevices_WithConnectedDevice(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	now := time.Now().UTC()
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Phone-1", Address: "A1:B1:C1:D1:E1:F1", PairedAt: now, IsBackend: true},
			{Name: "Phone-2", Address: "A2:B2:C2:D2:E2:F2", PairedAt: now},
		},
	})

	// Simulate connected state
	svc.connState.connected.Store(true)
	svc.connState.deviceName.Store("Phone-1")

	devices, err := svc.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 2)

	// Phone-1 should be marked as connected
	assert.True(t, devices[0].Connected)
	assert.True(t, devices[0].IsBackend)

	// Phone-2 should not be connected
	assert.False(t, devices[1].Connected)
	assert.False(t, devices[1].IsBackend)
}

// ---------------------------------------------------------------------------
// Phone: ListDevices -- no config file returns empty
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneListDevices_NoConfigFile(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)

	devices, err := svc.ListDevices()
	require.NoError(t, err)
	assert.Empty(t, devices)
}

// ---------------------------------------------------------------------------
// Phone: Connect -- empty name
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneConnect_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	err := svc.Connect("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: Connect -- device not found in config
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneConnect_DeviceNotFound(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "ExistingDevice", Address: "55:55:55:55:55:55"},
		},
	})

	err := svc.Connect("MissingDevice")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: Connect -- device missing noise keys
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneConnect_MissingNoiseKeys(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "NoKeysPhone",
				Address:              "66:66:66:66:66:66",
				LocalNoisePrivateKey: "",
				NoisePublicKey:       "",
			},
		},
	})

	err := svc.Connect("NoKeysPhone")
	assert.ErrorIs(t, err, ErrPhoneMissingKeys)
}

// ---------------------------------------------------------------------------
// Phone: Connect -- invalid base64 in local noise key
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneConnect_InvalidLocalKey(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "BadKeyPhone",
				Address:              "77:77:77:77:77:77",
				LocalNoisePrivateKey: "not-valid-base64!!!",
				NoisePublicKey:       "dGVzdA==", // valid base64
			},
		},
	})

	err := svc.Connect("BadKeyPhone")
	assert.ErrorIs(t, err, ErrPhoneMissingKeys)
}

// ---------------------------------------------------------------------------
// Phone: Connect -- invalid base64 in remote noise key
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneConnect_InvalidRemoteKey(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "BadRemotePhone",
				Address:              "88:88:88:88:88:88",
				LocalNoisePrivateKey: "dGVzdA==", // valid base64 but wrong length
				NoisePublicKey:       "not-valid-base64!!!",
			},
		},
	})

	err := svc.Connect("BadRemotePhone")
	assert.ErrorIs(t, err, ErrPhoneMissingKeys)
}

// ---------------------------------------------------------------------------
// Phone: Disconnect -- empty name
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneDisconnect_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	err := svc.Disconnect("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

// ---------------------------------------------------------------------------
// Phone: Scan -- invalid timeout values
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneScan_InvalidTimeout(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	t.Run("negative_timeout", func(t *testing.T) {
		_, err := svc.Scan(-1)
		assert.ErrorIs(t, err, ErrPhoneInvalidTimeout)
	})

	t.Run("zero_timeout", func(t *testing.T) {
		_, err := svc.Scan(0)
		assert.ErrorIs(t, err, ErrPhoneInvalidTimeout)
	})
}

// ---------------------------------------------------------------------------
// Phone: Pair -- empty address
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhonePair_EmptyAddress(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	device, err := svc.Pair("")
	assert.Nil(t, device)
	assert.ErrorIs(t, err, ErrPhonePairFailed)
}

// ---------------------------------------------------------------------------
// Phone: buildAttestationTrustPool -- nil trust store fallback
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_BuildAttestationTrustPool_NilTrustStore(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	// trustStore is nil by default

	pool, err := svc.buildAttestationTrustPool(nil)
	require.NoError(t, err)
	require.NotNil(t, pool)
}

// ---------------------------------------------------------------------------
// Phone: saveAttestationResult -- device not found in config
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_SaveAttestationResult_DeviceNotInConfig(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "OtherDevice", Address: "99:99:99:99:99:99"},
		},
	})

	cfg, err := svc.loadConfig()
	require.NoError(t, err)

	// Create a device that is NOT in the config
	missingDevice := &phoneConfigDevice{
		Name:    "MissingDevice",
		Address: "AA:AA:AA:AA:AA:AA",
	}

	result := &AttestationResult{
		Verified:      true,
		SecurityLevel: "tee",
		BootState:     "verified",
		AttestTime:    time.Now().UTC(),
	}

	// This should not panic -- the device won't be found in cfg.Devices
	// so no update happens, but saveConfig is still called.
	svc.saveAttestationResult(cfg, missingDevice, result)

	// Verify the existing device in config is not modified
	reloaded, err := svc.loadConfig()
	require.NoError(t, err)
	assert.Len(t, reloaded.Devices, 1)
	assert.Equal(t, "OtherDevice", reloaded.Devices[0].Name)
}

// ---------------------------------------------------------------------------
// Phone: IsConnected and ConnectedDeviceName
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneIsConnected(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	assert.False(t, svc.IsConnected())
	assert.Equal(t, "", svc.ConnectedDeviceName())

	svc.connState.connected.Store(true)
	svc.connState.deviceName.Store("TestPhone")

	assert.True(t, svc.IsConnected())
	assert.Equal(t, "TestPhone", svc.ConnectedDeviceName())
}

// ---------------------------------------------------------------------------
// Phone: SetEventEmitter and SetStatusChangeFunc
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneSetEventEmitter(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	var emitted bool
	svc.SetEventEmitter(func(_ events.Event) {
		emitted = true
	})

	// The emitter is set but we can't easily trigger it without BLE operations.
	// Verify via setConnected which uses the emitter.
	svc.setConnected("TestDevice")
	assert.True(t, emitted)
}

func TestTPMPhoneCoverageBoost_PhoneSetStatusChangeFunc(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())

	var statusChanged bool
	var reportedConnected bool
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		statusChanged = true
		reportedConnected = connected
	})

	svc.setConnected("TestDevice")
	assert.True(t, statusChanged)
	assert.True(t, reportedConnected)
}

// ---------------------------------------------------------------------------
// Phone: emitAttestationEvent -- nil emitter (no-op)
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_EmitAttestationEvent_NilEmitter(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	// eventEmitter is nil -- should be a no-op, no panic
	svc.emitAttestationEvent("Device", true, "details")
}

// ---------------------------------------------------------------------------
// Phone: emitPolicyViolationEvent -- nil emitter (no-op)
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_EmitPolicyViolationEvent_NilEmitter(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	// eventEmitter is nil -- should be a no-op, no panic
	svc.emitPolicyViolationEvent("Device", map[string]string{"key": "val"}, "msg")
}

// ---------------------------------------------------------------------------
// Phone: SetTrustStore
// ---------------------------------------------------------------------------

func TestTPMPhoneCoverageBoost_PhoneSetTrustStore(t *testing.T) {
	svc := NewPhoneService()
	svc.SetContext(context.Background())
	// Just verify SetTrustStore doesn't panic with nil
	svc.SetTrustStore(nil)
	assert.Nil(t, svc.trustStore)
}

// ---------------------------------------------------------------------------
// Helper: tpcbSetupPhoneConfig creates a temp HOME dir with a devices.yaml.
// ---------------------------------------------------------------------------

func tpcbSetupPhoneConfig(t *testing.T, cfg *phoneConfig) string {
	t.Helper()
	tmpDir := t.TempDir()
	xkeyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(xkeyDir, 0700))
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(xkeyDir, devicesConfigFileName), data, 0600))
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", tmpDir)
	return tmpDir
}
