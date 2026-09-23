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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// recordingPolicyHandler captures what LoginSO hands to the verified-policy
// handler, and how often. err, when set, is returned by every call, as
// applyVerifiedEnterprisePolicy does when the section's own Require*
// preconditions are not met by the host.
type recordingPolicyHandler struct {
	calls  int
	policy *config.PolicySection
	err    error
}

func (r *recordingPolicyHandler) handle(p *config.PolicySection) error {
	r.calls++
	r.policy = p
	return r.err
}

func TestLoginSO_Enterprise_ValidHMAC_HandsVerifiedPolicyToHandler(t *testing.T) {
	tmpDir := t.TempDir()
	soPIN := "enterprise-so-pin-12345"

	policy := loadedPolicy(t)
	require.NoError(t, config.WritePolicyHMAC(policy, soPIN, config.PolicyHMACPath(tmpDir)))

	svc := newTestAuthService(&authMockPINBackend{strategy: qrdbsdk.PINStrategySoftware}, tmpDir)
	rec := &recordingPolicyHandler{}
	svc.SetVerifiedPolicyHandler(rec.handle)

	result := svc.LoginSO(soPIN)

	require.True(t, result.PolicyVerified)
	require.Equal(t, 1, rec.calls, "the handler runs exactly once per verified login")
	require.NotNil(t, rec.policy)
	assert.Equal(t, *policy, *rec.policy, "the handler receives the section the HMAC verified")
}

func TestLoginSO_Enterprise_TamperedHMAC_DoesNotCallHandler(t *testing.T) {
	tmpDir := t.TempDir()
	soPIN := "enterprise-so-pin-12345"

	tampered := loadedPolicy(t)
	tampered.MinPINLength = 99
	require.NoError(t, config.WritePolicyHMAC(tampered, soPIN, config.PolicyHMACPath(tmpDir)))

	svc := newTestAuthService(&authMockPINBackend{strategy: qrdbsdk.PINStrategySoftware}, tmpDir)
	rec := &recordingPolicyHandler{}
	svc.SetVerifiedPolicyHandler(rec.handle)

	result := svc.LoginSO(soPIN)

	require.True(t, result.TamperDetected)
	assert.Equal(t, 0, rec.calls, "a section that fails verification is never handed out")
	assert.Nil(t, rec.policy)
}

func TestLoginSO_Enterprise_WrongSOPIN_DoesNotCallHandler(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, config.WritePolicyHMAC(loadedPolicy(t), "right-pin", config.PolicyHMACPath(tmpDir)))

	backend := &authMockPINBackend{
		strategy:    qrdbsdk.PINStrategySoftware,
		verifySOErr: errors.New("invalid SO PIN"),
	}
	svc := newTestAuthService(backend, tmpDir)
	rec := &recordingPolicyHandler{}
	svc.SetVerifiedPolicyHandler(rec.handle)

	result := svc.LoginSO("wrong-pin")

	require.False(t, result.Success)
	assert.Equal(t, 0, rec.calls, "a login that fails at the PIN never reaches policy verification")
}

func TestLoginSO_PersonalMode_DoesNotCallHandler(t *testing.T) {
	svc := newTestAuthService(&authMockPINBackend{strategy: qrdbsdk.PINStrategySoftware}, t.TempDir())
	rec := &recordingPolicyHandler{}
	svc.SetVerifiedPolicyHandler(rec.handle)

	result := svc.LoginSO("any-pin")

	require.True(t, result.Success)
	require.False(t, svc.IsEnterpriseMode())
	assert.Equal(t, 0, rec.calls, "personal mode has no enterprise policy to hand out")
}

// TestLoginSO_Enterprise_HandlerRefusal_StillSucceeds proves that an SO can
// still log in when the verified policy fails its own Require* startup
// preconditions: refusing SO login here would lock out the one person who
// could fix the deployment (see PolicyPreconditionError).
func TestLoginSO_Enterprise_HandlerRefusal_StillSucceeds(t *testing.T) {
	tmpDir := t.TempDir()
	soPIN := "enterprise-so-pin-12345"

	policy := loadedPolicy(t)
	require.NoError(t, config.WritePolicyHMAC(policy, soPIN, config.PolicyHMACPath(tmpDir)))

	svc := newTestAuthService(&authMockPINBackend{strategy: qrdbsdk.PINStrategySoftware}, tmpDir)
	rec := &recordingPolicyHandler{err: errors.New("policy: unmet startup preconditions: require_tpm")}
	svc.SetVerifiedPolicyHandler(rec.handle)

	result := svc.LoginSO(soPIN)

	require.True(t, result.Success, "the SO must still be able to log in and fix the deployment")
	assert.Equal(t, 1, rec.calls)
	assert.True(t, result.PolicyVerified, "the HMAC did verify; only applying the section was refused")
	assert.False(t, result.TamperDetected)
	assert.Equal(t, rec.err.Error(), result.Error)
}

func TestSetVerifiedPolicyHandler_NilClearsTheHandler(t *testing.T) {
	tmpDir := t.TempDir()
	soPIN := "enterprise-so-pin-12345"
	require.NoError(t, config.WritePolicyHMAC(loadedPolicy(t), soPIN, config.PolicyHMACPath(tmpDir)))

	svc := newTestAuthService(&authMockPINBackend{strategy: qrdbsdk.PINStrategySoftware}, tmpDir)
	rec := &recordingPolicyHandler{}
	svc.SetVerifiedPolicyHandler(rec.handle)
	svc.SetVerifiedPolicyHandler(nil)

	result := svc.LoginSO(soPIN)

	require.True(t, result.PolicyVerified)
	assert.Equal(t, 0, rec.calls, "a cleared handler is not called")
}
