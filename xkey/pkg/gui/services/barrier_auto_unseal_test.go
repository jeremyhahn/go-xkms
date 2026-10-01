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

package services

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/localtpm"
)

// These tests cover BarrierAutoUnsealService without a TPM; the TPM-enforced
// paths run against the simulator in tpm_policy_simulator_test.go.

func TestBarrierAutoUnseal_WithoutLocalServiceIsUnavailable(t *testing.T) {
	svc := NewBarrierAutoUnsealService(WithBarrierAutoUnsealBarrier(NewBarrierService(t.TempDir(), slog.Default())))

	ok, err := svc.TryAutoUnseal(context.Background(), string(xkms.StrategyPassphrase))
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealNoPolicyService)

	status, err := svc.GetAutoUnsealStatus()
	require.NoError(t, err)
	assert.False(t, status.Available)
	assert.NotEmpty(t, status.Reason)

	assert.ErrorIs(t, svc.EnableAutoUnseal("boot", "password"), ErrBarrierAutoUnsealNoPolicyService)
	assert.ErrorIs(t, svc.DisableAutoUnseal(), ErrBarrierAutoUnsealNoPolicyService)
}

func TestBarrierAutoUnseal_EnableValidatesItsArguments(t *testing.T) {
	svc := NewBarrierAutoUnsealService(WithBarrierAutoUnsealLocal(&localtpm.Policies{}))

	assert.ErrorIs(t, svc.EnableAutoUnseal("", "password"), ErrBarrierAutoUnsealEmptyPolicyName)
	assert.ErrorIs(t, svc.EnableAutoUnseal(xkms.TPMPolicyPlatform, "password"), ErrBarrierAutoUnsealBuiltinPolicy)
	assert.ErrorIs(t, svc.EnableAutoUnseal("boot", ""), ErrBarrierAutoUnsealCredentialRequired)
}

func TestBarrierAutoUnseal_TryWithoutBarrierFails(t *testing.T) {
	svc := NewBarrierAutoUnsealService(WithBarrierAutoUnsealLocal(&localtpm.Policies{}))
	ok, err := svc.TryAutoUnseal(context.Background(), string(xkms.StrategyPassphrase))
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealNoBarrier)
}

func TestBarrierAutoUnseal_SettersReplaceDependencies(t *testing.T) {
	svc := NewBarrierAutoUnsealService()
	local := &localtpm.Policies{}
	svc.SetLocal(local)
	svc.SetBarrier(NewBarrierService(t.TempDir(), slog.Default()))
	got, err := svc.requireLocal()
	require.NoError(t, err)
	assert.Same(t, local, got)
	assert.NotNil(t, svc.barrier.Load())

	svc.SetLocal(nil)
	_, err = svc.requireLocal()
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealNoPolicyService)
}

func TestSetupWizard_EnableBarrierAutoUnsealNeedsTheLocalService(t *testing.T) {
	wizard := &SetupWizardService{}
	assert.ErrorIs(t, wizard.enableBarrierAutoUnseal("password", ""), ErrBarrierAutoUnsealNoPolicyService)

	wizard.SetTPMPolicyService(NewTPMPolicyService())
	wizard.SetBarrierAutoUnsealService(NewBarrierAutoUnsealService())
	assert.ErrorIs(t, wizard.enableBarrierAutoUnseal("password", ""), ErrBarrierAutoUnsealNoPolicyService,
		"without a local TPM there is nothing to seal the password under")
}
