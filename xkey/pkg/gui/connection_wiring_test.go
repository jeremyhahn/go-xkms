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
	"testing"

	"github.com/stretchr/testify/assert"

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
		custodianService:   services.NewCustodianService(),
		tenantService:      services.NewTenantService(),
		certificateService: services.NewCertificateService(),
		tpmPolicyService:   services.NewTPMPolicyService(),
		staticPWService:    services.NewStaticPasswordService(nil),
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
