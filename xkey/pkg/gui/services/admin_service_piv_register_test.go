package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
)

type pivRegistration struct {
	backendID string
	category  string
}

// recordPIVRegistrations installs a PIV register hook on svc that records
// every call.
func recordPIVRegistrations(svc *AdminService) *[]pivRegistration {
	calls := &[]pivRegistration{}
	svc.SetPIVRegisterFunc(func(backendID, category string) {
		*calls = append(*calls, pivRegistration{backendID: backendID, category: category})
	})
	return calls
}

// TestAdminService_ConfigureBackend_PIVCapableWithoutRestart verifies that a
// backend configured at runtime is PIV-capable, the same as when it is loaded
// from config at the next start, and that the PIV register hook fires for it
// so it can hold PIV certificates without a restart.
func TestAdminService_ConfigureBackend_PIVCapableWithoutRestart(t *testing.T) {
	tests := []struct {
		backendType string
		params      map[string]string
		category    string
	}{
		{"tpm2", map[string]string{"id": "tpm-lab", "device": "/dev/tpmrm0"}, "tpm2"},
		{"pkcs11", map[string]string{"id": "hsm-lab", "library_path": "/usr/lib/softhsm/libsofthsm2.so"}, "pkcs11"},
	}
	for _, tt := range tests {
		t.Run(tt.backendType, func(t *testing.T) {
			isolateHome(t)
			svc := NewAdminService()
			registry := newMockFullRegistry()
			svc.SetBackendRegistry(registry)
			calls := recordPIVRegistrations(svc)

			require.NoError(t, svc.ConfigureBackend(tt.backendType, tt.params))

			require.Len(t, registry.registered, 1)
			assert.True(t, registry.registered[0].HasCapability(backendregistry.CapPIV),
				"a configured %s backend must be PIV-capable", tt.backendType)
			assert.Equal(t, []pivRegistration{{backendID: tt.params["id"], category: tt.category}}, *calls)
		})
	}
}

// TestAdminService_ConfigureBackend_InvalidSkipsPIVRegistration verifies that
// a rejected configuration never reaches the PIV register hook.
func TestAdminService_ConfigureBackend_InvalidSkipsPIVRegistration(t *testing.T) {
	isolateHome(t)
	svc := NewAdminService()
	svc.SetBackendRegistry(newMockFullRegistry())
	calls := recordPIVRegistrations(svc)

	require.ErrorIs(t, svc.ConfigureBackend("tpm2", map[string]string{}), ErrAdminMissingField)
	require.ErrorIs(t, svc.ConfigureBackend("floppy", map[string]string{"id": "x"}), ErrAdminInvalidBackendType)

	assert.Empty(t, *calls)
}
