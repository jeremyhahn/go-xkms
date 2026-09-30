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

//go:build tpm_simulator

package compose

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
)

// newSimulatorBackend opens a TPM2 key backend over the simulator.
func newSimulatorBackend(t *testing.T) *tpm2backend.Backend {
	t.Helper()
	backend, err := tpm2backend.NewBackend(&tpm2backend.Config{UseSimulator: true, KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, backend.Close()) })
	return backend
}

// TestBuild_TPMBackendComposesTheTPMPolicyService proves a host that supplies
// a TPM2 backend gets the TPM policy service, installed as the backend's
// scope provider and answering through the XKMSService once wired.
func TestBuild_TPMBackendComposesTheTPMPolicyService(t *testing.T) {
	svc := hostdeps.NewService(t)
	backend := newSimulatorBackend(t)
	deps := fullDeps(t, svc)
	deps.TPMBackend = backend

	st, err := Build(context.Background(), deps)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	require.Empty(t, st.Disabled, "every dependency, the TPM included, is supplied")
	require.NotNil(t, st.TPMPolicies)
	assert.True(t, backend.TenantBoundSealing(), "the service is the backend's scope provider")

	st.Wire(svc)
	assert.Same(t, st.TPMPolicies, svc.TPMPolicyService())
	created, err := svc.TPMPolicyCreate(platformCtx(), &transport.TPMPolicyCreateRequest{Name: "boot", Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{23})}})
	require.NoError(t, err)
	assert.True(t, created.Approved)
}

// TestBuildTPMPolicyService_StorageFailure proves a registry or key store
// that cannot open fails the build with a *FeatureBuildError.
func TestBuildTPMPolicyService_StorageFailure(t *testing.T) {
	_, err := BuildTPMPolicyService(TPMPolicyParams{Backend: newSimulatorBackend(t), Storage: failingStorage})
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureTPMPolicies, buildErr.Feature)
	assert.ErrorIs(t, err, errStorageDown)
}
