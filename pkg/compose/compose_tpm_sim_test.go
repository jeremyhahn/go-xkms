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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	tpmstore "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// newSimulatorBackend opens a TPM2 key backend over the simulator.
func newSimulatorBackend(t *testing.T) *tpm2backend.Backend {
	t.Helper()
	backend, err := tpm2backend.NewBackend(&tpm2backend.Config{UseSimulator: true, Keys: tpmblobtest.New(t)})
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

// TestBuildTPMPolicyService_TenantKeysDatabaseUnavailable proves a DAO
// factory that serves the registry's database but not the tenant key blobs'
// fails the build with a *FeatureBuildError naming the blob database.
func TestBuildTPMPolicyService_TenantKeysDatabaseUnavailable(t *testing.T) {
	kv := qrdbsdk.NewMemoryKVStore()
	registryOnly := qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{
		KVStoreProvider: func(uint64) qrdbsdk.KVStore { return kv },
		PartitionedProvider: func(database string, _ uint64) qrdbsdk.KVStore {
			if database == tpmpolicy.DatabaseName {
				return kv
			}
			return nil
		},
	})
	_, err := BuildTPMPolicyService(TPMPolicyParams{
		Backend: newSimulatorBackend(t),
		DAOs:    registryOnly,
	})
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureTPMPolicies, buildErr.Feature)
	var unavailable *dao.DatabaseUnavailableError
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, tpmstore.DatabaseName, unavailable.Database)
}

// TestBuildTPMPolicyService_RegistryDatabaseUnavailable proves a DAO factory
// that does not serve the registry's database fails the build with a
// *FeatureBuildError naming the database.
func TestBuildTPMPolicyService_RegistryDatabaseUnavailable(t *testing.T) {
	_, err := BuildTPMPolicyService(TPMPolicyParams{
		Backend: newSimulatorBackend(t),
		DAOs:    dao.NewStoreFactory(nil),
	})
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureTPMPolicies, buildErr.Feature)
	var unavailable *dao.DatabaseUnavailableError
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, tpmpolicy.DatabaseName, unavailable.Database)
}
