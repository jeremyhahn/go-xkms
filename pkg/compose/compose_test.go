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

package compose

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	sshrecords "github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	tpmstore "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// errStorageDown is the failure failingStorage injects.
var errStorageDown = errors.New("storage down")

// memoryStorage returns a StorageFactory handing out one in-memory backend
// per name, reused across calls, so a second Build over it sees what the
// first persisted.
func memoryStorage(t *testing.T) StorageFactory {
	t.Helper()
	backends := map[string]storage.Backend{}
	return func(name string) (storage.Backend, error) {
		if b, ok := backends[name]; ok {
			return b, nil
		}
		b, err := storage.NewMemoryBackend()
		require.NoError(t, err)
		backends[name] = b
		return b, nil
	}
}

// failingStorage refuses to open any store.
func failingStorage(string) (storage.Backend, error) { return nil, errStorageDown }

// platformCtx is a system-tenant caller: the platform-scoped subsystems
// (platform store, barrier) refuse every other caller.
func platformCtx() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "admin",
		TenantID: qrdbsdk.SystemTenantID,
		Roles:    []string{"admin"},
	})
}

// fullDeps supplies every dependency Build knows.
func fullDeps(t *testing.T, svc *xkms.XKMSService) Deps {
	t.Helper()
	leases, _ := barriertest.NewStandaloneCoordinator(t)
	return Deps{
		Service:            svc,
		Storage:            memoryStorage(t),
		DAOs:               testutil.NewMemoryDAOFactory(),
		BarrierRegistry:    hostdeps.NewBarrierRegistry(t),
		TenantStores:       testutil.NewTenantStores(),
		PIN:                hostdeps.NewPINBackend(t, "so-pin-123456", "user-pin-654321"),
		PlatformSealer:     &PlatformSealer{Strategy: "passphrase", Sealer: hostdeps.NewSealer(t)},
		CredentialStrategy: "barrier",
		CA:                 hostdeps.NewCAConfig("Compose Test Root"),
		Leases:             leases,
	}
}

func TestBuild_RequiresService(t *testing.T) {
	st, err := Build(context.Background(), Deps{})
	assert.Nil(t, st)
	var nilSvc *NilServiceError
	require.ErrorAs(t, err, &nilSvc)
	assert.Contains(t, err.Error(), "XKMSService")
}

// TestBuild_DefaultCredentialStrategyIsManual mirrors xkmsd's default.
func TestBuild_DefaultCredentialStrategyIsManual(t *testing.T) {
	svc := hostdeps.NewService(t)
	st, err := Build(context.Background(), Deps{Service: svc})
	require.NoError(t, err)
	require.NotNil(t, st.Credentials)
	assert.Equal(t, credentialspkg.StrategyManual, st.Credentials.Strategy())
}

func TestBuild_PlatformCredentialStrategyWithoutSealerIsOff(t *testing.T) {
	svc := hostdeps.NewService(t)
	st, err := Build(context.Background(), Deps{Service: svc, Storage: memoryStorage(t), CredentialStrategy: "tpm2"})
	require.NoError(t, err)
	assert.Nil(t, st.Credentials)
	assert.Contains(t, reasonsFor(st, FeatureCredentials), "platform store")
}

func TestBuild_UnknownCredentialStrategyIsABuildError(t *testing.T) {
	svc := hostdeps.NewService(t)
	st, err := Build(context.Background(), Deps{Service: svc, CredentialStrategy: "bogus"})
	require.NoError(t, err)
	assert.Nil(t, st.Credentials)
	var buildErr *FeatureBuildError
	require.True(t, anyAs(st.Disabled, &buildErr))
	assert.Equal(t, FeatureCredentials, buildErr.Feature)
	assert.ErrorIs(t, buildErr, credentialspkg.ErrInvalidStrategy)
}

// TestBuild_StorageFailureIsABuildErrorPerFeature proves a storage that
// cannot open fails each store-backed feature with a *FeatureBuildError and
// never aborts the composition.
func TestBuild_StorageFailureIsABuildErrorPerFeature(t *testing.T) {
	svc := hostdeps.NewService(t)
	deps := fullDeps(t, svc)
	deps.Storage = failingStorage

	st, err := Build(context.Background(), deps)
	require.NoError(t, err)

	failed := map[Feature]bool{}
	for _, reason := range st.Disabled {
		var buildErr *FeatureBuildError
		if errors.As(reason, &buildErr) {
			failed[buildErr.Feature] = true
			assert.ErrorIs(t, reason, errStorageDown)
		}
	}
	for _, f := range []Feature{FeaturePlatformStore, FeatureCA, FeatureInvite} {
		assert.True(t, failed[f], "%s must fail on storage", f)
	}
	// Features with no storage of their own still compose.
	assert.NotNil(t, st.Credentials)
	assert.NotNil(t, st.PasswordManager, "password records persist through DAOs, not storage")
	assert.NotNil(t, st.KeyVersions, "key versions persist through DAOs, not storage")
	assert.NotNil(t, st.KeyPolicies, "key policies persist through DAOs, not storage")
	assert.NotNil(t, st.SSH, "SSH records persist through DAOs, not storage")
}

// TestBuildCA_ReloadsPersistedRoot proves a second CA over the same DAO
// factory and storage loads the persisted root instead of minting a new one
// (go-xkms#793).
func TestBuildCA_ReloadsPersistedRoot(t *testing.T) {
	svc := hostdeps.NewService(t)
	params := CAParams{
		Config:          hostdeps.NewCAConfig("Reload Root"),
		DAOs:            testutil.NewMemoryDAOFactory(),
		Storage:         memoryStorage(t),
		BackendForStore: backendForStore(svc),
	}
	first, err := BuildCA(context.Background(), params)
	require.NoError(t, err)
	firstCert, err := first.CACertificate()
	require.NoError(t, err)

	second, err := BuildCA(context.Background(), params)
	require.NoError(t, err)
	secondCert, err := second.CACertificate()
	require.NoError(t, err)
	assert.Equal(t, firstCert.Raw, secondCert.Raw)
}

// TestBuildCA_StoresCertificatesInTheCADatabase proves the CA keeps its
// certificates as DAO entities in certstore.DatabaseName: a certificate store
// opened over the same factory finds the root the CA minted.
func TestBuildCA_StoresCertificatesInTheCADatabase(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	trustedCA, err := BuildCA(context.Background(), CAParams{
		Config:          hostdeps.NewCAConfig("DAO Root"),
		DAOs:            daos,
		Storage:         memoryStorage(t),
		BackendForStore: backendForStore(hostdeps.NewService(t)),
	})
	require.NoError(t, err)
	root, err := trustedCA.CACertificate()
	require.NoError(t, err)

	store, err := certstore.New(&certstore.Config{DAOs: daos})
	require.NoError(t, err)
	stored, err := store.GetCertificate(certstore.CertificateKey(root))
	require.NoError(t, err)
	assert.Equal(t, root.Raw, stored.Raw)
}

func TestBuildCA_InvalidInput(t *testing.T) {
	svc := hostdeps.NewService(t)
	valid := CAParams{
		Config:          hostdeps.NewCAConfig("Root"),
		DAOs:            testutil.NewMemoryDAOFactory(),
		Storage:         memoryStorage(t),
		BackendForStore: backendForStore(svc),
	}

	t.Run("nil dependencies", func(t *testing.T) {
		for name, p := range map[string]CAParams{
			"config":  {DAOs: valid.DAOs, Storage: valid.Storage, BackendForStore: valid.BackendForStore},
			"daos":    {Config: valid.Config, Storage: valid.Storage, BackendForStore: valid.BackendForStore},
			"storage": {Config: valid.Config, DAOs: valid.DAOs, BackendForStore: valid.BackendForStore},
			"backend": {Config: valid.Config, DAOs: valid.DAOs, Storage: valid.Storage},
		} {
			_, err := BuildCA(context.Background(), p)
			var nilDep *NilDependencyError
			assert.ErrorAs(t, err, &nilDep, name)
		}
	})

	t.Run("invalid configuration", func(t *testing.T) {
		p := valid
		cfg := hostdeps.NewCAConfig("Root")
		cfg.Identity[0].Valid = 0
		p.Config = cfg
		_, err := BuildCA(context.Background(), p)
		var opErr *CAOperationError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "validate configuration", opErr.Operation)
	})

	t.Run("missing keystore", func(t *testing.T) {
		p := valid
		p.BackendForStore = func(string, types.StoreType) (xkms.Backend, error) { return nil, errStorageDown }
		_, err := BuildCA(context.Background(), p)
		var opErr *CAOperationError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "resolve keystore", opErr.Operation)
	})

	t.Run("CA database not served", func(t *testing.T) {
		p := valid
		p.DAOs = dao.NewStoreFactory(nil)
		_, err := BuildCA(context.Background(), p)
		var opErr *CAOperationError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "create certificate store", opErr.Operation)
		var unavailable *dao.DatabaseUnavailableError
		require.ErrorAs(t, err, &unavailable)
		assert.Equal(t, certstore.DatabaseName, unavailable.Database)
	})

	t.Run("storage failure", func(t *testing.T) {
		p := valid
		p.Storage = failingStorage
		_, err := BuildCA(context.Background(), p)
		var opErr *CAOperationError
		require.ErrorAs(t, err, &opErr)
		assert.ErrorIs(t, err, errStorageDown)
	})

	t.Run("adopt hook failure", func(t *testing.T) {
		p := valid
		p.DAOs = testutil.NewMemoryDAOFactory()
		p.Storage = memoryStorage(t)
		p.AdoptCertStore = func(_ certstore.CertStore) error { return errStorageDown }
		_, err := BuildCA(context.Background(), p)
		var opErr *CAOperationError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "adopt staged certificates", opErr.Operation)
	})
}

// TestBuildSSHClient_ResolvesBackendKeysThroughService proves an SSH key
// naming a backend is minted in that XKMSService backend, and an unknown
// backend is refused rather than silently falling back to a software key.
func TestBuildSSHClient_ResolvesBackendKeysThroughService(t *testing.T) {
	svc := hostdeps.NewService(t)
	client, err := BuildSSHClient(testutil.NewMemoryDAOFactory(), svc.LookupBackend, svc)
	require.NoError(t, err)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "acme"})
	req := sdkssh.GenerateRequest{Scope: "user", Owner: "alice", Name: "hw", Algorithm: "ecdsa-p256", Backend: hostdeps.BackendName}
	key, err := client.Keys().Generate(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, key.BackendKeyID, "the key must live in the named backend")

	req.Name, req.Backend = "missing", "nope"
	_, err = client.Keys().Generate(ctx, req)
	assert.Error(t, err)
}

func TestBuilders_RejectNilDependencies(t *testing.T) {
	var nilDep *NilDependencyError

	_, err := BuildPasswordStore(nil)
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildTenantPasswordManager(nil, nil, "")
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildTenantPasswordManager(testutil.NewTenantStores(), nil, "")
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildPlatformStore(nil, nil, PlatformSealer{})
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildPlatformStore(nil, memoryStorage(t), PlatformSealer{})
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildSSHClient(nil, nil, nil)
	assert.ErrorAs(t, err, &nilDep)
	assert.Contains(t, err.Error(), "DAO factory")
	_, err = BuildSSHClient(testutil.NewMemoryDAOFactory(), nil, nil)
	assert.ErrorAs(t, err, &nilDep)
	assert.Contains(t, err.Error(), "backend lookup")
	_, err = BuildTPMPolicyService(TPMPolicyParams{DAOs: testutil.NewMemoryDAOFactory()})
	assert.ErrorAs(t, err, &nilDep)
	assert.Contains(t, err.Error(), "TPM2 backend")
	_, err = BuildTPMPolicyService(TPMPolicyParams{Backend: &tpm2backend.Backend{}})
	assert.ErrorAs(t, err, &nilDep)
	assert.Contains(t, err.Error(), "DAO factory")
}

// TestDatabases_FollowTheSuppliedDependencies proves every root opens the
// key-version, SSH and password databases, which need nothing else, and is
// asked to open another feature's database only when it supplies that
// feature's other dependency — the CA's for a CA configuration, the TPM policy
// registry's for a TPM2 backend.
func TestDatabases_FollowTheSuppliedDependencies(t *testing.T) {
	always := []string{keyversion.DatabaseName, keypolicy.DatabaseName, sshrecords.DatabaseName, staticpw.DatabaseName, truststore.DatabaseName, appraisal.DatabaseName}
	assert.Equal(t, always, Databases(Deps{}))
	assert.Equal(t, append(always, certstore.DatabaseName), Databases(Deps{CA: hostdeps.NewCAConfig("Root")}))
	assert.Equal(t, append(always, tpmpolicy.DatabaseName, tpmstore.DatabaseName), Databases(Deps{TPMBackend: &tpm2backend.Backend{}}))
	assert.Equal(t, append(always, certstore.DatabaseName, tpmpolicy.DatabaseName, tpmstore.DatabaseName),
		Databases(Deps{CA: hostdeps.NewCAConfig("Root"), TPMBackend: &tpm2backend.Backend{}}))
}

// TestBuild_CANeedsTheDAOFactory proves a root that supplies a CA
// configuration but no DAO factory leaves the CA off, saying why.
func TestBuild_CANeedsTheDAOFactory(t *testing.T) {
	deps := fullDeps(t, hostdeps.NewService(t))
	deps.DAOs = nil

	st, err := Build(context.Background(), deps)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	assert.Nil(t, st.CA)
	assert.Contains(t, reasonsFor(st, FeatureCA), "DAO factory")
}

// TestBuild_TPMPoliciesNeedTheDAOFactory proves a root that supplies a TPM2
// backend but no DAO factory leaves the TPM policy service off, saying why.
func TestBuild_TPMPoliciesNeedTheDAOFactory(t *testing.T) {
	deps := fullDeps(t, hostdeps.NewService(t))
	deps.TPMBackend = &tpm2backend.Backend{}
	deps.DAOs = nil

	st, err := Build(context.Background(), deps)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	assert.Nil(t, st.TPMPolicies)
	assert.Contains(t, reasonsFor(st, FeatureTPMPolicies), "DAO factory")
}

func TestBuilders_StorageFailureIsFeatureBuildError(t *testing.T) {
	var buildErr *FeatureBuildError

	_, err := BuildPasswordStore(dao.NewStoreFactory(nil))
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeaturePasswords, buildErr.Feature)
	var unavailable *dao.DatabaseUnavailableError
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, staticpw.DatabaseName, unavailable.Database)

	_, err = BuildPlatformStore(nil, failingStorage, PlatformSealer{Strategy: "passphrase", Sealer: hostdeps.NewSealer(t)})
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeaturePlatformStore, buildErr.Feature)

	// A backend whose TPM is not a pkg/tpm2 TPM cannot run the TPM policy
	// service; it is refused before any storage is opened.
	_, err = BuildTPMPolicyService(TPMPolicyParams{Backend: &tpm2backend.Backend{}, DAOs: testutil.NewMemoryDAOFactory()})
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureTPMPolicies, buildErr.Feature)
	assert.ErrorIs(t, err, ErrUnsupportedTPM)
	assert.Contains(t, err.Error(), "tpm-policies failed to build")
}

func TestErrorMessages(t *testing.T) {
	assert.Equal(t, "compose: ca is off: no CA configuration was supplied",
		(&FeatureDisabledError{Feature: FeatureCA, Missing: "CA configuration"}).Error())
	assert.Equal(t, "compose: building ssh requires a non-nil storage factory",
		(&NilDependencyError{Feature: FeatureSSH, Dependency: "storage factory"}).Error())
	assert.Equal(t, "compose: CA configuration has no identities", (&CANoIdentitiesError{}).Error())
	assert.Equal(t, "compose: CA load failed: storage down",
		(&CAOperationError{Operation: "load", Err: errStorageDown}).Error())
}

// reasonsFor joins the recorded reasons for feature.
func reasonsFor(st *Stores, feature Feature) string {
	var out string
	for _, reason := range st.Disabled {
		var disabled *FeatureDisabledError
		if errors.As(reason, &disabled) && disabled.Feature == feature {
			out += reason.Error()
		}
	}
	return out
}

// anyAs reports whether any error in errs matches target.
func anyAs[T error](errs []error, target *T) bool {
	for _, err := range errs {
		if errors.As(err, target) {
			return true
		}
	}
	return false
}

// TestTPM2Backend_NoneRegistered proves a service without a TPM2 backend
// yields none, leaving the TPM policy service off in a host composition.
func TestTPM2Backend_NoneRegistered(t *testing.T) {
	assert.Nil(t, TPM2Backend(hostdeps.NewService(t)))
}

// TestBuildKeyVersionStore proves the store is built over the factory serving
// its database, and that a missing factory and a factory without the database
// are typed errors naming the feature.
func TestBuildKeyVersionStore(t *testing.T) {
	store, err := BuildKeyVersionStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	require.NotNil(t, store)

	_, err = BuildKeyVersionStore(nil)
	var nilDep *NilDependencyError
	require.ErrorAs(t, err, &nilDep)
	assert.Equal(t, FeatureKeyVersions, nilDep.Feature)

	_, err = BuildKeyVersionStore(dao.NewStoreFactory(nil))
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureKeyVersions, buildErr.Feature)
	var unavailable *dao.DatabaseUnavailableError
	assert.ErrorAs(t, err, &unavailable)
}

func TestBuildKeyPolicyStore(t *testing.T) {
	store, err := BuildKeyPolicyStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	require.NotNil(t, store)

	_, err = BuildKeyPolicyStore(nil)
	var nilDep *NilDependencyError
	require.ErrorAs(t, err, &nilDep)
	assert.Equal(t, FeatureKeyPolicies, nilDep.Feature)

	_, err = BuildKeyPolicyStore(dao.NewStoreFactory(nil))
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureKeyPolicies, buildErr.Feature)
	var unavailable *dao.DatabaseUnavailableError
	assert.ErrorAs(t, err, &unavailable)
}

func TestBuildTrustRootStore(t *testing.T) {
	store, err := BuildTrustRootStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	require.NotNil(t, store)

	_, err = BuildTrustRootStore(nil)
	var nilDep *NilDependencyError
	require.ErrorAs(t, err, &nilDep)
	assert.Equal(t, FeatureTrustRoots, nilDep.Feature)

	_, err = BuildTrustRootStore(dao.NewStoreFactory(nil))
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureTrustRoots, buildErr.Feature)
	var unavailable *dao.DatabaseUnavailableError
	assert.ErrorAs(t, err, &unavailable)
}
