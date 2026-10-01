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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

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
	return Deps{
		Service:            svc,
		Storage:            memoryStorage(t),
		BarrierRegistry:    hostdeps.NewBarrierRegistry(t),
		PIN:                hostdeps.NewPINBackend(t, "so-pin-123456", "user-pin-654321"),
		PlatformSealer:     &PlatformSealer{Strategy: "passphrase", Sealer: hostdeps.NewSealer(t)},
		CredentialStrategy: "barrier",
		CA:                 hostdeps.NewCAConfig("Compose Test Root"),
		Custodians:         custodians{},
		Shares:             shares{},
		Backup:             backupClient{},
		ServeBarrier:       true,
	}
}

func TestBuild_RequiresService(t *testing.T) {
	st, err := Build(context.Background(), Deps{})
	assert.Nil(t, st)
	var nilSvc *NilServiceError
	require.ErrorAs(t, err, &nilSvc)
	assert.Contains(t, err.Error(), "XKMSService")
}

// TestBuild_EveryDependencyComposesEveryFeature proves a host that supplies
// every dependency gets every feature, and that Wire makes each one answer
// through the XKMSService rather than its "not configured" error. The TPM
// policy service needs a TPM, which only the simulator tests supply
// (compose_tpm_sim_test.go), so here it is the one feature off.
func TestBuild_EveryDependencyComposesEveryFeature(t *testing.T) {
	svc := hostdeps.NewService(t)
	st, err := Build(context.Background(), fullDeps(t, svc))
	require.NoError(t, err)
	require.Len(t, st.Disabled, 1, "only the TPM policy service may be off: no TPM2 backend is supplied")
	var disabled *FeatureDisabledError
	require.ErrorAs(t, st.Disabled[0], &disabled)
	assert.Equal(t, FeatureTPMPolicies, disabled.Feature)

	assert.NotNil(t, st.PasswordStore)
	assert.NotNil(t, st.PasswordManager)
	assert.NotNil(t, st.PIN)
	assert.NotNil(t, st.PlatformStore)
	assert.NotNil(t, st.Credentials)
	assert.NotNil(t, st.SSH)
	assert.NotNil(t, st.CA)
	assert.Nil(t, st.TPMPolicies)
	assert.NotNil(t, st.KeyVersions)
	assert.NotNil(t, st.Barrier)
	assert.NotNil(t, st.Custodians)
	assert.NotNil(t, st.Shares)
	assert.NotNil(t, st.Invite)
	assert.NotNil(t, st.Backup)
	assert.Equal(t, "barrier", st.Credentials.Strategy())

	st.Wire(svc)
	ctx := platformCtx()

	require.NoError(t, svc.SealStorePut(ctx, &transport.SealStorePutRequest{Name: "k", Secret: []byte("v")}))
	got, err := svc.SealStoreGet(ctx, &transport.SealStoreGetRequest{Name: "k"})
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got.Secret)

	caCert, err := svc.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	assert.Contains(t, caCert.Subject, "Compose Test Root")

	status, err := svc.BarrierStatus(ctx)
	require.NoError(t, err)
	assert.False(t, status.Sealed, "the host's unsealed barrier is the one served")

	_, err = svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)

	groups, err := svc.ListCustodianGroups(ctx)
	require.NoError(t, err)
	assert.Empty(t, groups.Groups, "custody answers from the host's node clients")

	backups, err := svc.ListBackups(ctx)
	require.NoError(t, err)
	assert.Empty(t, backups, "backup answers from the host's node client")

	// The key-version store is wired: a key rotates into version 2.
	_, err = svc.GenerateKey(ctx, &transport.GenerateKeyRequest{Backend: hostdeps.BackendName, KeyID: "composed", Algorithm: "ecdsa"})
	require.NoError(t, err)
	rotated, err := svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: hostdeps.BackendName, KeyID: "composed"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)
}

// TestBuild_NoDependenciesLeavesEveryFeatureOffWithTypedReasons proves a
// missing dependency never fails composition and is never silent: each
// feature is off with a *FeatureDisabledError naming what was missing.
func TestBuild_NoDependenciesLeavesEveryFeatureOffWithTypedReasons(t *testing.T) {
	svc := hostdeps.NewService(t)
	st, err := Build(context.Background(), Deps{Service: svc, CredentialStrategy: "barrier", ServeBarrier: true})
	require.NoError(t, err)

	missing := map[Feature]string{}
	for _, reason := range st.Disabled {
		var disabled *FeatureDisabledError
		require.ErrorAs(t, reason, &disabled, "every reason must be typed: %v", reason)
		if _, seen := missing[disabled.Feature]; !seen {
			missing[disabled.Feature] = disabled.Missing
		}
	}
	assert.Equal(t, map[Feature]string{
		FeaturePasswords:     "storage",
		FeaturePIN:           "PIN backend",
		FeaturePlatformStore: "storage",
		FeatureCredentials:   "barrier registry",
		FeatureSSH:           "storage",
		FeatureCA:            "CA configuration",
		FeatureTPMPolicies:   "TPM2 backend",
		FeatureKeyVersions:   "storage",
		FeatureBarrier:       "barrier registry",
		FeatureCustody:       "custody clients",
		FeatureInvite:        "storage",
		FeatureBackup:        "backup client",
	}, missing)

	assert.Nil(t, st.PasswordStore)
	assert.Nil(t, st.PlatformStore)
	assert.Nil(t, st.Credentials)
	assert.Nil(t, st.SSH)
	assert.Nil(t, st.CA)
	assert.Nil(t, st.TPMPolicies)
	assert.Nil(t, st.KeyVersions)
	assert.Nil(t, st.Barrier)
	assert.Nil(t, st.Invite)
	assert.Nil(t, st.Backup)

	// Wiring an empty composition leaves the service answering "not
	// configured" for each feature.
	st.Wire(svc)
	_, err = svc.SealStoreStatus(platformCtx())
	assert.ErrorIs(t, err, xkms.ErrNotConfigured)
	_, err = svc.TPMPolicyList(platformCtx(), &transport.TPMPolicyListRequest{})
	assert.ErrorIs(t, err, xkms.ErrNotConfigured)
	_, err = svc.RotateScopeKeys(platformCtx(), &transport.RotateScopeKeysRequest{})
	assert.ErrorIs(t, err, xkms.ErrNotConfigured, "rotation needs the key-version store")
	assert.NoError(t, st.Close(), "closing stores without a TPM policy service is a no-op")
}

// TestBuild_BarrierStaysOffByDefault proves a host's barrier is only served
// when the host opts in: the registry alone enables tenant password routing
// but never the barrier routes.
func TestBuild_BarrierStaysOffByDefault(t *testing.T) {
	svc := hostdeps.NewService(t)
	deps := fullDeps(t, svc)
	deps.ServeBarrier = false

	st, err := Build(context.Background(), deps)
	require.NoError(t, err)
	assert.NotNil(t, st.PasswordManager)
	assert.Nil(t, st.Barrier)
	assert.Nil(t, st.Custodians)

	st.Wire(svc)
	_, err = svc.BarrierStatus(platformCtx())
	assert.ErrorIs(t, err, xkms.ErrNotConfigured)
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
	for _, f := range []Feature{FeaturePasswords, FeaturePlatformStore, FeatureSSH, FeatureCA, FeatureKeyVersions, FeatureInvite} {
		assert.True(t, failed[f], "%s must fail on storage", f)
	}
	// Features with no storage of their own still compose.
	assert.NotNil(t, st.Credentials)
	assert.NotNil(t, st.Barrier)
}

// TestBuildCA_ReloadsPersistedRoot proves a second CA over the same storage
// loads the persisted root instead of minting a new one (go-xkms#793).
func TestBuildCA_ReloadsPersistedRoot(t *testing.T) {
	svc := hostdeps.NewService(t)
	open := memoryStorage(t)
	params := CAParams{
		Config:          hostdeps.NewCAConfig("Reload Root"),
		Storage:         open,
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

func TestBuildCA_InvalidInput(t *testing.T) {
	svc := hostdeps.NewService(t)
	valid := CAParams{
		Config:          hostdeps.NewCAConfig("Root"),
		Storage:         memoryStorage(t),
		BackendForStore: backendForStore(svc),
	}

	t.Run("nil dependencies", func(t *testing.T) {
		for name, p := range map[string]CAParams{
			"config":  {Storage: valid.Storage, BackendForStore: valid.BackendForStore},
			"storage": {Config: valid.Config, BackendForStore: valid.BackendForStore},
			"backend": {Config: valid.Config, Storage: valid.Storage},
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
	client, err := BuildSSHClient(memoryStorage(t), svc.LookupBackend)
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
	_, err = BuildTenantPasswordManager(nil, nil)
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildTenantPasswordManager(hostdeps.NewBarrierRegistry(t), nil)
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildPlatformStore(nil, nil, PlatformSealer{})
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildPlatformStore(nil, memoryStorage(t), PlatformSealer{})
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildSSHClient(nil, nil)
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildSSHClient(memoryStorage(t), nil)
	assert.ErrorAs(t, err, &nilDep)
	_, err = BuildTPMPolicyService(TPMPolicyParams{Storage: memoryStorage(t)})
	assert.ErrorAs(t, err, &nilDep)
	assert.Contains(t, err.Error(), "TPM2 backend")
	_, err = BuildTPMPolicyService(TPMPolicyParams{Backend: &tpm2backend.Backend{}})
	assert.ErrorAs(t, err, &nilDep)
	assert.Contains(t, err.Error(), "storage factory")
}

func TestBuilders_StorageFailureIsFeatureBuildError(t *testing.T) {
	var buildErr *FeatureBuildError

	_, err := BuildPasswordStore(failingStorage)
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeaturePasswords, buildErr.Feature)

	_, err = BuildPlatformStore(nil, failingStorage, PlatformSealer{Strategy: "passphrase", Sealer: hostdeps.NewSealer(t)})
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeaturePlatformStore, buildErr.Feature)

	svc := hostdeps.NewService(t)
	_, err = BuildSSHClient(failingStorage, svc.LookupBackend)
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureSSH, buildErr.Feature)

	// A backend whose TPM is not a pkg/tpm2 TPM cannot run the TPM policy
	// service; it is refused before any storage is opened.
	_, err = BuildTPMPolicyService(TPMPolicyParams{Backend: &tpm2backend.Backend{}, Storage: failingStorage})
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

// custodians and shares stand in for a qrdb node's custody clients. Only
// the listing calls the tests make are implemented; the embedded interfaces
// panic on anything else, so an unexpected call fails loudly.
type custodians struct {
	qrdbtransport.CustodianGroupClient
}

func (custodians) ListCustodianGroups(context.Context) (*qrdbtransport.ListCustodianGroupsResponse, error) {
	return &qrdbtransport.ListCustodianGroupsResponse{}, nil
}

type shares struct {
	qrdbtransport.ShareClient
}

func (shares) ListShares(context.Context) (*qrdbtransport.ListSharesResponse, error) {
	return &qrdbtransport.ListSharesResponse{}, nil
}

// backupClient stands in for a qrdb node's backup client (go-xkms#728). Only
// the listing call the tests make is implemented; the embedded interface
// panics on anything else, so an unexpected call fails loudly.
type backupClient struct {
	qrdbtransport.BackupClient
}

func (backupClient) ListBackups(context.Context) ([]qrdbtransport.BackupInfo, error) {
	return nil, nil
}

// TestTPM2Backend_NoneRegistered proves a service without a TPM2 backend
// yields none, leaving the TPM policy service off in a host composition.
func TestTPM2Backend_NoneRegistered(t *testing.T) {
	assert.Nil(t, TPM2Backend(hostdeps.NewService(t)))
}

// TestBuildKeyVersionStore proves the store is built over the storage its
// name opens, and that a missing factory and a failing storage are typed
// errors naming the feature.
func TestBuildKeyVersionStore(t *testing.T) {
	var opened []string
	open := func(name string) (storage.Backend, error) {
		opened = append(opened, name)
		return storage.New(), nil
	}
	store, err := BuildKeyVersionStore(open)
	require.NoError(t, err)
	require.NotNil(t, store)
	assert.Equal(t, []string{StorageKeyVersions}, opened)

	_, err = BuildKeyVersionStore(nil)
	var nilDep *NilDependencyError
	require.ErrorAs(t, err, &nilDep)
	assert.Equal(t, FeatureKeyVersions, nilDep.Feature)

	_, err = BuildKeyVersionStore(failingStorage)
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureKeyVersions, buildErr.Feature)
	assert.ErrorIs(t, err, errStorageDown)
}
