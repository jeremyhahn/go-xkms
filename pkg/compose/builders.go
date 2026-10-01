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
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/tenancy"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sealedstorage "github.com/jeremyhahn/go-xkms/pkg/storage/sealed"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Storage names each feature persists under. xkmsd resolves them to
// subdirectories (or qrdb key prefixes) of its configured storage; a host
// resolves them under its own namespace. They are part of the persisted
// layout: renaming one orphans existing data.
const (
	StoragePasswords      = "passwords"
	StoragePlatformStore  = "platform-store"
	StorageSSH            = "ssh"
	StorageCA             = "ca"
	StorageCASerials      = "ca-serials"
	StorageCARevocations  = "ca-revocations"
	StorageTPMPolicies    = "tpm-policies"
	StorageTPMKeys        = "tpm-keys"
	StorageKeyVersions    = "key-versions"
	defaultCredentialMode = credentialspkg.StrategyManual
)

// StorageFactory opens the storage.Backend a feature persists under name
// (one of the Storage* constants).
type StorageFactory func(name string) (storage.Backend, error)

// BackendLookup resolves a crypto backend by name. XKMSService.LookupBackend
// satisfies it.
type BackendLookup func(name string) (xkms.Backend, error)

// PlatformSealer is the sealer the platform store encrypts its records
// through, and the seal strategy it implements.
type PlatformSealer struct {
	// Strategy identifies the sealer (tpm2, pkcs11, awskms, passphrase, ...).
	Strategy seal.StrategyID

	// Sealer seals and unseals platform-store records.
	Sealer types.Sealer
}

// BuildPasswordStore builds the Password Manager's system store.
func BuildPasswordStore(open StorageFactory) (*staticpw.BackendStore, error) {
	if open == nil {
		return nil, &NilDependencyError{Feature: FeaturePasswords, Dependency: "storage factory"}
	}
	backend, err := open(StoragePasswords)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeaturePasswords, Err: err}
	}
	return staticpw.NewStore(backend), nil
}

// BuildKeyVersionStore builds the key-version record store over the storage
// StorageKeyVersions names. It is the one construction path of the store:
// xkmsd and an embedding host's module both build it here, and the
// XKMSService it is wired into (SetKeyVersionStore) needs it to rotate keys
// and to change the state of their versions.
func BuildKeyVersionStore(open StorageFactory) (*keyversion.Store, error) {
	if open == nil {
		return nil, &NilDependencyError{Feature: FeatureKeyVersions, Dependency: "storage factory"}
	}
	backend, err := open(StorageKeyVersions)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureKeyVersions, Err: err}
	}
	store, err := keyversion.NewStore(backend)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureKeyVersions, Err: err}
	}
	return store, nil
}

// BuildTenantPasswordManager builds the per-tenant Password Manager routing:
// tenant-scoped entries go to a store behind that tenant's barrier, system
// entries to store. passkeyRP is the WebAuthn relying party ID (the web
// console's domain, webauthn.rp_id) vault passkeys are created for; "" leaves
// passkey factors unavailable.
func BuildTenantPasswordManager(registry *seal.BarrierRegistry, store *staticpw.BackendStore, passkeyRP string) (*staticpw.TenantPasswordStoreManager, error) {
	if registry == nil {
		return nil, &NilDependencyError{Feature: FeatureTenantPasswords, Dependency: "barrier registry"}
	}
	if store == nil {
		return nil, &NilDependencyError{Feature: FeatureTenantPasswords, Dependency: "password store"}
	}
	manager, err := staticpw.NewTenantPasswordStoreManager(registry, store, staticpw.WithPasskeyRelyingParty(passkeyRP))
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureTenantPasswords, Err: err}
	}
	return manager, nil
}

// BuildPlatformStore builds the platform sealed-secret store: records are
// sealed through ps.Sealer and persisted under StoragePlatformStore.
func BuildPlatformStore(logger *slog.Logger, open StorageFactory, ps PlatformSealer) (seal.PlatformStore, error) {
	if open == nil {
		return nil, &NilDependencyError{Feature: FeaturePlatformStore, Dependency: "storage factory"}
	}
	if ps.Sealer == nil {
		return nil, &NilDependencyError{Feature: FeaturePlatformStore, Dependency: "sealer"}
	}
	logger = orDefault(logger)

	platformSealer, err := seal.NewPlatformSealer(
		logger,
		seal.SealerConfig{PreferenceOrder: []seal.StrategyID{ps.Strategy}},
		map[seal.StrategyID]types.Sealer{ps.Strategy: ps.Sealer},
	)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeaturePlatformStore, Err: err}
	}
	inner, err := open(StoragePlatformStore)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeaturePlatformStore, Err: err}
	}
	sealedBackend, err := sealedstorage.New(inner, platformSealer, nil)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeaturePlatformStore, Err: err}
	}
	store, err := seal.NewPlatformStore(sealedBackend, logger)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeaturePlatformStore, Err: err}
	}
	return store, nil
}

// BuildCredentialService builds the backend credential service for strategy
// ("" selects "manual"). The "barrier" strategy stores in barrier; every
// other non-manual strategy stores in platformStore.
func BuildCredentialService(logger *slog.Logger, strategy string, platformStore seal.PlatformStore, barrier *seal.Barrier) (*credentialspkg.Service, error) {
	if strategy == "" {
		strategy = defaultCredentialMode
	}
	svc, err := credentialspkg.New(&credentialspkg.Config{Strategy: strategy}, platformStore, barrier, orDefault(logger))
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureCredentials, Err: err}
	}
	return svc, nil
}

// BuildSSHClient builds the tenant-binding SSH client. Key generation and
// signing for a request naming a backend resolve through backends, narrowed
// to the caller's tenant, so a hardware-backed SSH key never leaves its
// device. permissions answers the ssh:service check a service-scoped address
// requires; nil closes the service scope.
func BuildSSHClient(open StorageFactory, backends BackendLookup, permissions tenancy.PermissionChecker) (sdkssh.Client, error) {
	if open == nil {
		return nil, &NilDependencyError{Feature: FeatureSSH, Dependency: "storage factory"}
	}
	if backends == nil {
		return nil, &NilDependencyError{Feature: FeatureSSH, Dependency: "backend lookup"}
	}
	sshStorage, err := open(StorageSSH)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureSSH, Err: err}
	}
	resolver := sshbackend.ResolverFunc(func(_ context.Context, backendID string) (types.KeyProvider, error) {
		b, err := backends(backendID)
		if err != nil {
			return nil, err
		}
		return b.KeyProvider(), nil
	})
	client, err := tenancy.New(tenancy.Options{Storage: sshStorage, Resolver: resolver, Permissions: permissions})
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureSSH, Err: err}
	}
	return client, nil
}

// CAParams configures BuildCA.
type CAParams struct {
	// Config is the CA's identity hierarchy. Required.
	Config *ca.MultiIdentityCAConfig

	// Storage opens the CA's certificate, serial and revocation stores.
	// Required.
	Storage StorageFactory

	// BackendForStore resolves the keystore holding each CA key by the
	// key's store type. Required.
	BackendForStore ca.BackendForStoreFunc

	// AuditLogger records CA lifecycle events. Optional.
	AuditLogger audit.Logger

	// AdoptCertStore runs against the CA's certificate store after the CA is
	// constructed and before it loads, so a caller can stage certificates
	// the load must find (xkmsd's cluster-ACME first-node material).
	// Optional.
	AdoptCertStore func(certstore.CertStore) error

	// Logger receives construction diagnostics. Nil selects slog.Default().
	Logger *slog.Logger
}

// BuildCA builds the Certificate Authority and brings it to a usable state:
// it loads the persisted hierarchy, or initializes a new one when no root
// has ever been persisted. Any other load failure fails closed rather than
// minting a second root over existing state.
func BuildCA(ctx context.Context, p CAParams) (ca.TrustedCA, error) {
	if p.Config == nil {
		return nil, &NilDependencyError{Feature: FeatureCA, Dependency: "CA configuration"}
	}
	if p.Storage == nil {
		return nil, &NilDependencyError{Feature: FeatureCA, Dependency: "storage factory"}
	}
	if p.BackendForStore == nil {
		return nil, &NilDependencyError{Feature: FeatureCA, Dependency: "backend resolver"}
	}
	logger := orDefault(p.Logger)

	if err := p.Config.Validate(); err != nil {
		return nil, &CAOperationError{Operation: "validate configuration", Err: err}
	}
	if len(p.Config.Identity) == 0 {
		return nil, &CANoIdentitiesError{}
	}
	root := p.Config.Identity[0]
	keyStore, err := p.BackendForStore(root.Subject.CommonName, root.GetStoreType())
	if err != nil {
		return nil, &CAOperationError{Operation: "resolve keystore", Err: err}
	}

	caStorage, err := p.Storage(StorageCA)
	if err != nil {
		return nil, &CAOperationError{Operation: "open certificate storage", Err: err}
	}
	certStore, err := certstore.New(&certstore.Config{CertStorage: storage.NewCertAdapter(caStorage)})
	if err != nil {
		return nil, &CAOperationError{Operation: "create certificate store", Err: err}
	}
	// Serials and revocations persist in the datastore so serial uniqueness
	// and the revocation set survive restarts (and replicate under Raft).
	serialStore, err := p.Storage(StorageCASerials)
	if err != nil {
		return nil, &CAOperationError{Operation: "open serial storage", Err: err}
	}
	revocationStore, err := p.Storage(StorageCARevocations)
	if err != nil {
		return nil, &CAOperationError{Operation: "open revocation storage", Err: err}
	}

	trustedCA, err := ca.NewFromMultiIdentityConfig(&ca.MultiIdentityParams{
		Config:          p.Config,
		KeyStore:        keyStore,
		CertStore:       certStore,
		SerialGen:       ca.NewSerialGenerator(ca.NewBackendStorage(serialStore)),
		RevocationStore: revocationStore,
		BackendForStore: p.BackendForStore,
		AuditLogger:     p.AuditLogger,
	})
	if err != nil {
		return nil, &CAOperationError{Operation: "create", Err: err}
	}

	if p.AdoptCertStore != nil {
		if err := p.AdoptCertStore(certStore); err != nil {
			return nil, &CAOperationError{Operation: "adopt staged certificates", Err: err}
		}
	}

	// Only ca.ErrCertificateNotFound — a root or intermediate simply absent —
	// means "never initialized". Any other load failure is a problem with
	// existing state and must not be papered over with a new root
	// (go-xkms#793).
	if err := trustedCA.Load(ctx); err != nil {
		if !errors.Is(err, ca.ErrCertificateNotFound) {
			return nil, &CAOperationError{Operation: "load existing CA", Err: err}
		}
		logger.Info("No existing CA found, initializing new CA", "reason", err.Error())
		if err := trustedCA.Init(ctx); err != nil {
			return nil, &CAOperationError{Operation: "initialize new CA", Err: err}
		}
	}
	return trustedCA, nil
}

// TPMPolicyParams are the dependencies of the TPM policy service.
type TPMPolicyParams struct {
	// Backend is the TPM2 key backend. The service runs over its TPM,
	// Platform SRK and key store (the system scope), and is installed as its
	// scope provider, so its key operations run in the scope of each key's
	// tenant. Required.
	Backend *tpm2backend.Backend

	// Storage opens the service's registry (StorageTPMPolicies) and the
	// store of every tenant's TPM object blobs (StorageTPMKeys). Required.
	Storage StorageFactory

	// VTPM configures the per-tenant vTPM supervisor. Nil leaves vtpm mode
	// unavailable: a tenant set to it is refused with
	// tpmpolicy.ErrVTPMUnavailable.
	VTPM *vtpm.Config

	// Logger receives the service's lifecycle events. Nil selects
	// slog.Default().
	Logger *slog.Logger
}

// BuildTPMPolicyService builds the TPM policy service (pkg/tpmpolicy) over
// the TPM2 key backend and installs it as the backend's scope provider. The
// service seals each scope's secrets with the backend's own TPM, under the
// built-in platform policy the service names on every sealed object. The
// caller closes the service at shutdown, which also removes it from the TPM.
func BuildTPMPolicyService(p TPMPolicyParams) (*tpmpolicy.Service, error) {
	if p.Backend == nil {
		return nil, &NilDependencyError{Feature: FeatureTPMPolicies, Dependency: "TPM2 backend"}
	}
	if p.Storage == nil {
		return nil, &NilDependencyError{Feature: FeatureTPMPolicies, Dependency: "storage factory"}
	}
	tpm, ok := p.Backend.TPM().(*pkgtpm2.TPM2)
	if !ok {
		return nil, &FeatureBuildError{Feature: FeatureTPMPolicies, Err: ErrUnsupportedTPM}
	}
	registryStore, err := p.Storage(StorageTPMPolicies)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureTPMPolicies, Err: err}
	}
	registry, err := tpmpolicy.NewRegistry(registryStore)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureTPMPolicies, Err: err}
	}
	keyStorage, err := p.Storage(StorageTPMKeys)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureTPMPolicies, Err: err}
	}
	svc, err := tpmpolicy.NewService(tpmpolicy.Config{
		Registry:    registry,
		TPM:         tpm,
		PlatformSRK: p.Backend.SRKAttributes(),
		Keys:        p.Backend.KeyBackend(),
		KeyStorage:  keyStorage,
		Sealer:      tpm,
		VTPM:        p.VTPM,
		Logger:      orDefault(p.Logger),
	})
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureTPMPolicies, Err: err}
	}
	p.Backend.SetScopeProvider(svc)
	return svc, nil
}

// OIDCCredentialParams are BuildOIDCCredentialService's inputs.
type OIDCCredentialParams struct {
	// Registry holds the tenant barriers credentials are sealed on.
	// Required.
	Registry *seal.BarrierRegistry

	// Leases is the qrdb lease primitive (qrdbsdk.Client.Coordination()).
	// Required.
	Leases credential.Leases

	// Audit receives credential events; nil logs them only.
	Audit audit.Logger

	// SchedulerInterval is how often the leader looks for credentials due
	// for refresh; zero is credential.DefaultSchedulerInterval.
	SchedulerInterval time.Duration

	// Logger receives the service's log lines.
	Logger *slog.Logger
}

// BuildOIDCCredentialService builds the server-side OIDC credential service
// (pkg/oidc/credential) over the tenant barriers and starts its refresh
// scheduler. The caller closes the service at shutdown, which stops the
// scheduler.
func BuildOIDCCredentialService(p OIDCCredentialParams) (*credential.Service, error) {
	if p.Registry == nil {
		return nil, &NilDependencyError{Feature: FeatureOIDCCredentials, Dependency: "barrier registry"}
	}
	if p.Leases == nil {
		return nil, &NilDependencyError{Feature: FeatureOIDCCredentials, Dependency: "qrdb coordination"}
	}
	opts := []credential.Option{credential.WithLogger(orDefault(p.Logger)), credential.WithLeases(p.Leases)}
	if p.Audit != nil {
		opts = append(opts, credential.WithAudit(p.Audit))
	}
	svc, err := credential.New(credential.RegistryBarriers(p.Registry), opts...)
	if err != nil {
		return nil, &FeatureBuildError{Feature: FeatureOIDCCredentials, Err: err}
	}
	svc.Start(p.SchedulerInterval)
	return svc, nil
}

// orDefault returns logger, or slog.Default() when it is nil.
func orDefault(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}
