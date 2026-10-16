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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	sshrecords "github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	tpmstore "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Deps is what an embedding host supplies for Build. Only Service is
// required; every other field enables the features that need it, and a
// feature whose dependency is absent stays off with a recorded reason.
type Deps struct {
	// Service is the composed XKMSService the stores are wired into, and
	// whose backends back SSH and the CA. Required.
	Service *xkms.XKMSService

	// Storage opens the backend each feature persists under. Enables SSH
	// and — together with their own dependency — the platform store, CA and
	// TPM policies.
	Storage StorageFactory

	// BarrierRegistry is the tenant barrier registry. Enables the "barrier"
	// credential strategy.
	BarrierRegistry *seal.BarrierRegistry

	// TenantStores resolves each tenant's go-qrdb store, behind that
	// tenant's barrier (the node's StoreResolver). With DAOs it enables
	// per-tenant Password Manager routing.
	TenantStores qrdbsdk.TenantStoreResolver

	// PIN is the PIN backend whose user PIN opens a tenant Password
	// Manager session. Without it a tenant's password store cannot be
	// unlocked. It also backs the PIN management surface.
	PIN qrdbsdk.PINBackend

	// PlatformSealer enables the platform sealed-secret store.
	PlatformSealer *PlatformSealer

	// CredentialStrategy selects how the credential service seals backend
	// credentials; empty selects "manual". "barrier" needs BarrierRegistry,
	// and the hardware and cloud strategies need PlatformSealer.
	CredentialStrategy string

	// CA enables the Certificate Authority, keyed in the Service's
	// backends by each CA key's store type. It needs DAOs and Storage.
	CA *ca.MultiIdentityCAConfig

	// DAOs serves the go-qrdb database of each feature that persists through
	// DAOs; Databases names them, for the composition root to open first.
	// Enables key versions, trust roots and the Password Manager; with CA and Storage, the Certificate Authority;
	// with TPMBackend, the TPM policy service.
	DAOs *qrdbsdk.DAOFactory

	// TPMBackend is the TPM2 key backend. With DAOs it enables
	// the TPM policy service, which Build installs as the backend's scope
	// provider.
	TPMBackend *tpm2backend.Backend

	// VTPM configures the TPM policy service's per-tenant vTPMs. Nil
	// leaves vtpm mode unavailable.
	VTPM *vtpm.Config

	// ReferenceSigner is the reference-value signer's endorsement the TPM
	// policy service verifies a signed CoRIM under. Nil leaves
	// reference-value branch updates unavailable.
	ReferenceSigner *refvalue.VerifyOptions

	// NodeID is the deployment's node ID (cluster.node_id; 0 on a single
	// node), which keys the TPM policy registry's records to this node.
	NodeID uint64

	// Leases is the host qrdb node's lease primitive
	// (qrdbsdk.Client.Coordination()), which serializes OIDC credential
	// refreshes and elects their scheduler's leader across a cluster. The
	// OIDC credential feature needs it. On a standalone node qrdb refuses
	// the lease family with a typed error, which the credential service
	// reads as the single process it is.
	Leases credential.Leases

	// PasskeyRelyingParty is the WebAuthn relying party ID -- the web
	// console's domain -- the password vault's passkey factors are created
	// for. Empty leaves passkey factors unavailable.
	PasskeyRelyingParty string

	// Audit receives the OIDC credential events. Nil logs them only.
	Audit qrdbsdk.NodeAuditLogger

	// Logger receives one line per feature built or left off. Nil selects
	// slog.Default().
	Logger *slog.Logger
}

// Stores holds the composed subsystems. A nil field is a feature that is
// off; Disabled explains each one.
type Stores struct {
	// PasswordStore is the Password Manager's system store.
	PasswordStore *staticpw.DAOStore

	// PasswordManager routes Password Manager entries to per-tenant stores.
	PasswordManager *staticpw.TenantPasswordStoreManager

	// PIN is the PIN backend.
	PIN qrdbsdk.PINBackend

	// PlatformStore is the platform sealed-secret store.
	PlatformStore seal.PlatformStore

	// Credentials is the backend credential service.
	Credentials *credentialspkg.Service

	// SSH is the tenant-binding SSH client.
	SSH sdkssh.Client

	// CA is the Certificate Authority.
	CA ca.TrustedCA

	// TPMPolicies is the TPM policy service. Its owner closes it at
	// shutdown.
	TPMPolicies *tpmpolicy.Service

	// KeyVersions is the key-version record store.
	KeyVersions *keyversion.Store

	// OIDCCredentials is the server-side OIDC credential service, its
	// refresh scheduler running.
	OIDCCredentials *credential.Service

	// Invite is the enrollment-invitation store (go-xkms#1294 part B).
	Invite xkms.InviteStore

	// TrustRoots is the platform trust-root store.
	TrustRoots *truststore.DAOStore

	// Disabled holds one *FeatureDisabledError or *FeatureBuildError per
	// feature Build left off.
	Disabled []error
}

// Databases returns the go-qrdb databases that the DAO-backed features d
// supplies the other dependencies for persist in. A composition root opens
// each on its datastore and sets d.DAOs to the factory serving them before
// Build; a root that opens none leaves those features off.
func Databases(d Deps) []string {
	databases := []string{keyversion.DatabaseName, sshrecords.DatabaseName, staticpw.DatabaseName, truststore.DatabaseName}
	if d.CA != nil {
		databases = append(databases, certstore.DatabaseName)
	}
	if d.TPMBackend != nil {
		databases = append(databases, tpmpolicy.DatabaseName, tpmstore.DatabaseName)
	}
	return databases
}

// Build composes every feature d supplies the dependencies for, logging
// one line per feature built or left off. It fails only when d carries no
// Service; a missing or failing feature is recorded in Stores.Disabled and
// the rest compose without it.
//
// Build does not wire the result: call Stores.Wire to publish it into the
// Service.
func Build(ctx context.Context, d Deps) (*Stores, error) {
	if d.Service == nil {
		return nil, &NilServiceError{}
	}
	b := &builder{logger: orDefault(d.Logger), stores: &Stores{}}
	st := b.stores

	var systemBarrier *seal.Barrier
	if d.BarrierRegistry != nil {
		systemBarrier = d.BarrierRegistry.SystemBarrier()
	}

	// Password Manager: the system store, then per-tenant routing.
	if b.need(FeaturePasswords, d.DAOs != nil, "DAO factory") {
		st.PasswordStore = built(b, FeaturePasswords, func() (*staticpw.DAOStore, error) {
			return BuildPasswordStore(d.DAOs)
		})
	}
	if st.PasswordStore != nil && b.need(FeatureTenantPasswords, d.TenantStores != nil, "tenant store resolver") {
		st.PasswordManager = built(b, FeatureTenantPasswords, func() (*staticpw.TenantPasswordStoreManager, error) {
			return BuildTenantPasswordManager(d.TenantStores, st.PasswordStore, d.PasskeyRelyingParty)
		})
	}

	if b.need(FeaturePIN, d.PIN != nil, "PIN backend") {
		st.PIN = d.PIN
		b.logger.Info("xkms feature on", "feature", FeaturePIN)
	}

	// Platform store, then the credential service that may store in it.
	if b.need(FeaturePlatformStore, d.Storage != nil, "storage") &&
		b.need(FeaturePlatformStore, d.PlatformSealer != nil, "platform sealer") {
		st.PlatformStore = built(b, FeaturePlatformStore, func() (seal.PlatformStore, error) {
			return BuildPlatformStore(b.logger, d.Storage, *d.PlatformSealer)
		})
	}
	b.credentials(d.CredentialStrategy, systemBarrier)

	if b.need(FeatureSSH, d.DAOs != nil, "DAO factory") {
		st.SSH = built(b, FeatureSSH, func() (sdkssh.Client, error) {
			return BuildSSHClient(d.DAOs, d.Service.LookupBackend, d.Service)
		})
	}

	if b.need(FeatureCA, d.CA != nil, "CA configuration") &&
		b.need(FeatureCA, d.DAOs != nil, "DAO factory") &&
		b.need(FeatureCA, d.Storage != nil, "storage") {
		st.CA = built(b, FeatureCA, func() (ca.TrustedCA, error) {
			return BuildCA(ctx, CAParams{
				Config:          d.CA,
				DAOs:            d.DAOs,
				Storage:         d.Storage,
				BackendForStore: backendForStore(d.Service),
				Logger:          b.logger,
			})
		})
	}

	if b.need(FeatureTPMPolicies, d.TPMBackend != nil, "TPM2 backend") &&
		b.need(FeatureTPMPolicies, d.DAOs != nil, "DAO factory") {
		st.TPMPolicies = built(b, FeatureTPMPolicies, func() (*tpmpolicy.Service, error) {
			return BuildTPMPolicyService(TPMPolicyParams{
				Backend: d.TPMBackend,
				DAOs:    d.DAOs,
				NodeID:  d.NodeID,
				VTPM:    d.VTPM,
				Logger:  b.logger,

				ReferenceSigner: d.ReferenceSigner,
			})
		})
	}

	if b.need(FeatureKeyVersions, d.DAOs != nil, "DAO factory") {
		st.KeyVersions = built(b, FeatureKeyVersions, func() (*keyversion.Store, error) {
			return BuildKeyVersionStore(d.DAOs)
		})
	}

	if b.need(FeatureTrustRoots, d.DAOs != nil, "DAO factory") {
		st.TrustRoots = built(b, FeatureTrustRoots, func() (*truststore.DAOStore, error) {
			return BuildTrustRootStore(d.DAOs)
		})
	}

	if b.need(FeatureOIDCCredentials, d.BarrierRegistry != nil, "barrier registry") &&
		b.need(FeatureOIDCCredentials, d.Leases != nil, "qrdb coordination") {
		st.OIDCCredentials = built(b, FeatureOIDCCredentials, func() (*credential.Service, error) {
			return BuildOIDCCredentialService(OIDCCredentialParams{
				Registry: d.BarrierRegistry,
				Leases:   d.Leases,
				Audit:    d.Audit,
				Logger:   b.logger,
			})
		})
	}

	if b.need(FeatureInvite, d.Storage != nil, "storage") {
		st.Invite = built(b, FeatureInvite, func() (xkms.InviteStore, error) {
			return BuildInviteStore(d.Storage)
		})
	}

	return st, nil
}

// Wire publishes every composed store into svc. A nil store is skipped, so
// the Service keeps answering its "not configured" error for a feature that
// is off.
func (st *Stores) Wire(svc *xkms.XKMSService) {
	if st.PasswordStore != nil {
		svc.SetPasswordStore(st.PasswordStore)
	}
	if st.PasswordManager != nil {
		svc.SetPasswordStoreManager(st.PasswordManager)
	}
	if st.PIN != nil {
		svc.SetPINManager(st.PIN)
	}
	if st.PlatformStore != nil {
		svc.SetPlatformStore(st.PlatformStore)
	}
	if st.Credentials != nil {
		svc.SetCredentialService(st.Credentials)
	}
	if st.TPMPolicies != nil {
		svc.SetTPMPolicyService(st.TPMPolicies)
	}
	if st.KeyVersions != nil {
		svc.SetKeyVersionStore(st.KeyVersions)
	}
	if st.TrustRoots != nil {
		svc.SetTrustRootStore(st.TrustRoots)
	}
	if st.OIDCCredentials != nil {
		svc.SetOIDCCredentialService(st.OIDCCredentials)
	}
	// ca.TrustedCA does not carry the transport-shaped *Raw methods; the
	// concrete CA satisfies provider.CA through them (pkg/ca
	// service_adapter.go).
	if caProvider, ok := st.CA.(provider.CA); ok {
		svc.SetCA(caProvider)
	}
	if st.Invite != nil {
		svc.SetInviteStore(st.Invite)
	}
}

// builder accumulates the stores and the reasons features are off.
type builder struct {
	logger *slog.Logger
	stores *Stores
}

// need reports whether a dependency of feature is present, recording a
// FeatureDisabledError when it is not.
func (b *builder) need(feature Feature, present bool, missing string) bool {
	if present {
		return true
	}
	b.off(&FeatureDisabledError{Feature: feature, Missing: missing})
	return false
}

// off records and logs why a feature is off.
func (b *builder) off(err error) {
	b.stores.Disabled = append(b.stores.Disabled, err)
	var disabled *FeatureDisabledError
	if errors.As(err, &disabled) {
		b.logger.Info("xkms feature off", "feature", disabled.Feature, "reason", err.Error())
		return
	}
	b.logger.Error("xkms feature failed to build; it stays off", "error", err.Error())
}

// credentials builds the credential service, turning a strategy whose
// storage is not composed into a disabled feature rather than a failure.
func (b *builder) credentials(strategy string, barrier *seal.Barrier) {
	svc, err := BuildCredentialService(b.logger, strategy, b.stores.PlatformStore, barrier)
	switch {
	case errors.Is(err, credentialspkg.ErrNilBarrier):
		b.off(&FeatureDisabledError{Feature: FeatureCredentials, Missing: "barrier registry"})
	case errors.Is(err, credentialspkg.ErrNilPlatformStore):
		b.off(&FeatureDisabledError{Feature: FeatureCredentials, Missing: "platform store"})
	case err != nil:
		b.off(err)
	default:
		b.stores.Credentials = svc
		b.logger.Info("xkms feature on", "feature", FeatureCredentials, "strategy", svc.Strategy())
	}
}

// built runs a feature's builder, recording its failure and logging its
// success. It returns the zero value when the build failed.
func built[T any](b *builder, feature Feature, build func() (T, error)) T {
	v, err := build()
	if err != nil {
		var buildErr *FeatureBuildError
		if !errors.As(err, &buildErr) {
			err = &FeatureBuildError{Feature: feature, Err: err}
		}
		b.off(err)
		var zero T
		return zero
	}
	b.logger.Info("xkms feature on", "feature", feature)
	return v
}

// TPM2Backend returns svc's TPM2 key backend -- the key provider of the
// backend registered as "tpm2" -- or nil when svc has none.
func TPM2Backend(svc *xkms.XKMSService) *tpm2backend.Backend {
	b, err := svc.LookupBackend(string(types.StoreTPM2))
	if err != nil {
		return nil
	}
	tpm, ok := b.KeyProvider().(*tpm2backend.Backend)
	if !ok {
		return nil
	}
	return tpm
}

// Close releases what the stores hold open beyond their storage: the OIDC
// credential scheduler, and the TPM policy service's scopes and vTPMs. The
// owner of the stores calls it at shutdown.
func (st *Stores) Close() error {
	var errs []error
	if st.OIDCCredentials != nil {
		errs = append(errs, st.OIDCCredentials.Close())
	}
	if st.TPMPolicies != nil {
		errs = append(errs, st.TPMPolicies.Close())
	}
	return errors.Join(errs...)
}

// backendForStore resolves each CA key's keystore from svc's backends by
// the key's store type.
func backendForStore(svc *xkms.XKMSService) ca.BackendForStoreFunc {
	return func(_ string, storeType types.StoreType) (xkms.Backend, error) {
		return svc.LookupBackend(string(storeType))
	}
}
