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
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Local TPM policy service errors.
var (
	// ErrLocalTPMPolicyNoTPM indicates OpenLocalTPMPolicies was given no TPM.
	ErrLocalTPMPolicyNoTPM = errors.New("tpm_policy: local mode needs a TPM")

	// ErrLocalTPMPolicyNoKeys indicates OpenLocalTPMPolicies was given no
	// key store for the TPM's own objects.
	ErrLocalTPMPolicyNoKeys = errors.New("tpm_policy: local mode needs the TPM's key store")

	// ErrLocalTPMPolicyNoDataDir indicates OpenLocalTPMPolicies was given no
	// data directory to keep the policy registry in.
	ErrLocalTPMPolicyNoDataDir = errors.New("tpm_policy: local mode needs a data directory")

	// ErrLocalTPMPolicyNoStoreOpener indicates OpenLocalTPMPolicies was given
	// no function to open its stores with.
	ErrLocalTPMPolicyNoStoreOpener = errors.New("tpm_policy: local mode needs a store opener")

	// ErrLocalTPMPolicyBuildFailed indicates the in-process TPM policy
	// service could not be built over the TPM.
	ErrLocalTPMPolicyBuildFailed = errors.New("tpm_policy: failed to build the local TPM policy service")

	// ErrTPMObjectNameRequired indicates a sealed-object operation without a
	// name.
	ErrTPMObjectNameRequired = errors.New("tpm_policy: sealed object name is required")
)

// localScope is the tenant every local operation acts on: xKey owns one TPM
// and keeps all of its objects in the system scope.
const localScope = ""

// LocalTPMPolicyParams are the dependencies of the TPM policy service xKey
// runs in-process over its own TPM.
type LocalTPMPolicyParams struct {
	// TPM is xKey's TPM. The service installs itself as its policy binding
	// resolver, so every key and sealed object created on it can name a
	// policy.
	TPM xkms.TrustedPlatformModule

	// Keys is the TPM's own key store: the system scope's objects (its
	// policy authority and sealed scope secrets) live there.
	Keys xkms.TPMKeyBackend

	// DataDir is xKey's data directory. The policy registry is kept in
	// "<DataDir>/tpm-policies" and tenant object blobs in
	// "<DataDir>/tpm-keys", outside the barrier: boot-time auto-unseal reads
	// the registry before the barrier is open, and everything in it is
	// either public policy metadata or sealed by the TPM.
	DataDir string

	// OpenStore opens the store rooted at a directory.
	OpenStore func(dir string) (xkms.StorageBackend, error)

	// Accessor, when set, serializes every operation with the other users
	// of the TPM (the GUI shares one TPM between its services).
	Accessor *TPMAccessor

	// Logger receives the service's lifecycle events. Nil selects
	// slog.Default().
	Logger *slog.Logger
}

// LocalTPMPolicies is the TPM policy service running in-process over xKey's
// own TPM, in the system scope, and the stores it owns. Its TPM policy API
// operations are the SDK's TenantTPMPolicies for the system scope -- the
// conversion xkmsd serves -- serialized with the TPM's other users.
type LocalTPMPolicies struct {
	svc *xkms.TPMPolicyService

	// policies serves the TPM policy API operations in the system scope.
	policies *xkms.TenantTPMPolicies

	// backend is the TPM2 key backend the service was built over, with the
	// service installed as its scope provider: it seals the local sealed
	// objects in the system scope and records their assignments.
	backend *xkms.TPM2Backend

	stores   []xkms.StorageBackend
	accessor *TPMAccessor
}

// OpenLocalTPMPolicies builds the TPM policy service over xKey's TPM exactly
// as xkmsd does (xkms.BuildTPMPolicyService), with its stores under
// p.DataDir.
func OpenLocalTPMPolicies(p LocalTPMPolicyParams) (*LocalTPMPolicies, error) {
	switch {
	case p.TPM == nil:
		return nil, ErrLocalTPMPolicyNoTPM
	case p.Keys == nil:
		return nil, ErrLocalTPMPolicyNoKeys
	case p.DataDir == "":
		return nil, ErrLocalTPMPolicyNoDataDir
	case p.OpenStore == nil:
		return nil, ErrLocalTPMPolicyNoStoreOpener
	}
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	backend, err := xkms.NewTPM2BackendWithTPM(&xkms.TPM2BackendExternalConfig{
		TPM:        p.TPM,
		KeyBackend: p.Keys,
		Logger:     logger,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLocalTPMPolicyBuildFailed, Cause: err}
	}
	l := &LocalTPMPolicies{accessor: p.Accessor}
	svc, err := xkms.BuildTPMPolicyService(xkms.TPMPolicyParams{
		Backend: backend,
		Storage: func(name string) (xkms.StorageBackend, error) {
			store, openErr := p.OpenStore(filepath.Join(p.DataDir, name))
			if openErr != nil {
				return nil, openErr
			}
			l.stores = append(l.stores, store)
			return store, nil
		},
		Logger: logger,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLocalTPMPolicyBuildFailed, Cause: errors.Join(err, l.closeStores())}
	}
	policies, err := xkms.NewTenantTPMPolicies(svc, localScope)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLocalTPMPolicyBuildFailed, Cause: errors.Join(err, svc.Close(), l.closeStores())}
	}
	l.svc = svc
	l.policies = policies
	l.backend = backend
	return l, nil
}

// Service returns the in-process TPM policy service.
func (l *LocalTPMPolicies) Service() *xkms.TPMPolicyService {
	return l.svc
}

// Close closes the service, which removes it from the TPM, and its stores.
func (l *LocalTPMPolicies) Close() error {
	return errors.Join(l.svc.Close(), l.closeStores())
}

// closeStores closes every store the service opened.
func (l *LocalTPMPolicies) closeStores() error {
	var errs []error
	for _, store := range l.stores {
		errs = append(errs, store.Close())
	}
	l.stores = nil
	return errors.Join(errs...)
}

// lock serializes an operation with the TPM's other users. The returned
// function releases it.
func (l *LocalTPMPolicies) lock() (func(), error) {
	if l.accessor == nil {
		return func() {}, nil
	}
	if _, err := l.accessor.Acquire(); err != nil {
		return nil, err
	}
	return l.accessor.Release, nil
}

// Assign records that the local object of kind ("key" or "sealed") named
// name was created under policy ("" is the platform policy).
func (l *LocalTPMPolicies) Assign(ctx context.Context, kind, name, policy string) error {
	objectKind, err := xkms.ParseTPMObjectKind(kind)
	if err != nil {
		return err
	}
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return l.svc.Assign(ctx, localScope, objectKind, name, policy, nil)
}

// Unassign removes the local object's assignment; an object with none is
// not an error.
func (l *LocalTPMPolicies) Unassign(ctx context.Context, kind, name string) error {
	objectKind, err := xkms.ParseTPMObjectKind(kind)
	if err != nil {
		return err
	}
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return l.svc.Unassign(ctx, localScope, objectKind, name)
}

// AutoUnsealPolicy returns the name of the policy carrying the auto-unseal
// mark, or xkms.ErrTPMPolicyNotFound when none does.
func (l *LocalTPMPolicies) AutoUnsealPolicy(ctx context.Context) (string, error) {
	unlock, err := l.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	p, err := l.svc.AutoUnsealPolicy(ctx, localScope)
	if err != nil {
		return "", err
	}
	return p.Name, nil
}

// sealedObjectAttrs returns the attributes of the local sealed object name in
// the system scope, bound to policy.
func sealedObjectAttrs(name, policy string) *xkms.KeyAttributes {
	return &xkms.KeyAttributes{
		CN:        name,
		StoreType: xkms.StoreTPM2,
		TPMPolicy: policy,
	}
}

// SealObject seals data in the TPM as the local sealed object name,
// replacing any object of that name, bound to policy: a named policy, the
// built-in "platform" policy, or "" for none. An object bound to a named
// policy and no password answers only to the policy's approved PCR state,
// and its assignment is recorded, so the policy cannot be deleted under it.
func (l *LocalTPMPolicies) SealObject(ctx context.Context, name, policy string, data []byte) error {
	if name == "" {
		return ErrTPMObjectNameRequired
	}
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	_, err = l.backend.Seal(ctx, data, &xkms.SealOptions{KeyAttributes: sealedObjectAttrs(name, policy)})
	return err
}

// UnsealObject returns the data of the local sealed object name. The TPM
// authorizes the unseal through the policy the object was sealed under; for
// a named policy that is a policy session proving the approved PCR state,
// so it fails once the PCRs drift from it or the policy is revoked.
//
// The object is loaded from the scope's key store by name, never from
// caller-held blobs, so its recorded policy binding is always the one used.
func (l *LocalTPMPolicies) UnsealObject(ctx context.Context, name string) ([]byte, error) {
	if name == "" {
		return nil, ErrTPMObjectNameRequired
	}
	unlock, err := l.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return l.backend.Unseal(ctx,
		&xkms.SealedData{Backend: xkms.BackendTypeTPM2, KeyID: name},
		&xkms.UnsealOptions{KeyAttributes: sealedObjectAttrs(name, "")})
}

// DeleteObject removes the local sealed object name and its assignment. It
// does not unseal the object first, so it succeeds after the PCRs have
// drifted from its policy; an object that does not exist is not an error.
func (l *LocalTPMPolicies) DeleteObject(ctx context.Context, name string) error {
	if name == "" {
		return ErrTPMObjectNameRequired
	}
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	keys, err := l.svc.KeyStore(localScope)
	if err != nil {
		return err
	}
	if err := keys.Delete(sealedObjectAttrs(name, "")); err != nil && !isNotFound(err) {
		return err
	}
	return l.svc.Unassign(ctx, localScope, xkms.TPMObjectSealed, name)
}

// isNotFound reports whether err means a stored object does not exist.
func isNotFound(err error) bool {
	return errors.Is(err, xkms.ErrStorageNotFound) || errors.Is(err, fs.ErrNotExist)
}

// Compile-time check that the local service serves the same operations as a
// connected xkmsd.
var _ tpmPolicyBackend = (*LocalTPMPolicies)(nil)

// locked runs op, one of the system scope's TPM policy API operations, with
// the TPM held.
func locked[Req, Resp any](ctx context.Context, l *LocalTPMPolicies, req Req,
	op func(*xkms.TenantTPMPolicies, context.Context, Req) (Resp, error)) (Resp, error) {

	unlock, err := l.lock()
	if err != nil {
		var zero Resp
		return zero, err
	}
	defer unlock()
	return op(l.policies, ctx, req)
}

// TPMPolicyCreate creates a named policy of the request's branches over the
// live PCR values of xKey's TPM.
func (l *LocalTPMPolicies) TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyCreate)
}

// TPMPolicyGet returns a named policy.
func (l *LocalTPMPolicies) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyGet)
}

// TPMPolicyUpdate re-captures a policy's PCR values and re-approves it.
func (l *LocalTPMPolicies) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyUpdate)
}

// TPMPolicyRevoke withdraws a policy's approval.
func (l *LocalTPMPolicies) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyRevoke)
}

// TPMPolicyList returns the named policies, sorted by name.
func (l *LocalTPMPolicies) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyList)
}

// TPMPolicyVerify compares a policy's captured PCR values with the live ones.
func (l *LocalTPMPolicies) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyVerify)
}

// TPMPolicyDelete deletes a policy no object is assigned to.
func (l *LocalTPMPolicies) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return l.policies.TPMPolicyDelete(ctx, req)
}

// TPMPolicyObjects lists the objects assigned to a policy.
func (l *LocalTPMPolicies) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyObjects)
}

// TPMPolicySetAutoUnseal sets or clears a policy's auto-unseal mark.
func (l *LocalTPMPolicies) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicySetAutoUnseal)
}

// TPMPolicySetDescription replaces a policy's description.
func (l *LocalTPMPolicies) TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicySetDescription)
}

// TPMObjectPolicy returns the policy a local key or sealed object was
// created under. KeyID is a key ID or a bare object name.
func (l *LocalTPMPolicies) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMObjectPolicy)
}

// TPMPolicyRotateAuthority replaces the system scope's policy authority.
func (l *LocalTPMPolicies) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyRotateAuthority)
}
