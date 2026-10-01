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

// Package localtpm is the TPM policy service a client runs in-process over
// the host's own TPM: the named-policy registry, the policy authority, the
// policies' NV indexes and the approval counter, in the system scope, built
// exactly as xkmsd builds them. xkey (its GUI and CLI) and xkmsctl both run
// it, so a key or sealed object made under a named policy by one is the
// same object to the other.
package localtpm

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Errors.
var (
	// ErrNoTPM indicates Open was given no TPM.
	ErrNoTPM = errors.New("localtpm: local mode needs a TPM")

	// ErrNoKeys indicates Open was given no key store for the TPM's own
	// objects.
	ErrNoKeys = errors.New("localtpm: local mode needs the TPM's key store")

	// ErrNoDataDir indicates Open was given no data directory to keep the
	// policy registry in.
	ErrNoDataDir = errors.New("localtpm: local mode needs a data directory")

	// ErrNoStoreOpener indicates Open was given no function to open its
	// stores with.
	ErrNoStoreOpener = errors.New("localtpm: local mode needs a store opener")

	// ErrObjectNameRequired indicates a sealed-object operation without a
	// name.
	ErrObjectNameRequired = errors.New("localtpm: sealed object name is required")
)

// BuildError reports a TPM policy service that could not be built over the
// TPM.
type BuildError struct {
	Err error
}

// Error implements the error interface.
func (e *BuildError) Error() string {
	return "localtpm: failed to build the local TPM policy service: " + e.Err.Error()
}

// Unwrap returns the underlying failure.
func (e *BuildError) Unwrap() error { return e.Err }

// localScope is the tenant every local operation acts on: a client owns one
// TPM and keeps all of its objects in the system scope.
const localScope = ""

// Params are the dependencies of the TPM policy service a client runs
// in-process over its own TPM.
type Params struct {
	// TPM is the host's TPM. The service installs itself as its policy binding
	// resolver, so every key and sealed object created on it can name a
	// policy.
	TPM tpm2.TrustedPlatformModule

	// Keys is the TPM's own key store: the system scope's objects (its
	// policy authority and sealed scope secrets) live there.
	Keys store.KeyBackend

	// DataDir is the client's data directory. The policy registry is kept in
	// "<DataDir>/tpm-policies" and tenant object blobs in
	// "<DataDir>/tpm-keys", outside the barrier: boot-time auto-unseal reads
	// the registry before the barrier is open, and everything in it is
	// either public policy metadata or sealed by the TPM.
	DataDir string

	// OpenStore opens the store rooted at a directory.
	OpenStore func(dir string) (storage.Backend, error)

	// Lock, when set, serializes every operation with the other users of
	// the TPM (the xkey GUI shares one TPM between its services); it
	// returns the function that releases it.
	Lock func() (func(), error)

	// Logger receives the service's lifecycle events. Nil selects
	// slog.Default().
	Logger *slog.Logger
}

// Policies is the TPM policy service running in-process over the host's own
// TPM, in the system scope, and the stores it owns: the policy registry,
// the policy authority, the policies' NV indexes and the approval counter,
// exactly as xkmsd runs them (compose.BuildTPMPolicyService). Its TPM
// policy API operations are TenantTPMPolicies for the system scope -- the
// conversion xkmsd serves -- serialized with the TPM's other users.
type Policies struct {
	svc *tpmpolicy.Service

	// policies serves the TPM policy API operations in the system scope.
	policies *xkms.TenantTPMPolicies

	// backend is the TPM2 key backend the service was built over, with the
	// service installed as its scope provider: it creates keys and seals
	// objects in the system scope under named policies and records their
	// assignments.
	backend *tpm2backend.Backend

	stores []storage.Backend
	lockFn func() (func(), error)
}

// Open builds the TPM policy service over the host's TPM exactly as xkmsd
// does (compose.BuildTPMPolicyService), with its stores under p.DataDir.
func Open(p Params) (*Policies, error) {
	switch {
	case p.TPM == nil:
		return nil, ErrNoTPM
	case p.Keys == nil:
		return nil, ErrNoKeys
	case p.DataDir == "":
		return nil, ErrNoDataDir
	case p.OpenStore == nil:
		return nil, ErrNoStoreOpener
	}
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	backend, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
		TPM:        p.TPM,
		KeyBackend: p.Keys,
		Logger:     logger,
	})
	if err != nil {
		return nil, &BuildError{Err: err}
	}
	l := &Policies{lockFn: p.Lock}
	svc, err := compose.BuildTPMPolicyService(compose.TPMPolicyParams{
		Backend: backend,
		Storage: func(name string) (storage.Backend, error) {
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
		return nil, &BuildError{Err: errors.Join(err, l.closeStores())}
	}
	policies, err := xkms.NewTenantTPMPolicies(svc, localScope)
	if err != nil {
		return nil, &BuildError{Err: errors.Join(err, svc.Close(), l.closeStores())}
	}
	l.svc = svc
	l.policies = policies
	l.backend = backend
	return l, nil
}

// Service returns the in-process TPM policy service.
func (l *Policies) Service() *tpmpolicy.Service {
	return l.svc
}

// Backend returns the TPM 2.0 key backend the service runs over. Keys it
// creates in the system scope are bound to the policy their attributes name
// (TPMPolicy) and their assignment is recorded, so the TPM enforces the
// policy and the policy cannot be deleted under them.
func (l *Policies) Backend() *tpm2backend.Backend {
	return l.backend
}

// Close closes the service, which removes it from the TPM, and its stores.
func (l *Policies) Close() error {
	return errors.Join(l.svc.Close(), l.closeStores())
}

// closeStores closes every store the service opened.
func (l *Policies) closeStores() error {
	var errs []error
	for _, store := range l.stores {
		errs = append(errs, store.Close())
	}
	l.stores = nil
	return errors.Join(errs...)
}

// lock serializes an operation with the TPM's other users. The returned
// function releases it.
func (l *Policies) lock() (func(), error) {
	if l.lockFn == nil {
		return func() {}, nil
	}
	return l.lockFn()
}

// Assign records that the local object of kind ("key" or "sealed") named
// name was created under policy ("" is the platform policy).
func (l *Policies) Assign(ctx context.Context, kind, name, policy string) error {
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
func (l *Policies) Unassign(ctx context.Context, kind, name string) error {
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
func (l *Policies) AutoUnsealPolicy(ctx context.Context) (string, error) {
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
func sealedObjectAttrs(name, policy string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:        name,
		StoreType: types.StoreTPM2,
		TPMPolicy: policy,
	}
}

// SealObject seals data in the TPM as the local sealed object name,
// replacing any object of that name, bound to policy: a named policy, the
// built-in "platform" policy, or "" for none. An object bound to a named
// policy and no password answers only to the policy's approved PCR state,
// and its assignment is recorded, so the policy cannot be deleted under it.
func (l *Policies) SealObject(ctx context.Context, name, policy string, data []byte) error {
	if name == "" {
		return ErrObjectNameRequired
	}
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	_, err = l.backend.Seal(ctx, data, &types.SealOptions{KeyAttributes: sealedObjectAttrs(name, policy)})
	return err
}

// UnsealObject returns the data of the local sealed object name. The TPM
// authorizes the unseal through the policy the object was sealed under; for
// a named policy that is a policy session proving the approved PCR state,
// so it fails once the PCRs drift from it or the policy is revoked.
//
// The object is loaded from the scope's key store by name, never from
// caller-held blobs, so its recorded policy binding is always the one used.
func (l *Policies) UnsealObject(ctx context.Context, name string) ([]byte, error) {
	if name == "" {
		return nil, ErrObjectNameRequired
	}
	unlock, err := l.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return l.backend.Unseal(ctx,
		&types.SealedData{Backend: types.BackendTypeTPM2, KeyID: name},
		&types.UnsealOptions{KeyAttributes: sealedObjectAttrs(name, "")})
}

// DeleteObject removes the local sealed object name and its assignment. It
// does not unseal the object first, so it succeeds after the PCRs have
// drifted from its policy; an object that does not exist is not an error.
func (l *Policies) DeleteObject(ctx context.Context, name string) error {
	if name == "" {
		return ErrObjectNameRequired
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
	return l.svc.Unassign(ctx, localScope, tpmpolicy.ObjectSealed, name)
}

// isNotFound reports whether err means a stored object does not exist.
func isNotFound(err error) bool {
	return errors.Is(err, storage.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}

// locked runs op, one of the system scope's TPM policy API operations, with
// the TPM held.
func locked[Req, Resp any](ctx context.Context, l *Policies, req Req,
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
func (l *Policies) TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyCreate)
}

// TPMPolicyGet returns a named policy.
func (l *Policies) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyGet)
}

// TPMPolicyUpdate re-captures a policy's PCR values and re-approves it.
func (l *Policies) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyUpdate)
}

// TPMPolicyRevoke withdraws a policy's approval.
func (l *Policies) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyRevoke)
}

// TPMPolicyList returns the named policies, sorted by name.
func (l *Policies) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyList)
}

// TPMPolicyVerify compares a policy's captured PCR values with the live ones.
func (l *Policies) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyVerify)
}

// TPMPolicyDelete deletes a policy no object is assigned to.
func (l *Policies) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return l.policies.TPMPolicyDelete(ctx, req)
}

// TPMPolicyObjects lists the objects assigned to a policy.
func (l *Policies) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyObjects)
}

// TPMPolicySetAutoUnseal sets or clears a policy's auto-unseal mark.
func (l *Policies) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicySetAutoUnseal)
}

// TPMPolicySetDescription replaces a policy's description.
func (l *Policies) TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicySetDescription)
}

// TPMObjectPolicy returns the policy a local key or sealed object was
// created under. KeyID is a key ID or a bare object name.
func (l *Policies) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMObjectPolicy)
}

// TPMPolicyRotateAuthority replaces the system scope's policy authority.
func (l *Policies) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return locked(ctx, l, req, (*xkms.TenantTPMPolicies).TPMPolicyRotateAuthority)
}
