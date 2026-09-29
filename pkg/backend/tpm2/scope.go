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

package tpm2

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"

	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ScopeProvider resolves where a tenant's TPM objects live and records which
// named policy each object was created under. *tpmpolicy.Service satisfies
// it; with one installed (SetScopeProvider) every key and seal operation runs
// in the scope KeyAttributes.TenantID selects.
type ScopeProvider interface {
	// ScopeTPM opens tenant's scope ("" or "system" is the system scope).
	// The caller closes the result when the operation ends.
	ScopeTPM(ctx context.Context, tenant string) (*tpmpolicy.ScopeTPM, error)

	// KeyStore returns tenant's key store without opening the scope.
	KeyStore(tenant string) (store.KeyBackend, error)

	// Scopes lists every scope with a record.
	Scopes(ctx context.Context) ([]string, error)

	// Assign, Unassign and Assignments maintain and read the registry of
	// which policy each object of a scope was created under.
	Assign(ctx context.Context, tenant string, kind tpmpolicy.ObjectKind, name, policy string, authPolicy []byte) error
	Unassign(ctx context.Context, tenant string, kind tpmpolicy.ObjectKind, name string) error
	Assignments(ctx context.Context, tenant string) ([]*tpmpolicy.Assignment, error)
}

// Compile-time check that the policy service is a scope provider.
var _ ScopeProvider = (*tpmpolicy.Service)(nil)

var (
	// ErrReservedObject is returned for a key operation that names an object
	// the TPM policy service keeps for itself (a scope's storage key, policy
	// authority, sealed secrets or vTPM state key).
	ErrReservedObject = errors.New("tpm2: the name is reserved for a TPM policy service object")

	// ErrTenantSymmetricKeyUnsupported is returned for a symmetric key
	// operation of a tenant in shared TPM mode: the TPM seals symmetric keys
	// under the Platform SRK only, which a shared tenant does not own. A vtpm
	// tenant's symmetric keys live under its own vTPM's Platform SRK.
	ErrTenantSymmetricKeyUnsupported = errors.New("tpm2: symmetric keys are not available to a tenant in shared TPM mode")

	// ErrTenantImportUnsupported is returned for ImportKey in a tenant scope:
	// a duplicate is imported under the Platform SRK, which a tenant scope's
	// objects are not parented to.
	ErrTenantImportUnsupported = errors.New("tpm2: key import is not available in a tenant TPM scope")
)

// ScopeError wraps a failure to open a tenant's TPM scope.
type ScopeError struct {
	Tenant string
	Err    error
}

// Error implements the error interface.
func (e *ScopeError) Error() string {
	return fmt.Sprintf("tpm2: TPM scope of tenant %q: %v", tpmpolicy.ScopeName(e.Tenant), e.Err)
}

// Unwrap returns the underlying cause.
func (e *ScopeError) Unwrap() error { return e.Err }

// AssignmentError wraps a failure to record or remove an object's policy
// assignment.
type AssignmentError struct {
	Tenant string
	Object string
	Err    error
}

// Error implements the error interface.
func (e *AssignmentError) Error() string {
	return fmt.Sprintf("tpm2: TPM policy assignment of %q in tenant %q: %v", e.Object, tpmpolicy.ScopeName(e.Tenant), e.Err)
}

// Unwrap returns the underlying cause.
func (e *AssignmentError) Unwrap() error { return e.Err }

// SetScopeProvider installs the provider that routes every key and seal
// operation to the TPM scope of KeyAttributes.TenantID. Nil restores the
// single-scope behaviour: every object on the backend's own TPM, key store
// and Platform SRK.
func (b *Backend) SetScopeProvider(p ScopeProvider) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scopes = p
}

// TenantBoundSealing reports whether a sealed object is bound to the tenant
// that sealed it. It is true with a scope provider, which seals each
// tenant's objects under that tenant's own storage parent.
func (b *Backend) TenantBoundSealing() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.scopes != nil
}

// isSystemTenant reports whether tenant names the system scope.
func isSystemTenant(tenant string) bool {
	return tpmpolicy.ScopeName(tenant) == tpmpolicy.ScopeName("")
}

// keyScope is the TPM scope one operation runs in: the TPM, the key store and
// the storage parent of its objects.
type keyScope struct {
	// tenant is the scope's tenant ID; "" for the system scope.
	tenant string

	tpm    pkgtpm2.TrustedPlatformModule
	keys   store.KeyBackend
	parent *types.KeyAttributes

	// shared marks a tenant scope on the backend's own (physical) TPM,
	// whose parent is a tenant storage key rather than a Platform SRK.
	shared bool

	// scoped reports that a scope provider resolved the scope.
	scoped bool

	// release closes the ScopeTPM; nil without a scope provider.
	release func() error
}

// close releases the scope's loaded parent.
func (s *keyScope) close() error {
	if s.release == nil {
		return nil
	}
	return s.release()
}

// scope resolves the TPM scope of tenant. Without a scope provider it is the
// backend's own TPM, key store and Platform SRK, as before scopes existed.
// The caller holds b.mu and closes the result.
func (b *Backend) scope(ctx context.Context, tenant string) (*keyScope, error) {
	if b.scopes == nil {
		return &keyScope{tpm: b.tpm, keys: b.keyBackend, parent: b.srkAttrs}, nil
	}
	st, err := b.scopes.ScopeTPM(ctx, tenant)
	if err != nil {
		return nil, &ScopeError{Tenant: tenant, Err: err}
	}
	s := &keyScope{
		tpm:     st.TPM,
		keys:    st.Keys,
		parent:  st.Parent,
		scoped:  true,
		release: st.Close,
	}
	if !isSystemTenant(tenant) {
		s.tenant = tenant
		s.shared = pkgtpm2.TrustedPlatformModule(st.TPM) == b.tpm
	}
	return s, nil
}

// bind returns the attributes an operation in s presents to the TPM. In the
// system scope they are attrs itself, parented to the Platform SRK when the
// caller named no parent, exactly as before scopes existed. In a tenant scope
// they are a copy parented to the scope's storage parent, whose handle is
// only valid while the scope is open, so the caller's attributes never keep
// it.
func (s *keyScope) bind(attrs *types.KeyAttributes) *types.KeyAttributes {
	if s.tenant == "" {
		if attrs.Parent == nil {
			attrs.Parent = s.parent
		}
		return attrs
	}
	bound := *attrs
	bound.Parent = s.parent
	return &bound
}

// refuseSymmetric refuses a symmetric key operation the scope cannot serve.
func (s *keyScope) refuseSymmetric() error {
	if s.shared {
		return ErrTenantSymmetricKeyUnsupported
	}
	return nil
}

// refuseReserved refuses attrs naming an object the policy service owns.
func (b *Backend) refuseReserved(attrs *types.KeyAttributes) error {
	if b.scopes != nil && tpmpolicy.IsReservedObject(attrs.CN) {
		return &ReservedObjectError{CN: attrs.CN}
	}
	return nil
}

// ReservedObjectError reports a key operation that named a TPM policy
// service object. It unwraps to ErrReservedObject.
type ReservedObjectError struct {
	CN string
}

// Error implements the error interface.
func (e *ReservedObjectError) Error() string {
	return fmt.Sprintf("%v: %q", ErrReservedObject, e.CN)
}

// Unwrap returns ErrReservedObject.
func (e *ReservedObjectError) Unwrap() error { return ErrReservedObject }

// authPolicyOf returns the authPolicy digest recorded in the public area of
// the object attrs names in keys.
func authPolicyOf(keys store.KeyBackend, attrs *types.KeyAttributes) ([]byte, error) {
	public, err := keys.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		return nil, err
	}
	return publicAuthPolicy(public)
}

// publicAuthPolicy returns the authPolicy digest of a marshaled TPMT_PUBLIC.
func publicAuthPolicy(public []byte) ([]byte, error) {
	area := tpm2.BytesAs2B[tpm2.TPMTPublic](public)
	contents, err := area.Contents()
	if err != nil {
		return nil, err
	}
	return contents.AuthPolicy.Buffer, nil
}

// assign records the policy the object attrs names was created under. It is
// a no-op without a scope provider.
func (b *Backend) assign(ctx context.Context, s *keyScope, kind tpmpolicy.ObjectKind, attrs *types.KeyAttributes, authPolicy []byte) error {
	if !s.scoped {
		return nil
	}
	if err := b.scopes.Assign(ctx, s.tenant, kind, attrs.CN, attrs.TPMPolicy, authPolicy); err != nil {
		return &AssignmentError{Tenant: s.tenant, Object: tpmpolicy.ObjectID(kind, attrs.CN), Err: err}
	}
	return nil
}

// unassign removes every assignment recorded for the object attrs names. A
// key and a sealed object share their scope's key-store namespace, so
// deleting a name's blobs removes whichever object it held.
func (b *Backend) unassign(ctx context.Context, s *keyScope, attrs *types.KeyAttributes) error {
	if !s.scoped {
		return nil
	}
	var errs []error
	for _, kind := range []tpmpolicy.ObjectKind{tpmpolicy.ObjectKey, tpmpolicy.ObjectSealed} {
		if err := b.scopes.Unassign(ctx, s.tenant, kind, attrs.CN); err != nil {
			errs = append(errs, &AssignmentError{Tenant: s.tenant, Object: tpmpolicy.ObjectID(kind, attrs.CN), Err: err})
		}
	}
	return errors.Join(errs...)
}
