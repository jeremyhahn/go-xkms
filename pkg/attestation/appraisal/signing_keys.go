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

package appraisal

import (
	"context"
	"crypto"
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
)

// ReleaseSigningKeyID is the key ID of a tenant's release signing key, the
// default signer of the tenant's images and CoRIM (SPEC release-signing-key).
// Keys are tenant-scoped, so like an OTA board's image key the ID is a
// function of the key's use alone: every tenant's release key has this ID in
// its own key namespace.
const ReleaseSigningKeyID = "release-signing"

const (
	// maxRepositoryLen bounds a repository path to the 255 bytes registries
	// accept for a whole image name.
	maxRepositoryLen = 255

	// signingKeyBindingKind names the record kind in a *RecordNotFoundError.
	signingKeyBindingKind = "signing-key binding"
)

// SigningKeyBinding names the key that signs one of a tenant's repositories,
// in place of the tenant's release key.
type SigningKeyBinding struct {
	// Repository is the OCI repository path, as in "org/app".
	Repository string `json:"repository"`

	// KeyID is the tenant key that signs the repository's images and CoRIM.
	KeyID string `json:"key_id"`

	// Backend is the key's backend; empty is the tenant's default backend.
	Backend string `json:"backend,omitempty"`

	// UpdatedAt is when the binding was last set.
	UpdatedAt time.Time `json:"updated_at"`
}

// SetSigningKeyBindingRequest binds (or rebinds) a repository to a key.
type SetSigningKeyBindingRequest struct {
	Repository string `json:"repository"`
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend,omitempty"`
}

// GetSigningKeyBindingRequest names a repository's binding.
type GetSigningKeyBindingRequest struct {
	Repository string `json:"repository"`
}

// ListSigningKeyBindingsResponse lists a tenant's bindings, ordered by
// repository.
type ListSigningKeyBindingsResponse struct {
	Bindings []*SigningKeyBinding `json:"bindings"`
}

// DeleteSigningKeyBindingRequest removes a repository's binding, returning
// the repository to the release key.
type DeleteSigningKeyBindingRequest struct {
	Repository string `json:"repository"`
}

// ResolveSigningKeyRequest names the repository whose signing key to
// resolve.
type ResolveSigningKeyRequest struct {
	Repository string `json:"repository"`
}

// SigningKeyResolution is the key that signs a repository.
type SigningKeyResolution struct {
	Repository string `json:"repository"`
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend,omitempty"`

	// Default is true when no binding names the repository, so the key is
	// the tenant's release key.
	Default bool `json:"default"`
}

// ValidateRepository applies the binding-name rule: a repository is an OCI
// repository path of at most 255 bytes. It returns a *RepositoryError.
func ValidateRepository(repository string) error {
	if len(repository) > maxRepositoryLen || !validation.ValidOCIRepository(repository) {
		return &RepositoryError{Repository: repository}
	}
	return nil
}

// validateSigningKey checks a binding's key ID and optional backend name.
func validateSigningKey(req *SetSigningKeyBindingRequest) error {
	if err := validation.ValidateKeyID(req.KeyID); err != nil {
		return &SigningKeyError{KeyID: req.KeyID, Cause: err}
	}
	if req.Backend == "" {
		return nil
	}
	if err := validation.ValidateBackendName(req.Backend); err != nil {
		return &SigningKeyError{KeyID: req.KeyID, Cause: err}
	}
	return nil
}

// SetSigningKeyBinding binds one of the tenant's repositories to a key, so
// the repository's images and CoRIM verify against that key and no longer
// against the release key. Setting a repository again replaces its binding.
func (a *Appraiser) SetSigningKeyBinding(ctx context.Context, tenant string, req *SetSigningKeyBindingRequest) (*SigningKeyBinding, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := ValidateRepository(req.Repository); err != nil {
		return nil, err
	}
	if err := validateSigningKey(req); err != nil {
		return nil, err
	}
	binding := &SigningKeyBinding{
		Repository: req.Repository,
		KeyID:      req.KeyID,
		Backend:    req.Backend,
		UpdatedAt:  a.now().UTC(),
	}
	if err := a.store.PutSigningKeyBinding(ctx, tenant, binding); err != nil {
		return nil, err
	}
	return binding, nil
}

// GetSigningKeyBinding returns the binding of one of the tenant's
// repositories. A repository with none is a *RecordNotFoundError.
func (a *Appraiser) GetSigningKeyBinding(ctx context.Context, tenant string, req *GetSigningKeyBindingRequest) (*SigningKeyBinding, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return a.store.GetSigningKeyBinding(ctx, tenant, req.Repository)
}

// ListSigningKeyBindings lists the tenant's bindings, ordered by repository.
func (a *Appraiser) ListSigningKeyBindings(ctx context.Context, tenant string) (*ListSigningKeyBindingsResponse, error) {
	bindings, err := a.store.ListSigningKeyBindings(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return &ListSigningKeyBindingsResponse{Bindings: bindings}, nil
}

// DeleteSigningKeyBinding removes the binding of one of the tenant's
// repositories, returning it to the release key. A repository with none is
// a *RecordNotFoundError.
func (a *Appraiser) DeleteSigningKeyBinding(ctx context.Context, tenant string, req *DeleteSigningKeyBindingRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return a.store.DeleteSigningKeyBinding(ctx, tenant, req.Repository)
}

// ResolveSigningKey returns the key that signs one of the tenant's
// repositories: the bound key when a binding names the repository,
// otherwise the tenant's release key.
func (a *Appraiser) ResolveSigningKey(ctx context.Context, tenant string, req *ResolveSigningKeyRequest) (*SigningKeyResolution, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	binding, err := a.store.GetSigningKeyBinding(ctx, tenant, req.Repository)
	if errors.Is(err, ErrRecordNotFound) {
		return &SigningKeyResolution{Repository: req.Repository, KeyID: ReleaseSigningKeyID, Default: true}, nil
	}
	if err != nil {
		return nil, err
	}
	return &SigningKeyResolution{Repository: binding.Repository, KeyID: binding.KeyID, Backend: binding.Backend}, nil
}

// SigningKeySource returns the public half of a tenant's signing key. The
// key service that holds the tenant's keys implements it; the Appraiser
// only ever sees public keys.
type SigningKeySource interface {
	SigningPublicKey(ctx context.Context, tenant string, key *SigningKeyResolution) (crypto.PublicKey, error)
}

// WithSigningKeySource sets the source of the public keys that verify a
// repository's signatures. Without one, verifying a repository's signature
// is a *ConfigError.
func WithSigningKeySource(source SigningKeySource) Option {
	return func(a *Appraiser) { a.signingKeys = source }
}

// RepositorySigningKey resolves the key that signs one of the tenant's
// repositories and returns it with its public half.
func (a *Appraiser) RepositorySigningKey(ctx context.Context, tenant, repository string) (*SigningKeyResolution, crypto.PublicKey, error) {
	if a.signingKeys == nil {
		return nil, nil, &ConfigError{Field: "signing key source", Reason: "is required to verify a repository's signatures"}
	}
	resolution, err := a.ResolveSigningKey(ctx, tenant, &ResolveSigningKeyRequest{Repository: repository})
	if err != nil {
		return nil, nil, err
	}
	key, err := a.signingKeys.SigningPublicKey(ctx, tenant, resolution)
	if err != nil {
		return nil, nil, err
	}
	return resolution, key, nil
}

// TenantSigningKeys returns the signing keys of one tenant's repositories,
// in the shape an image verifier resolves a repository's key through
// (image.SigningKeyResolver).
func (a *Appraiser) TenantSigningKeys(tenant string) *TenantSigningKeys {
	return &TenantSigningKeys{appraiser: a, tenant: tenant}
}

// TenantSigningKeys resolves the public key that signs each of one tenant's
// repositories.
type TenantSigningKeys struct {
	appraiser *Appraiser
	tenant    string
}

// SigningKey returns the public key that signs the repository: its bound
// key, or else the tenant's release key.
func (k *TenantSigningKeys) SigningKey(ctx context.Context, repository string) (crypto.PublicKey, error) {
	_, key, err := k.appraiser.RepositorySigningKey(ctx, k.tenant, repository)
	return key, err
}

// verifyRepositoryCoRIM verifies a repository's signed CoRIM under the
// repository's signing key alone. A CoRIM no other key may sign is refused
// with a *SignerRefusedError, as the Cause of a *ReferenceValuesRejectedError.
func (a *Appraiser) verifyRepositoryCoRIM(ctx context.Context, tenant, repository string, signed []byte) (*refvalue.Manifest, error) {
	resolution, key, err := a.RepositorySigningKey(ctx, tenant, repository)
	if err != nil {
		return nil, err
	}
	manifest, err := refvalue.VerifySigned(signed, refvalue.VerifyOptions{PublicKey: key, Now: a.now()})
	if err != nil {
		refused := &SignerRefusedError{Repository: repository, KeyID: resolution.KeyID, Cause: err}
		return nil, &ReferenceValuesRejectedError{Reason: refused.Error(), Cause: refused}
	}
	return manifest, nil
}

// verifyReferenceValues verifies signed reference values: a repository's
// under its signing key, the rest against the tenant's reference-signer
// endorsements.
func (a *Appraiser) verifyReferenceValues(ctx context.Context, tenant, repository string, signed []byte) (*refvalue.Manifest, error) {
	if repository != "" {
		return a.verifyRepositoryCoRIM(ctx, tenant, repository, signed)
	}
	return a.verifyCoRIM(ctx, tenant, signed)
}
