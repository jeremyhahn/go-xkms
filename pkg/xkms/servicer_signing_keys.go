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

package xkms

import (
	"context"
	"crypto"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// The per-repository signing-key binding service layer (SPEC
// release-signing-key, go-xkms#1697). A tenant's images and CoRIM are signed
// by its release key (appraisal.ReleaseSigningKeyID) unless a binding names
// another key for the repository. Like the other Verifier methods, each acts
// on the caller's tenant and returns ErrNotConfigured when no Appraiser is
// wired.
//
// Changing a binding redirects every verification of the repository to
// another key, and reading one reveals which key signs it, so every method
// checks its attestation_signing_keys:* permission here as well as at the
// wire gate: an in-process caller composing the service through sdk/go meets
// the same refusal as a remote one.

// ErrSigningKeyForbidden is a signing-key call by a caller that does not
// hold the attestation_signing_keys:* permission it requires.
var ErrSigningKeyForbidden = errors.New("attestation: caller may not use the signing-key binding")

// SigningKeyPermissionError refuses a signing-key call by a caller without
// the permission it requires. It matches ErrSigningKeyForbidden and the
// authorizer's own refusal under errors.Is.
type SigningKeyPermissionError struct {
	// Permission is the resource:action the call requires.
	Permission string
	// Err is the authorizer's refusal.
	Err error
}

// Error reports the permission and the refusal.
func (e *SigningKeyPermissionError) Error() string {
	return "attestation: the signing-key call requires " + e.Permission + ": " + e.Err.Error()
}

// Unwrap returns ErrSigningKeyForbidden and the authorizer's refusal.
func (e *SigningKeyPermissionError) Unwrap() []error {
	return []error{ErrSigningKeyForbidden, e.Err}
}

// authorizeSigningKeys refuses a caller that does not hold
// attestation_signing_keys:action.
// CoRIMSignError reports a CoRIM that could not be signed for a repository.
// Err is the refvalue sentinel chain (ErrMalformed, ErrMeta, ErrSignerKey,
// ErrSign), so callers match the cause with errors.Is.
type CoRIMSignError struct {
	// Repository is the repository the CoRIM was to be signed for.
	Repository string
	// KeyID is the signing key ResolveSigningKey named.
	KeyID string
	// Err is the signer's failure.
	Err error
}

// Error reports the repository, key and failure.
func (e *CoRIMSignError) Error() string {
	return "attestation: signing the CoRIM of repository " + e.Repository + " with key " + e.KeyID + ": " + e.Err.Error()
}

// Unwrap returns the signer's failure.
func (e *CoRIMSignError) Unwrap() error {
	return e.Err
}

func (s *XKMSService) authorizeSigningKeys(ctx context.Context, action string) error {
	if err := s.AuthorizeCaller(ctx, auth.ResourceAttestationSigningKeys, action); err != nil {
		return &SigningKeyPermissionError{Permission: auth.ResourceAttestationSigningKeys + ":" + action, Err: err}
	}
	return nil
}

// SetSigningKeyBinding names the key that signs one of the caller's tenant's
// repositories, in place of the release key.
//
// Permission: attestation_signing_keys:bind.
func (s *XKMSService) SetSigningKeyBinding(ctx context.Context, req *appraisal.SetSigningKeyBindingRequest) (*appraisal.SigningKeyBinding, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionBind); err != nil {
		return nil, err
	}
	return appraiser.SetSigningKeyBinding(ctx, tenant, req)
}

// GetSigningKeyBinding returns the binding of one of the caller's tenant's
// repositories.
//
// Permission: attestation_signing_keys:get.
func (s *XKMSService) GetSigningKeyBinding(ctx context.Context, req *appraisal.GetSigningKeyBindingRequest) (*appraisal.SigningKeyBinding, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionGet); err != nil {
		return nil, err
	}
	return appraiser.GetSigningKeyBinding(ctx, tenant, req)
}

// ListSigningKeyBindings lists the caller's tenant's bindings, ordered by
// repository.
//
// Permission: attestation_signing_keys:list.
func (s *XKMSService) ListSigningKeyBindings(ctx context.Context) (*appraisal.ListSigningKeyBindingsResponse, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionList); err != nil {
		return nil, err
	}
	return appraiser.ListSigningKeyBindings(ctx, tenant)
}

// DeleteSigningKeyBinding removes the binding of one of the caller's
// tenant's repositories, returning it to the release key.
//
// Permission: attestation_signing_keys:bind.
func (s *XKMSService) DeleteSigningKeyBinding(ctx context.Context, req *appraisal.DeleteSigningKeyBindingRequest) error {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionBind); err != nil {
		return err
	}
	return appraiser.DeleteSigningKeyBinding(ctx, tenant, req)
}

// SigningPublicKey returns the public half of the tenant key a resolution
// names, so an Appraiser composed with appraisal.WithSigningKeySource(service)
// verifies a repository's signatures under the tenant's own key. The public
// key comes from the backend's signer: the cloud KMS backends return no
// private key from GetKey for a non-extractable key.
func (s *XKMSService) SigningPublicKey(ctx context.Context, tenant string, key *appraisal.SigningKeyResolution) (crypto.PublicKey, error) {
	signer, err := s.repositorySigner(ctx, tenant, key)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// repositorySigner returns the tenant-scoped backend signer of a resolved
// repository signing key.
func (s *XKMSService) repositorySigner(ctx context.Context, tenant string, key *appraisal.SigningKeyResolution) (crypto.Signer, error) {
	if key == nil {
		return nil, appraisal.ErrNilRequest
	}
	b, backendName, err := s.resolveTenantBackendWithName(key.Backend, tenant)
	if err != nil {
		return nil, err
	}
	// Every tenant names its release key release-signing, and the system
	// tenant's backend is unscoped, so the lookup is restricted to the
	// requested tenant: a key of another tenant is never trusted.
	owner := recordTenant(tenant)
	k, err := s.resolveKeyOf(ctx, b, backendName, key.KeyID, &owner)
	if err != nil {
		return nil, err
	}
	cur, err := k.current()
	if err != nil {
		return nil, err
	}
	signer, err := k.backend.Signer(ctx, cur.attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "read repository signing key", KeyID: key.KeyID, Err: err}
	}
	return signer, nil
}

// ResolveSigningKey returns the key that signs one of the caller's tenant's
// repositories: its bound key, or else the release key.
//
// Permission: attestation_signing_keys:get.
func (s *XKMSService) ResolveSigningKey(ctx context.Context, req *appraisal.ResolveSigningKeyRequest) (*appraisal.SigningKeyResolution, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionGet); err != nil {
		return nil, err
	}
	return appraiser.ResolveSigningKey(ctx, tenant, req)
}

// SignCoRIM signs CoRIM reference values of one of the caller's tenant's
// repositories as a draft-ietf-rats-corim-11 §4.2 signed CoRIM, with the key
// ResolveSigningKey names: the repository's bound key, or else the tenant's
// release key (owner ruling 134). The key is the tenant-scoped backend's
// signer, restricted to the caller's tenant as SigningPublicKey restricts
// it, so the output verifies under the key the Verifier trusts for the
// repository.
//
// Permission: attestation_signing_keys:sign.
func (s *XKMSService) SignCoRIM(ctx context.Context, req *appraisal.SignCoRIMRequest) (*appraisal.SignedCoRIM, error) {
	if req == nil {
		return nil, appraisal.ErrNilRequest
	}
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionSign); err != nil {
		return nil, err
	}
	if err := appraisal.ValidateRepository(req.Repository); err != nil {
		return nil, err
	}
	key, err := appraiser.ResolveSigningKey(ctx, tenant, &appraisal.ResolveSigningKeyRequest{Repository: req.Repository})
	if err != nil {
		return nil, err
	}
	signer, err := s.repositorySigner(ctx, tenant, key)
	if err != nil {
		return nil, err
	}
	meta := refvalue.Meta{
		SignerName: req.SignerName,
		SignerURI:  req.SignerURI,
		NotBefore:  req.NotBefore,
		NotAfter:   req.NotAfter,
	}
	signed, err := refvalue.Sign(req.CoRIM, meta, signer)
	if err != nil {
		return nil, &CoRIMSignError{Repository: req.Repository, KeyID: key.KeyID, Err: err}
	}
	return &appraisal.SignedCoRIM{Key: *key, CoRIM: signed}, nil
}
