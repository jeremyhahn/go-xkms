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

package transport

import (
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// SigningKeyService manages which key signs a repository's images and
// CoRIM: the tenant release key unless a binding names another of the
// tenant's keys (go-xkms#1697). Every method acts on the caller's tenant.
type SigningKeyService interface {
	// SetSigningKeyBinding names the key that signs a repository.
	// Permission: attestation_signing_keys:bind.
	SetSigningKeyBinding(ctx context.Context, req *SetSigningKeyBindingRequest) (*SigningKeyBinding, error)

	// GetSigningKeyBinding returns a repository's binding.
	// Permission: attestation_signing_keys:get.
	GetSigningKeyBinding(ctx context.Context, req *GetSigningKeyBindingRequest) (*SigningKeyBinding, error)

	// ListSigningKeyBindings returns the tenant's bindings.
	// Permission: attestation_signing_keys:list.
	ListSigningKeyBindings(ctx context.Context) (*ListSigningKeyBindingsResponse, error)

	// DeleteSigningKeyBinding removes a repository's binding, so the
	// release key signs it again. Permission: attestation_signing_keys:bind.
	DeleteSigningKeyBinding(ctx context.Context, req *DeleteSigningKeyBindingRequest) error

	// ResolveSigningKey returns the key that signs a repository.
	// Permission: attestation_signing_keys:get.
	ResolveSigningKey(ctx context.Context, req *ResolveSigningKeyRequest) (*SigningKeyResolution, error)

	// SignCoRIM signs CoRIM reference values of a repository as a
	// draft-ietf-rats-corim-11 §4.2 signed CoRIM with the key
	// ResolveSigningKey names. Permission: attestation_signing_keys:sign.
	SignCoRIM(ctx context.Context, req *SignCoRIMRequest) (*SignedCoRIM, error)

	// SignImage signs a container image of a repository with the key
	// ResolveSigningKey names, as a DSSE in-toto attestation pushed to the
	// image's registry. Permission: attestation_signing_keys:sign.
	SignImage(ctx context.Context, req *SignImageRequest) (*SignedImage, error)
}

// SignImageRequest asks for a container image to be signed with the key
// that signs its repository.
type SignImageRequest struct {
	// Reference names the image, registry/repository[:tag][@digest]. Its
	// repository path is the repository whose signing key signs it.
	Reference string `json:"reference"`

	// PredicateType is the in-toto statement's predicate type; cosign's
	// (image.PredicateTypeCosign) when empty.
	PredicateType string `json:"predicate_type,omitempty"`

	// Predicate is the statement's predicate, a JSON value. It may be empty
	// only for cosign's predicate type.
	Predicate json.RawMessage `json:"predicate,omitempty"`

	// Registry holds the credentials the service pushes the attestation to
	// the image's registry with; nil sends none.
	Registry *ImageRegistryCredentials `json:"registry,omitempty"`
}

// ImageRegistryCredentials are the basic credentials of an image registry,
// which the service also presents to the registry's token realm.
type ImageRegistryCredentials struct {
	Username string            `json:"username"`
	Password types.SecretBytes `json:"password,omitempty"`
}

// SignedImage is an image signature and the key that made it.
type SignedImage struct {
	// Key is the signing key ResolveSigningKey named for the repository.
	Key SigningKeyResolution `json:"key"`

	// Digest is the signed manifest digest.
	Digest string `json:"digest"`

	// Envelope is the pushed DSSE envelope JSON.
	Envelope []byte `json:"envelope"`

	// Certificate is the PEM code-signing certificate of Key, issued by
	// the service's CA in the caller's tenant for this signature.
	Certificate []byte `json:"certificate"`

	// Referrer is the digest of the OCI 1.1 referrer manifest holding the
	// attestation; ReferrerIndexed reports whether the registry indexed it.
	Referrer        string `json:"referrer"`
	ReferrerIndexed bool   `json:"referrer_indexed"`

	// AttestationTag is the cosign ".att" tag the attestation was added to.
	AttestationTag string `json:"attestation_tag"`
}

// SigningKeyServicer is the server side of SigningKeyService.
type SigningKeyServicer interface {
	SigningKeyService
}

// The signing-key request and response types are aliases of the appraisal
// domain types, which carry the JSON tags, as types_escrow.go does for
// pkg/escrow.
type (
	SigningKeyBinding              = appraisal.SigningKeyBinding
	SetSigningKeyBindingRequest    = appraisal.SetSigningKeyBindingRequest
	GetSigningKeyBindingRequest    = appraisal.GetSigningKeyBindingRequest
	ListSigningKeyBindingsResponse = appraisal.ListSigningKeyBindingsResponse
	DeleteSigningKeyBindingRequest = appraisal.DeleteSigningKeyBindingRequest
	ResolveSigningKeyRequest       = appraisal.ResolveSigningKeyRequest
	SigningKeyResolution           = appraisal.SigningKeyResolution
	SignCoRIMRequest               = appraisal.SignCoRIMRequest
	SignedCoRIM                    = appraisal.SignedCoRIM
)
