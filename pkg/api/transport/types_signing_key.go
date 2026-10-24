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

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
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
)
