// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package ca

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	objstore "github.com/jeremyhahn/go-objstore/pkg/common"
)

// =============================================================================
// Multi-identity construction errors
// =============================================================================

var (
	// ErrNoIdentity indicates that Params.Identity is empty when a
	// multi-identity constructor requires at least one entry.
	ErrNoIdentity = errors.New("ca: params.identity requires at least one entry")

	// ErrNoIntermediateIdentity indicates that Params.Identity does not
	// contain an intermediate entry (index 1) when one is required.
	ErrNoIntermediateIdentity = errors.New("ca: params.identity[1] (intermediate) is required")

	// ErrParentCARequired indicates NewIntermediateCA was called without a
	// non-nil, initialized parent TrustedCA.
	ErrParentCARequired = errors.New("ca: parent ca is required")

	// ErrParentCANotInitialized indicates NewIntermediateCA was called with
	// a parent that has not yet been initialized.
	ErrParentCANotInitialized = errors.New("ca: parent ca not initialized")

	// ErrStoreFactoryReturnedNil indicates a configured factory returned a
	// nil store. Factories must return a usable store or an error.
	ErrStoreFactoryReturnedNil = errors.New("ca: store factory returned nil")
)

// =============================================================================
// Factory function types
// =============================================================================

// KeyStoreFactoryFunc resolves a KeyStore for a given CA common name.
// Used by multi-identity constructors to assign a dedicated KeyStore to each
// CA (root, intermediate) keyed on its subject CN. When nil, the single
// shared Params.KeyStore is used for all identities.
type KeyStoreFactoryFunc func(cn string) (xkms.Backend, error)

// BackendForStoreFunc resolves an xkms.Backend for a given CA CN and
// StoreType. It is called once per unique StoreType found in an identity's
// Keys slice. A nil return with a nil error is not permitted; the function
// must return a usable Backend or an error.
//
// The CA caches the returned backends in a per-instance keystoreMap so a given
// BackendForStoreFunc is invoked at most once per (cn, storeType) pair.
type BackendForStoreFunc func(cn string, storeType types.StoreType) (xkms.Backend, error)

// CertStoreFactoryFunc resolves a CertStore for a given CA common name.
// See KeyStoreFactoryFunc for semantics.
type CertStoreFactoryFunc func(cn string) (certstore.CertStore, error)

// ObjectStoreFactoryFunc resolves an object store for a given CA common name.
// See KeyStoreFactoryFunc for semantics. Object store is optional; a factory
// that returns (nil, nil) is permitted and yields no object store for that CA.
type ObjectStoreFactoryFunc func(cn string) (objstore.Storage, error)

// =============================================================================
// ResolveStores
// =============================================================================

// ResolveStores returns the KeyStore, CertStore, and ObjectStore for the CA
// identified by cn. When a factory is set on Params it is invoked with cn
// and its result returned; otherwise the single shared store from Params is
// returned. ObjectStore is optional and may be nil.
//
// ResolveStores returns typed errors when a factory yields nil or fails, and
// when a required shared store is missing.
func (p *Params) ResolveStores(cn string) (xkms.Backend, certstore.CertStore, objstore.Storage, error) {
	var (
		ks  xkms.Backend
		cs  certstore.CertStore
		os  objstore.Storage
		err error
	)

	if p.KeyStoreFactory != nil {
		ks, err = p.KeyStoreFactory(cn)
		if err != nil {
			return nil, nil, nil, &errs.Wrapped{Msg: fmt.Sprintf("ca: keystore factory failed for %q", cn), Err: err}
		}
		if ks == nil {
			return nil, nil, nil, &errs.Detail{Err: ErrStoreFactoryReturnedNil, Detail: fmt.Sprintf("keystore factory for %q", cn)}
		}
	} else {
		if p.KeyStore == nil {
			return nil, nil, nil, ErrKeyStoreRequired
		}
		ks = p.KeyStore
	}

	if p.CertStoreFactory != nil {
		cs, err = p.CertStoreFactory(cn)
		if err != nil {
			return nil, nil, nil, &errs.Wrapped{Msg: fmt.Sprintf("ca: certstore factory failed for %q", cn), Err: err}
		}
		if cs == nil {
			return nil, nil, nil, &errs.Detail{Err: ErrStoreFactoryReturnedNil, Detail: fmt.Sprintf("certstore factory for %q", cn)}
		}
	} else {
		if p.CertStore == nil {
			return nil, nil, nil, ErrCertStoreRequired
		}
		cs = p.CertStore
	}

	if p.ObjectStoreFactory != nil {
		os, err = p.ObjectStoreFactory(cn)
		if err != nil {
			return nil, nil, nil, &errs.Wrapped{Msg: fmt.Sprintf("ca: object store factory failed for %q", cn), Err: err}
		}
		// Nil object store is allowed; it is optional for the CA.
	} else {
		os = p.ObjectStore
	}

	return ks, cs, os, nil
}

// =============================================================================
// caConfigFromIdentity
// =============================================================================

// caConfigFromIdentity builds a flat CAConfig from an Identity. The returned
// config carries the subject, validity, store type, IsRoot flag, and
// distribution/OCSP/AIA URLs from the identity. DefaultCertValidity is
// supplied via the defaultCertValidity argument; 0 means use the package
// default (DefaultCertValidityDays).
func caConfigFromIdentity(id Identity, defaultCertValidity int) *CAConfig {
	subject := id.Subject
	cfg := &CAConfig{
		Identity:               subject.CommonName,
		Subject:                &subject,
		ValidityDays:           id.GetValidityDays(),
		IsRootCA:               id.IsRoot,
		MaxPathLength:          id.MaxPathLength,
		MaxPathLengthZero:      id.MaxPathLengthZero,
		CRLDistributionPoints:  id.CRLDistributionPoints,
		OCSPServers:            id.OCSPServers,
		IssuingCertificateURLs: id.IssuingCertificateURLs,
		PolicyIdentifiers:      id.PolicyIdentifiers,
		StoreType:              id.GetStoreType(),
		CRLValidityDays:        id.GetCRLValidityDays(),
	}
	if defaultCertValidity > 0 {
		cfg.DefaultCertValidityDays = defaultCertValidity
	} else {
		cfg.DefaultCertValidityDays = DefaultCertValidityDays
	}
	return cfg
}

// =============================================================================
// NewParentCA
// =============================================================================

// NewParentCA creates a single-identity TrustedCA for the root entry in
// params.Identity. The returned CA is not initialized; callers invoke Init()
// to generate a self-signed root certificate, or Load() to load an existing
// one from storage.
//
// Stores are resolved per-CA via Params.KeyStoreFactory / CertStoreFactory /
// ObjectStoreFactory when set; otherwise Params.KeyStore / CertStore /
// ObjectStore are used.
//
// Thread-safe: Yes.
func NewParentCA(params *Params) (TrustedCA, error) {
	if params == nil {
		return nil, ErrInvalidConfig
	}
	if len(params.Identity) == 0 {
		return nil, ErrNoIdentity
	}

	root := params.Identity[0]
	if err := root.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "ca: root identity invalid", Err: err}
	}

	ks, cs, os, err := params.ResolveStores(root.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	keyAttrs, err := root.ToKeyAttributes()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "ca: root identity key attributes", Err: err}
	}
	if keyAttrs.KeyType == 0 {
		keyAttrs.KeyType = types.KeyTypeCA
	}

	defaultValidity := 0
	if params.Config != nil {
		defaultValidity = params.Config.DefaultCertValidityDays
	}
	cfg := caConfigFromIdentity(root, defaultValidity)

	instance, err := New(&Params{
		Config:             cfg,
		KeyAttributes:      keyAttrs,
		KeyStore:           ks,
		CertStore:          cs,
		ObjectStore:        os,
		RevocationStore:    params.RevocationStore,
		SerialGen:          params.SerialGen,
		Profiles:           params.Profiles,
		BackendForStore:    params.BackendForStore,
		RequireKeyPassword: params.RequireKeyPassword,
		// Pass the root Identity as index 0 so New() builds the keystoreMap
		// from its full multi-key slice (the flat CAConfig keeps only Keys[0]).
		Identity: []Identity{root},
	})
	if err != nil {
		return nil, err
	}
	// Preserve the caller-supplied Identity so IssuingIdentity() can return
	// the full multi-key slice verbatim. The flat CAConfig path drops all
	// Keys after the first.
	if caInstance, ok := instance.(*CA); ok {
		rootCopy := root
		caInstance.inputIdentity = &rootCopy
	}
	return instance, nil
}

// =============================================================================
// NewIntermediateCA
// =============================================================================

// NewIntermediateCA creates an intermediate TrustedCA from params.Identity[1]
// signed by the provided parent root CA. parent must be initialized (its
// IsInitialized() must return true); otherwise ErrParentCANotInitialized is
// returned.
//
// The intermediate CA is returned fully initialized: its key has been
// generated in the resolved KeyStore and its certificate has been signed by
// the parent and stored in the resolved CertStore.
//
// Thread-safe: Yes. The parent must remain valid for the lifetime of this
// call.
func NewIntermediateCA(ctx context.Context, params *Params, parent TrustedCA) (TrustedCA, error) {
	if params == nil {
		return nil, ErrInvalidConfig
	}
	if parent == nil {
		return nil, ErrParentCARequired
	}
	if !parent.IsInitialized() {
		return nil, ErrParentCANotInitialized
	}
	if len(params.Identity) < 2 {
		return nil, ErrNoIntermediateIdentity
	}

	intermediateID := params.Identity[1]
	if err := intermediateID.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "ca: intermediate identity invalid", Err: err}
	}

	ks, cs, os, err := params.ResolveStores(intermediateID.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	keyAttrs, err := intermediateID.ToKeyAttributes()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "ca: intermediate identity key attributes", Err: err}
	}
	if keyAttrs.KeyType == 0 {
		keyAttrs.KeyType = types.KeyTypeCA
	}

	defaultValidity := 0
	if params.Config != nil {
		defaultValidity = params.Config.DefaultCertValidityDays
	}
	cfg := caConfigFromIdentity(intermediateID, defaultValidity)
	// The intermediate is not a root.
	cfg.IsRootCA = false

	instance, err := New(&Params{
		Config:             cfg,
		KeyAttributes:      keyAttrs,
		KeyStore:           ks,
		CertStore:          cs,
		ObjectStore:        os,
		RevocationStore:    params.RevocationStore,
		SerialGen:          params.SerialGen,
		Profiles:           params.Profiles,
		BackendForStore:    params.BackendForStore,
		RequireKeyPassword: params.RequireKeyPassword,
		// Pass the intermediate Identity as index 0 so New() builds the
		// keystoreMap from its full multi-key slice.
		Identity: []Identity{intermediateID},
	})
	if err != nil {
		return nil, err
	}

	caInstance, ok := instance.(*CA)
	if !ok {
		return nil, &errs.Message{Msg: fmt.Sprintf("ca: unexpected TrustedCA implementation %T", instance)}
	}

	if err := initializeAsIntermediate(ctx, caInstance, intermediateID, parent); err != nil {
		return nil, err
	}

	// Preserve the caller-supplied intermediate Identity so IssuingIdentity()
	// returns the full multi-key slice verbatim rather than a single-key
	// reconstruction from the flat CAConfig.
	intermediateCopy := intermediateID
	caInstance.inputIdentity = &intermediateCopy

	return caInstance, nil
}

// initializeAsIntermediate populates the intermediate CA with its root cert
// cached from the parent, signs the intermediate certificate using the parent
// as issuer, stores it, and marks the CA initialized. This avoids invoking
// Init(), which would attempt to create a new root in the intermediate's
// stores.
func initializeAsIntermediate(ctx context.Context, caInstance *CA, identity Identity, parent TrustedCA) error {
	caInstance.mu.Lock()
	defer caInstance.mu.Unlock()

	if caInstance.initialized.Load() {
		return ErrAlreadyInitialized
	}

	parentCert, err := parent.CACertificate()
	if err != nil {
		return &errs.Wrapped{Msg: "ca: retrieve parent certificate", Err: err}
	}

	// The parent TrustedCA is itself a crypto.Signer bound to the parent's
	// signing key. Using it here transparently works whether the parent's
	// KeyStore is shared with or distinct from the intermediate's.
	parentSigner, ok := parent.(crypto.Signer)
	if !ok {
		return &errs.Message{Msg: fmt.Sprintf("ca: parent %T does not implement crypto.Signer", parent)}
	}

	cert, err := caInstance.createSingleIntermediateCertificate(ctx, &identity, parentCert, parentSigner)
	if err != nil {
		return &errs.Wrapped{Msg: "ca: create intermediate certificate", Err: err}
	}

	if err := caInstance.certStore.StoreCertificate(cert); err != nil {
		return &errs.Wrapped{Msg: "ca: store intermediate certificate", Err: err}
	}

	caInstance.rootCert = parentCert
	caInstance.intermediateCert = cert
	caInstance.initialized.Store(true)

	return nil
}

// =============================================================================
// NewCA
// =============================================================================

// NewCA builds a root+intermediate pair from params.Identity. When only one
// identity is present, only the root is built and returned; the intermediate
// return value is nil. When two identities are present, the root is built and
// initialized first, then the intermediate is built and signed by the root.
//
// On success both returned CAs are initialized (IsInitialized() == true).
//
// Thread-safe: Yes.
func NewCA(ctx context.Context, params *Params) (TrustedCA, TrustedCA, error) {
	if params == nil {
		return nil, nil, ErrInvalidConfig
	}
	if len(params.Identity) == 0 {
		return nil, nil, ErrNoIdentity
	}

	root, err := NewParentCA(params)
	if err != nil {
		return nil, nil, err
	}

	if err := root.Init(ctx); err != nil {
		return nil, nil, &errs.Wrapped{Msg: "ca: initialize parent ca", Err: err}
	}

	if len(params.Identity) == 1 {
		return root, nil, nil
	}

	intermediate, err := NewIntermediateCA(ctx, params, root)
	if err != nil {
		return nil, nil, err
	}

	return root, intermediate, nil
}
