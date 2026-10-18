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
	"encoding/pem"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// The TrustRoot* methods serve the platform trust-root store
// (pkg/attestation/truststore). The store is process-wide, so every method is
// platform-scoped (qrdbsdk.IdentityIsSystemTenant): a tenant-scoped caller is refused
// with a *TenantBindingError that reads as not-found, before the store is
// touched.

// SetTrustRootStore wires the platform trust-root store.
func (s *XKMSService) SetTrustRootStore(store *truststore.DAOStore) { s.trustRoots.store(store) }

// TrustRootStore returns the platform trust-root store, or nil when unwired.
func (s *XKMSService) TrustRootStore() *truststore.DAOStore { return s.trustRoots.load() }

// trustRootStore returns the store for op once the caller is platform-scoped.
func (s *XKMSService) trustRootStore(ctx context.Context, op string) (*truststore.DAOStore, error) {
	store := s.trustRoots.load()
	if !qrdbsdk.IdentityIsSystemTenant(auth.GetIdentity(ctx)) {
		return nil, refuseTenant(ctx, op, "")
	}
	if store == nil {
		return nil, ErrNotConfigured
	}
	return store, nil
}

// TrustRootList lists the trust roots, sorted by subject, optionally only
// those of req.Purpose. The PEM is left out.
func (s *XKMSService) TrustRootList(ctx context.Context, req *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	store, err := s.trustRootStore(ctx, "list trust roots")
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	var purpose truststore.CertPurpose
	if req.Purpose != "" {
		if purpose, err = truststore.ParsePurpose(req.Purpose); err != nil {
			return nil, err
		}
	}
	_, metas, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	roots := make([]transport.TrustRoot, 0, len(metas))
	for _, meta := range metas {
		if purpose != "" && meta.Purpose != purpose {
			continue
		}
		roots = append(roots, trustRootToTransport(meta, ""))
	}
	return &transport.TrustRootListResponse{Roots: roots}, nil
}

// TrustRootGet returns one trust root, its PEM included.
func (s *XKMSService) TrustRootGet(ctx context.Context, req *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	store, err := s.trustRootStore(ctx, "get trust root")
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	cert, meta, err := store.Get(ctx, req.Fingerprint)
	if err != nil {
		return nil, err
	}
	root := trustRootToTransport(meta, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	return &root, nil
}

// TrustRootImport adds the certificates of a PEM bundle, classified as
// req.Purpose or, when it is empty, each from its own contents. Certificates
// the store already holds are counted as skipped and keep their purpose.
func (s *XKMSService) TrustRootImport(ctx context.Context, req *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	store, err := s.trustRootStore(ctx, "import trust roots")
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	opts := &truststore.AddCertificateOptions{Source: req.Source}
	if req.Purpose != "" {
		if opts.Purpose, err = truststore.ParsePurpose(req.Purpose); err != nil {
			return nil, err
		}
	}
	result, err := store.ImportPEM(ctx, []byte(req.PEM), opts)
	if err != nil {
		return nil, err
	}
	return &transport.TrustRootImportResponse{Added: result.Added, Skipped: result.Skipped}, nil
}

// TrustRootQuarantine reclassifies a trust root as synced: it stays listed
// but anchors no verification until it is removed and imported again with a
// purpose.
func (s *XKMSService) TrustRootQuarantine(ctx context.Context, req *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	store, err := s.trustRootStore(ctx, "quarantine trust root")
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	meta, err := store.SetPurpose(ctx, req.Fingerprint, truststore.PurposeSynced)
	if err != nil {
		return nil, err
	}
	root := trustRootToTransport(meta, "")
	return &root, nil
}

// TrustRootRemove deletes a trust root.
func (s *XKMSService) TrustRootRemove(ctx context.Context, req *transport.TrustRootRequest) error {
	store, err := s.trustRootStore(ctx, "remove trust root")
	if err != nil {
		return err
	}
	if req == nil {
		return ErrNilRequest
	}
	return store.Delete(ctx, req.Fingerprint)
}

// trustRootToTransport converts trust-root metadata to its transport form.
func trustRootToTransport(meta *truststore.CertMetadata, pemText string) transport.TrustRoot {
	return transport.TrustRoot{
		Fingerprint: meta.Fingerprint,
		Purpose:     string(meta.Purpose),
		Subject:     meta.Subject,
		Issuer:      meta.Issuer,
		Algorithm:   meta.Algorithm,
		NotBefore:   meta.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    meta.NotAfter.UTC().Format(time.RFC3339),
		AddedAt:     meta.AddedAt.UTC().Format(time.RFC3339),
		Source:      meta.Source,
		PEM:         pemText,
	}
}
