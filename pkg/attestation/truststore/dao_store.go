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

package truststore

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"sort"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// DatabaseName is the qrdb database that holds the platform trust roots.
const DatabaseName = "trust_roots"

// trustCertEntityType is the entity namespace of the trust roots.
const trustCertEntityType = "trust_certs"

// DAOStore is the platform's persisted trust-root store: a go-qrdb
// GenericDAO in the DatabaseName database. Each certificate is stored as a
// TrustCertEntity with a deterministic ID derived from its SHA-256
// fingerprint. Trust roots are public certificates, so no barrier
// encryption is needed.
type DAOStore struct {
	closed atomic.Bool
	dao    qrdbsdk.GenericDAO[*TrustCertEntity]
	idGen  *qrdbsdk.FieldHashGenerator
}

// NewDAOStore creates a DAOStore on the DatabaseName database of factory.
func NewDAOStore(factory *qrdbsdk.DAOFactory) (*DAOStore, error) {
	idGen := qrdbsdk.NewFieldHashGenerator("Fingerprint")

	trustDAO, err := dao.New(factory, DatabaseName, trustCertEntityType,
		func() *TrustCertEntity { return &TrustCertEntity{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOStore{
		dao:   trustDAO,
		idGen: idGen,
	}, nil
}

// computeID returns the deterministic entity ID for a fingerprint.
func (s *DAOStore) computeID(fingerprint string) uint64 {
	entity := &TrustCertEntity{Fingerprint: fingerprint}
	return s.idGen.NextID(entity)
}

// Add persists a trusted certificate. A nil opts, or an empty opts.Purpose,
// classifies the certificate from its contents (ClassifyCertificate); an
// unknown purpose is refused with ErrInvalidPurpose. A certificate the store
// already holds is refused with ErrCertificateExists: reclassify it with
// SetPurpose instead.
func (s *DAOStore) Add(ctx context.Context, cert *x509.Certificate, opts *AddCertificateOptions) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if cert == nil {
		return ErrInvalidCertificate
	}

	purpose := ClassifyCertificate(cert)
	var source string
	if opts != nil {
		if opts.Purpose != "" {
			purpose = opts.Purpose
		}
		source = opts.Source
	}
	if !IsValidPurpose(purpose) {
		return ErrInvalidPurpose
	}

	fp := Fingerprint(cert)
	exists, err := s.exists(ctx, s.computeID(fp))
	if err != nil {
		return err
	}
	if exists {
		return ErrCertificateExists
	}

	block := &pem.Block{
		Type:  pemBlockType,
		Bytes: cert.Raw,
	}
	pemBytes := pem.EncodeToMemory(block)

	now := time.Now().UTC()

	entity := &TrustCertEntity{
		Fingerprint: fp,
		Purpose:     string(purpose),
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		Algorithm:   algorithmName(cert.PublicKeyAlgorithm),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		PEM:         string(pemBytes),
		Source:      source,
		AddedAt:     now,
	}
	entity.SetEntityID(s.computeID(fp))

	return s.dao.Save(ctx, entity)
}

// exists reports whether the store holds the entity id.
func (s *DAOStore) exists(ctx context.Context, id uint64) (bool, error) {
	_, err := s.dao.Get(ctx, id)
	if err == nil {
		return true, nil
	}
	if qrdbsdk.IsDAONotFound(err) {
		return false, nil
	}
	return false, err
}

// ImportPEM adds every certificate of a PEM bundle with opts (see Add),
// counting the ones the store already holds as skipped.
func (s *DAOStore) ImportPEM(ctx context.Context, pemData []byte, opts *AddCertificateOptions) (ImportResult, error) {
	return importPEM(daoImporter{ctx: ctx, store: s}, pemData, opts)
}

// daoImporter adapts DAOStore.Add to the context-free certificateImporter
// importPEM drives, binding the import's context.
type daoImporter struct {
	ctx   context.Context
	store *DAOStore
}

// AddCertificateWithOptions adds cert through the DAOStore.
func (d daoImporter) AddCertificateWithOptions(cert *x509.Certificate, opts *AddCertificateOptions) error {
	return d.store.Add(d.ctx, cert, opts)
}

// SetPurpose reclassifies the certificate fingerprint as purpose and returns
// its updated metadata. Setting PurposeSynced quarantines it: the root stays
// listed but Anchors no longer returns it.
func (s *DAOStore) SetPurpose(ctx context.Context, fingerprint string, purpose CertPurpose) (*CertMetadata, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}
	if err := validateFingerprint(fingerprint); err != nil {
		return nil, err
	}
	if !IsValidPurpose(purpose) {
		return nil, ErrInvalidPurpose
	}

	entity, err := s.dao.Get(ctx, s.computeID(fingerprint))
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrCertificateNotFound
		}
		return nil, err
	}
	entity.Purpose = string(purpose)
	if err := s.dao.Save(ctx, entity); err != nil {
		return nil, err
	}
	return entityToMetadata(entity), nil
}

// Anchors returns the certificates of purpose for use as verification
// anchors. A purpose that anchors nothing (PurposeSynced, the quarantine)
// is refused with ErrNotAnchorPurpose, so a quarantined root can never
// anchor a chain.
func (s *DAOStore) Anchors(ctx context.Context, purpose CertPurpose) ([]*x509.Certificate, error) {
	if !IsAnchorPurpose(purpose) {
		return nil, ErrNotAnchorPurpose
	}
	return s.GetByPurpose(ctx, purpose)
}

// Get retrieves a trusted certificate by its SHA-256 fingerprint (hex-encoded).
// Returns the parsed x509.Certificate and its metadata.
func (s *DAOStore) Get(ctx context.Context, fingerprint string) (*x509.Certificate, *CertMetadata, error) {
	if s.closed.Load() {
		return nil, nil, ErrStoreClosed
	}

	if err := validateFingerprint(fingerprint); err != nil {
		return nil, nil, err
	}

	entityID := s.computeID(fingerprint)

	entity, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, nil, ErrCertificateNotFound
		}
		return nil, nil, err
	}

	cert, parseErr := parsePEMBytes([]byte(entity.PEM))
	if parseErr != nil {
		return nil, nil, parseErr
	}

	meta := entityToMetadata(entity)

	return cert, meta, nil
}

// GetByPurpose returns all trusted certificates matching the given purpose.
func (s *DAOStore) GetByPurpose(ctx context.Context, purpose CertPurpose) ([]*x509.Certificate, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	var certs []*x509.Certificate

	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*TrustCertEntity]) error {
		for _, entity := range result.Entities {
			if entity.Purpose == string(purpose) {
				cert, parseErr := parsePEMBytes([]byte(entity.PEM))
				if parseErr != nil {
					continue
				}
				certs = append(certs, cert)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// List returns all trusted certificates sorted by subject name.
func (s *DAOStore) List(ctx context.Context) ([]*x509.Certificate, []*CertMetadata, error) {
	if s.closed.Load() {
		return nil, nil, ErrStoreClosed
	}

	var entities []*TrustCertEntity

	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*TrustCertEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Subject < entities[j].Subject
	})

	certs := make([]*x509.Certificate, 0, len(entities))
	metas := make([]*CertMetadata, 0, len(entities))

	for _, entity := range entities {
		cert, parseErr := parsePEMBytes([]byte(entity.PEM))
		if parseErr != nil {
			continue
		}
		certs = append(certs, cert)
		metas = append(metas, entityToMetadata(entity))
	}

	return certs, metas, nil
}

// Delete removes a trusted certificate by its SHA-256 fingerprint.
func (s *DAOStore) Delete(ctx context.Context, fingerprint string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	entityID := s.computeID(fingerprint)

	_, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return ErrCertificateNotFound
		}
		return err
	}

	stub := &TrustCertEntity{}
	stub.SetEntityID(entityID)
	return s.dao.Delete(ctx, stub)
}

// Page retrieves a paginated set of trust certificate entities.
func (s *DAOStore) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*TrustCertEntity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*TrustCertEntity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, query)
}

// Close marks the store as closed. The underlying DAO does not need
// explicit closing since its lifecycle is managed by the kvstore.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}

// entityToMetadata converts a TrustCertEntity to CertMetadata.
func entityToMetadata(entity *TrustCertEntity) *CertMetadata {
	return &CertMetadata{
		Subject:     entity.Subject,
		Issuer:      entity.Issuer,
		Fingerprint: entity.Fingerprint,
		NotBefore:   entity.NotBefore,
		NotAfter:    entity.NotAfter,
		Algorithm:   entity.Algorithm,
		AddedAt:     entity.AddedAt,
		Purpose:     CertPurpose(entity.Purpose),
		Source:      entity.Source,
	}
}
