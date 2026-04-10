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

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// DAOStore implements trust certificate persistence using a go-qrdb GenericDAO
// backed by a kvstore.KVStore. Each certificate is stored as a TrustCertEntity
// with a deterministic ID derived from the SHA-256 fingerprint. Since trust
// certificates are public CA certs, no barrier encryption is needed.
type DAOStore struct {
	closed atomic.Bool
	dao    dao.GenericDAO[*TrustCertEntity]
	idGen  *dao.FieldHashGenerator
}

// NewDAOStore creates a new DAOStore using the given kvstore.KVStore.
// The entity type namespace is "trust_certs".
func NewDAOStore(kvStore kvstore.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore
	}

	idGen := dao.NewFieldHashGenerator("Fingerprint")

	trustDAO, err := dao.New[*TrustCertEntity](
		kvStore,
		"trust_certs",
		func() *TrustCertEntity { return &TrustCertEntity{} },
		dao.WithIDGenerator(idGen),
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

// Add persists a trusted certificate with the given purpose. The certificate
// is PEM-encoded, its metadata extracted, and stored as a TrustCertEntity.
// If a certificate with the same fingerprint already exists, it is overwritten
// (upsert behavior).
func (s *DAOStore) Add(ctx context.Context, cert *x509.Certificate, purpose CertPurpose) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if cert == nil {
		return ErrInvalidCertificate
	}

	fp := Fingerprint(cert)

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
		AddedAt:     now,
	}
	entity.SetEntityID(s.computeID(fp))

	return s.dao.Save(ctx, entity)
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
		if dao.IsNotFound(err) {
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

	err := s.dao.ForEachPage(ctx, dao.PageQuery{Page: 1, PageSize: 1000}, func(result dao.PageResult[*TrustCertEntity]) error {
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

	err := s.dao.ForEachPage(ctx, dao.PageQuery{Page: 1, PageSize: 1000}, func(result dao.PageResult[*TrustCertEntity]) error {
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
		if dao.IsNotFound(err) {
			return ErrCertificateNotFound
		}
		return err
	}

	stub := &TrustCertEntity{}
	stub.SetEntityID(entityID)
	return s.dao.Delete(ctx, stub)
}

// Page retrieves a paginated set of trust certificate entities.
func (s *DAOStore) Page(ctx context.Context, query dao.PageQuery) (dao.PageResult[*TrustCertEntity], error) {
	if s.closed.Load() {
		return dao.PageResult[*TrustCertEntity]{}, ErrStoreClosed
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
