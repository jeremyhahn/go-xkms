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

package store

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const (
	// DatabaseName is the go-qrdb database TPM blobs live in. A composition
	// root opens it on the datastore before calling NewBlobStore.
	DatabaseName = "tpm2"

	// blobEntityType is the DAO entity type of a TPM blob.
	blobEntityType = "tpm_blobs"

	// SystemTenant is the tenant segment of the system scope's blobs.
	SystemTenant = "system"

	// listPageSize is the page size BlobStore.KeyNames scans with.
	listPageSize = 1000
)

// blobExtensions are the extensions a key's blobs can carry; Delete removes
// every one of them. FSEXT_LEGACY_PRIVATE_BLOB is included because symmetric
// keys written before go-xkms#1148 hold their (unprotected) private blob
// there, and deleting a key must not leave it behind (go-xkms#1168).
var blobExtensions = []string{
	FSEXT_PRIVATE_BLOB,
	FSEXT_PUBLIC_BLOB,
	FSEXT_TPM_CONTEXT,
	FSEXT_PLATFORM_POLICY,
	FSEXT_TPM_POLICY,
	FSEXT_LEGACY_PRIVATE_BLOB,
}

var (
	_ KeyBackend = (*BlobStore)(nil)
	_ KeyLister  = (*BlobStore)(nil)
)

// TPMBlob is one stored artifact of a TPM object: its public or private area,
// saved context, policy record or certificate. Key is the natural key
// "{tenant}/{name}/{ext}" its entity ID derives from.
type TPMBlob struct {
	ID     uint64 `json:"id"`
	Key    string `json:"key"`
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
	Ext    string `json:"ext"`
	Data   []byte `json:"data"`
}

// EntityID returns the blob's entity ID.
func (b *TPMBlob) EntityID() uint64 { return b.ID }

// SetEntityID sets the blob's entity ID.
func (b *TPMBlob) SetEntityID(id uint64) { b.ID = id }

// BlobStore persists the blobs of one tenant's TPM objects as TPMBlob
// entities through a go-qrdb DAO. It implements KeyBackend, keyed by the
// object's Common Name and the artifact's extension.
type BlobStore struct {
	logger *slog.Logger
	blobs  qrdbsdk.GenericDAO[*TPMBlob]
	tenant string
}

// NewBlobStore returns the system tenant's BlobStore, whose DAO daos builds
// over DatabaseName. Tenant derives the other tenants' stores from it.
func NewBlobStore(logger *slog.Logger, daos *qrdbsdk.DAOFactory) (*BlobStore, error) {
	if daos == nil {
		return nil, ErrNilDAOFactory
	}
	blobs, err := dao.New(daos, DatabaseName, blobEntityType,
		func() *TPMBlob { return &TPMBlob{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Key")))
	if err != nil {
		return nil, &BlobStoreCreateError{Cause: err}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BlobStore{logger: logger, blobs: blobs, tenant: SystemTenant}, nil
}

// Tenant returns the BlobStore of tenant's objects, sharing this store's DAO.
// The empty tenant is the system tenant.
func (s *BlobStore) Tenant(tenant string) (*BlobStore, error) {
	if tenant == "" {
		tenant = SystemTenant
	}
	if err := storage.ValidateTenantID(tenant); err != nil || strings.ContainsRune(tenant, 0) {
		return nil, &InvalidBlobKeyError{Field: "tenant", Value: tenant}
	}
	return &BlobStore{logger: s.logger, blobs: s.blobs, tenant: tenant}, nil
}

// TenantID returns the tenant whose blobs this store holds.
func (s *BlobStore) TenantID() string {
	return s.tenant
}

// blobKey returns the natural key of the ext blob of the object named name.
func (s *BlobStore) blobKey(name, ext string) (string, error) {
	if name == "" {
		return "", ErrEmptyKeyCN
	}
	if strings.ContainsRune(name, 0) {
		return "", &InvalidBlobKeyError{Field: "name", Value: name}
	}
	if ext == "" || strings.ContainsAny(ext, "/\x00") {
		return "", &InvalidBlobKeyError{Field: "extension", Value: ext}
	}
	return s.tenant + "/" + name + "/" + ext, nil
}

// attrsName returns the Common Name of attrs, refusing nil attributes.
func attrsName(attrs *types.KeyAttributes) (string, error) {
	if attrs == nil {
		return "", ErrEmptyKeyCN
	}
	return attrs.CN, nil
}

// Get returns the ext blob of the key attrs names. A missing blob is a
// *BlobReadError matching ErrBlobNotFound.
func (s *BlobStore) Get(attrs *types.KeyAttributes, ext types.FSExtension) ([]byte, error) {
	name, err := attrsName(attrs)
	if err != nil {
		return nil, err
	}
	return s.read(context.Background(), name, string(ext))
}

// Save stores data as the ext blob of the key attrs names. Without overwrite
// an existing blob is left in place and Save fails with a *BlobWriteError
// matching ErrBlobExists.
func (s *BlobStore) Save(attrs *types.KeyAttributes, data []byte, ext types.FSExtension, overwrite bool) error {
	name, err := attrsName(attrs)
	if err != nil {
		return err
	}
	return s.write(context.Background(), name, string(ext), data, overwrite)
}

// Delete removes every blob of the key attrs names. Blobs the key never had
// are not an error.
func (s *BlobStore) Delete(attrs *types.KeyAttributes) error {
	name, err := attrsName(attrs)
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, ext := range blobExtensions {
		if _, err := s.remove(ctx, name, ext); err != nil {
			return err
		}
	}
	return nil
}

// KeyNames returns, sorted, the names of this tenant's objects that have an
// ext blob.
func (s *BlobStore) KeyNames(ctx context.Context, ext types.FSExtension) ([]string, error) {
	var names []string
	query := qrdbsdk.PageQuery{Page: 1, PageSize: listPageSize}
	err := s.blobs.ForEachPage(ctx, query, func(page qrdbsdk.PageResult[*TPMBlob]) error {
		for _, blob := range page.Entities {
			if blob.Tenant == s.tenant && blob.Ext == string(ext) {
				names = append(names, blob.Name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, &BlobListError{Tenant: s.tenant, Ext: string(ext), Cause: err}
	}
	sort.Strings(names)
	return names, nil
}

// read returns the ext blob of the object named name.
func (s *BlobStore) read(ctx context.Context, name, ext string) ([]byte, error) {
	key, err := s.blobKey(name, ext)
	if err != nil {
		return nil, err
	}
	blob, err := s.blobs.GetByNaturalKey(ctx, key)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, &BlobReadError{Name: key, Cause: ErrBlobNotFound}
	}
	if err != nil {
		return nil, &BlobReadError{Name: key, Cause: err}
	}
	return blob.Data, nil
}

// write stores data as the ext blob of the object named name.
func (s *BlobStore) write(ctx context.Context, name, ext string, data []byte, overwrite bool) error {
	key, err := s.blobKey(name, ext)
	if err != nil {
		return err
	}
	blob := &TPMBlob{Key: key, Tenant: s.tenant, Name: name, Ext: ext, Data: data}
	if overwrite {
		if err := s.blobs.Save(ctx, blob); err != nil {
			return &BlobWriteError{Name: key, Cause: err}
		}
		return nil
	}
	stored, err := s.blobs.SaveIfAbsent(ctx, blob)
	if err != nil {
		return &BlobWriteError{Name: key, Cause: err}
	}
	if !stored {
		return &BlobWriteError{Name: key, Cause: ErrBlobExists}
	}
	return nil
}

// remove deletes the ext blob of the object named name, reporting whether it
// was stored; an absent blob is not an error.
func (s *BlobStore) remove(ctx context.Context, name, ext string) (removed bool, err error) {
	key, err := s.blobKey(name, ext)
	if err != nil {
		return false, err
	}
	blob, err := s.blobs.GetByNaturalKey(ctx, key)
	if qrdbsdk.IsDAONotFound(err) {
		return false, nil
	}
	if err == nil {
		err = s.blobs.Delete(ctx, blob)
	}
	if err != nil {
		return false, &BlobDeleteError{Name: key, Cause: err}
	}
	return true, nil
}
