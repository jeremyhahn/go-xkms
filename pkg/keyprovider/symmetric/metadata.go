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

package symmetric

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// keyMetadataSchemaVersion is the schema version of keyMetadata: it carries
// SchemaVersion, Exportable, Sensitive, TenantID and Partition. A key ID
// string (format [partition:]sw:secret:cn:algorithm, see Backend.ListKeys)
// has no room for anything beyond the fields it already encodes, so any key
// attribute that must survive a restart needs this separate persisted
// record. loadKeyMetadata requires an exact match: there is no older shape
// to fall back to, and a record from any other version is a typed error
// rather than a guess at its intent.
const keyMetadataSchemaVersion = 3

// keyMetadata is the versioned record persisted alongside a symmetric key's
// raw bytes to carry attributes that the key ID string cannot encode. It is
// JSON-encoded to match the rest of this package's on-disk conventions (see
// storeSymmetricKey's use of the same storage.Backend for key material).
//
// keyMetadata is written and read exclusively through SaveKeyMetadata /
// GetKeyMetadata / DeleteKeyMetadata in pkg/storage, which route through the
// identical storage.Backend the key material itself uses. That is the seam
// where the system/tenant barrier applies its encryption, so this record
// inherits whatever sealing already protects the key it describes. Nothing
// in this type may be persisted through any other channel.
type keyMetadata struct {
	// SchemaVersion identifies the shape of this record.
	SchemaVersion int `json:"schema_version"`

	// Exportable mirrors types.KeyAttributes.Exportable as supplied by the
	// caller at key creation or import time. Only newKeyMetadata may set
	// this field to true; nothing downstream of key creation is permitted
	// to widen a key from non-exportable to exportable.
	Exportable bool `json:"exportable"`

	// Sensitive mirrors types.KeyAttributes.Sensitive as supplied by the caller
	// at key creation or import time, and is what the service layer consults
	// before releasing plaintext. Like Exportable, only newKeyMetadata sets it,
	// so nothing downstream of creation can clear it.
	Sensitive bool `json:"sensitive"`

	// TenantID is the tenant that owns the key, empty for an untenanted key.
	TenantID string `json:"tenant_id,omitempty"`

	// Partition is the key's partition, empty when unpartitioned.
	Partition string `json:"partition,omitempty"`
}

// newKeyMetadata builds the current-schema keyMetadata record for attrs.
// It exists as a single choke point for Exportable so that "exportable" can
// only ever come from the caller's own attributes at creation time.
func newKeyMetadata(attrs *types.KeyAttributes) *keyMetadata {
	return &keyMetadata{
		SchemaVersion: keyMetadataSchemaVersion,
		Exportable:    attrs.Exportable,
		Sensitive:     attrs.Sensitive,
		TenantID:      attrs.TenantID,
		Partition:     string(attrs.Partition),
	}
}

// saveKeyMetadata persists metadata for keyID through the backend's
// storage.Backend, the same seam key material goes through via storage.SaveKey,
// so the record inherits whatever barrier encryption is configured.
func (b *Backend) saveKeyMetadata(ctx context.Context, keyID string, attrs *types.KeyAttributes) error {
	data, err := json.Marshal(newKeyMetadata(attrs))
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal key metadata", Err: err}
	}
	if err := storage.SaveKeyMetadata(ctx, b.storage, keyID, data); err != nil {
		return &errs.Wrapped{Msg: "failed to store key metadata", Err: err}
	}
	return nil
}

// saveKeyMetadataOrRollback persists the metadata record and, if that fails,
// removes the key blob the caller has just committed.
//
// Key material and its metadata are two separate storage keys -- keys/<id>.key
// and meta/<id>.json -- and storage.Backend offers no multi-key transaction, so
// the pair cannot be committed atomically. Without the compensating delete a
// failed write returns an error while the bytes stay durably stored, and the
// key that results is worse than no key at all: loadKeyMetadata reads a missing
// record as Exportable=false, Sensitive=true, so the key exists under a policy
// the caller never asked for and cannot be exported or released. Because both
// callers refuse to overwrite an existing ID, the orphan then blocks its own
// recovery -- a retry gets backend.ErrKeyAlreadyExists.
//
// Both callers check for an existing key before writing, so the blob deleted
// here is always the one this operation wrote. This must not be used on a path
// that can overwrite: there the delete would destroy the previous key rather
// than restore it.
func (b *Backend) saveKeyMetadataOrRollback(ctx context.Context, keyID string, attrs *types.KeyAttributes) error {
	err := b.saveKeyMetadata(ctx, keyID, attrs)
	if err == nil {
		return nil
	}
	if delErr := storage.DeleteKey(ctx, b.storage, keyID); delErr != nil {
		return &errs.Affix{
			Prefix: "failed to store key metadata: ",
			Err:    err,
			Suffix: fmt.Sprintf(" (rollback of key %s also failed: %v)", keyID, delErr),
		}
	}
	return err
}

// SaveKeyMetadata persists the attributes that a key's identifier cannot carry.
//
// It exists because SoftwareBackend's import ceremony stores symmetric key
// bytes itself rather than delegating to Backend.ImportKey, and so bypasses the
// metadata step that GenerateSymmetricKey and ImportKey both perform. Without
// this, a key imported through C_UnwrapKey read back as non-exportable no
// matter what CKA_EXTRACTABLE the caller asked for -- the attribute was
// accepted and then quietly lost, exactly the defect this metadata record was
// introduced to close.
func (b *Backend) SaveKeyMetadata(ctx context.Context, keyID string, attrs *types.KeyAttributes) error {
	return b.saveKeyMetadata(ctx, keyID, attrs)
}

// loadKeyMetadata retrieves metadata for keyID.
//
// Every key this package creates writes its metadata record in the same
// operation that writes the key material (see saveKeyMetadataOrRollback and
// SaveKeyMetadata), so a missing record, an unparseable record, or a record
// stamped with any schema version other than the current one means the key
// was not created through a supported path. loadKeyMetadata reports that as
// a typed error rather than substituting a guessed default: ListKeys and
// every other caller must fail rather than silently misreport a key's
// Exportable or Sensitive attribute.
func (b *Backend) loadKeyMetadata(ctx context.Context, keyID string) (*keyMetadata, error) {
	data, err := storage.GetKeyMetadata(ctx, b.storage, keyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &errs.Detail{Err: ErrKeyMetadataNotFound, Detail: keyID}
		}
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to read key metadata for %s", keyID), Err: err}
	}
	var metadata keyMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to parse key metadata for %s", keyID), Err: err}
	}
	if metadata.SchemaVersion != keyMetadataSchemaVersion {
		return nil, &errs.Message{Msg: fmt.Sprintf(
			"key metadata for %s uses unsupported schema version %d, want %d",
			keyID, metadata.SchemaVersion, keyMetadataSchemaVersion)}
	}
	return &metadata, nil
}

// deleteKeyMetadata removes the metadata record for keyID so a deleted key
// leaves no orphaned record behind. Every key created through this package
// has a metadata record, so a missing record is reported as
// ErrKeyMetadataNotFound rather than treated as the ordinary case.
func (b *Backend) deleteKeyMetadata(ctx context.Context, keyID string) error {
	if err := storage.DeleteKeyMetadata(ctx, b.storage, keyID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return &errs.Detail{Err: ErrKeyMetadataNotFound, Detail: keyID}
		}
		return &errs.Wrapped{Msg: "failed to delete key metadata", Err: err}
	}
	return nil
}
