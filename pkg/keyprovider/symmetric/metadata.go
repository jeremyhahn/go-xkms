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
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// keyMetadataSchemaVersion1 is the first schema version of keyMetadata. A
// key ID string (format [partition:]sw:secret:cn:algorithm, see
// Backend.ListKeys) has no room for anything beyond the fields it already
// encodes, so any key attribute that must survive a restart -- currently
// just Exportable -- needs a separate persisted record. Recording the
// schema explicitly, rather than inferring the shape from which fields are
// present, lets loadKeyMetadata evolve the format later without guessing
// at an older record's intent.
const keyMetadataSchemaVersion1 = 1

// keyMetadataSchemaVersion2 adds Sensitive, the PKCS#11 CKA_SENSITIVE the
// service layer checks before releasing a key's plaintext. It was added
// because that decision was previously reachable only through the calling
// module's own object store, which is client-side state.
const keyMetadataSchemaVersion2 = 2

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
	//
	// Present from schema version 2. A version 1 record has no such field, so it
	// decodes to false and loadKeyMetadata corrects it to true -- see there for
	// why an unrecorded sensitivity must be read as the protective value.
	Sensitive bool `json:"sensitive"`
}

// newKeyMetadata builds the current-schema keyMetadata record for attrs.
// It exists as a single choke point for Exportable so that "exportable" can
// only ever come from the caller's own attributes at creation time.
func newKeyMetadata(attrs *types.KeyAttributes) *keyMetadata {
	return &keyMetadata{
		SchemaVersion: keyMetadataSchemaVersion2,
		Exportable:    attrs.Exportable,
		Sensitive:     attrs.Sensitive,
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

// loadKeyMetadata retrieves metadata for keyID, falling back to the safe
// defaults (Exportable=false, Sensitive=true) when no record exists or the
// stored record cannot be parsed.
//
// A missing or corrupt record is intentionally not an error: every key
// created before metadata persistence existed has no record at all, and
// failing ListKeys or any other reader for that reason would break every
// pre-existing key. Exportable=false is the same default attrs.Validate
// already applies to a freshly constructed types.KeyAttributes, so keys
// that predate this format behave exactly as they did before it existed.
//
// # Sensitive on a version 1 record
//
// A version 1 record predates the field and says nothing about sensitivity, so
// it is read as sensitive: the safe value, not the convenient one.
//
// PKCS#11 makes this the only defensible reading. CKA_SENSITIVE carries
// footnote 11 -- "attribute cannot be changed once set to CK_TRUE" -- and
// CKA_EXTRACTABLE carries footnote 12, the same rule for CK_FALSE. Both
// ratchets turn one way only, toward more protection, and a conforming token
// has no operation that weakens a key. Supplying "not sensitive" for a key
// whose sensitivity was never recorded would be this store asserting the less
// protective of the two values on the key's behalf, which is the single
// direction the specification does not permit.
//
// Nothing is stranded by this. ExportKeyMaterial releases plaintext, and
// plaintext release is the path CKA_SENSITIVE exists to close; a version 1 key
// with Exportable=true is still wrappable through C_WrapKey, which is governed
// by CKA_EXTRACTABLE and is the ordinary way a key leaves an HSM. Failing
// closed here withdraws the unsafe path and leaves the safe one intact.
func (b *Backend) loadKeyMetadata(ctx context.Context, keyID string) *keyMetadata {
	data, err := storage.GetKeyMetadata(ctx, b.storage, keyID)
	if err != nil {
		return legacyKeyMetadata()
	}
	var metadata keyMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return legacyKeyMetadata()
	}
	if metadata.SchemaVersion < keyMetadataSchemaVersion2 {
		// The field is absent from the stored JSON, so it decoded to false.
		// Restore the protective reading the record itself cannot supply.
		metadata.Sensitive = true
	}
	return &metadata
}

// legacyKeyMetadata is the record assumed for a key with no readable metadata:
// one that predates metadata persistence entirely, or whose record cannot be
// parsed. Both protections are at their safe setting, so a key the store cannot
// describe is neither exportable nor revealable.
func legacyKeyMetadata() *keyMetadata {
	return &keyMetadata{
		SchemaVersion: keyMetadataSchemaVersion1,
		Exportable:    false,
		Sensitive:     true,
	}
}

// deleteKeyMetadata removes the metadata record for keyID so a deleted key
// leaves no orphaned record behind.
//
// storage.ErrNotFound is swallowed rather than propagated: keys created
// before metadata persistence existed never had a record to begin with, and
// DeleteKey must still succeed for them.
func (b *Backend) deleteKeyMetadata(ctx context.Context, keyID string) error {
	if err := storage.DeleteKeyMetadata(ctx, b.storage, keyID); err != nil {
		if err == storage.ErrNotFound {
			return nil
		}
		return &errs.Wrapped{Msg: "failed to delete key metadata", Err: err}
	}
	return nil
}
