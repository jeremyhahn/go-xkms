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

package pkcs8

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	ecdhpkg "github.com/jeremyhahn/go-xkms/pkg/crypto/ecdh"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/youmark/pkcs8"
)

// PKCS8Backend implements the Backend interface using PKCS#8 encoding
// for key storage. Keys are stored using the provided storage Backend implementation.
//
// This backend is software-based and supports RSA, ECDSA, and Ed25519 keys.
// Keys can be optionally encrypted with a password using PKCS#8 encryption.
//
// Security: by default the backend is fail-closed — GenerateKey returns
// ErrPlaintextKeyNotAllowed when no password is provided. Set
// Config.AllowPlaintextKeys to opt into unencrypted persistence.
//
// Thread-safe: Yes, uses a read-write mutex for concurrent access.
type PKCS8Backend struct {
	storage        storage.Backend
	closed         bool
	allowPlaintext bool
	mu             sync.RWMutex
}

// Type returns the backend type identifier.
func (b *PKCS8Backend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

// Capabilities returns what features this backend supports.
func (b *PKCS8Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: false,
		Import:              true, // PKCS#8 supports key import via standard encoding
		Export:              true, // PKCS#8 supports key export via standard encoding
		KeyAgreement:        true, // PKCS#8 supports ECDH key agreement (P-256, P-384, P-521, X25519)
		ECIES:               false,
	}
}

// keyMetadataSchemaVersion is the schema version of keyMetadata: it carries
// SchemaVersion, CN, KeyType, StoreType, KeyAlgorithm, TenantID, Partition,
// Exportable, Hash and KeyOrigin. There is a single supported shape; every
// field is read directly from whatever record exists, with no
// version-gated inference.
const keyMetadataSchemaVersion = 2

// keyMetadata is the record persisted alongside a key's PKCS#8 bytes to carry
// the attributes the key identifier cannot express.
//
// The identifier produced by types.KeyAttributes.ID() is
// [tenant:][partition:]storetype:keytype:cn:algorithm. A tenant-scoped key
// with no partition and an untenanted key with a partition therefore produce
// identifiers of the same shape, and nothing in the string says which of the
// two the leading segment is. The tenant has to be recoverable -- a
// tenant-scoped view of a backend filters ListKeys on
// types.KeyAttributes.TenantID, and a key that reports no tenant is invisible
// to the tenant that owns it -- so it is recorded here rather than inferred.
//
// The record is written through the backend's own storage.Backend, the same
// seam the key material goes through, so it inherits whatever barrier
// encryption protects the key it describes.
type keyMetadata struct {
	// SchemaVersion identifies the shape of this record.
	SchemaVersion int `json:"schema_version,omitempty"`

	// CN, KeyType, StoreType and KeyAlgorithm mirror the identifier's own
	// segments. They were present before the schema was versioned and are
	// kept so an operator reading a record out of storage can identify the
	// key it belongs to without parsing the path.
	CN           string `json:"cn"`
	KeyType      string `json:"key_type"`
	StoreType    string `json:"store_type"`
	KeyAlgorithm string `json:"key_algorithm"`

	// TenantID is the tenant that owns the key, empty for an untenanted key.
	TenantID string `json:"tenant_id,omitempty"`

	// Partition is the key's partition, empty when unpartitioned.
	Partition string `json:"partition,omitempty"`

	// Exportable mirrors types.KeyAttributes.Exportable as supplied by the
	// caller at key creation time.
	Exportable bool `json:"exportable"`

	// Hash is the digest the key is configured to use, as crypto.Hash's
	// numeric value. The identifier cannot express it, and before this record
	// carried it a digest set at import was simply discarded — the field was
	// inert rather than merely unpersisted (#162).
	Hash uint `json:"hash,omitempty"`

	// KeyOrigin records whether the key was generated in place or imported.
	// Unlike every other field here it is never supplied by a caller: the
	// service layer stamps it from the code path that ran, so that a relying
	// party reading it is reading a fact rather than an assertion.
	KeyOrigin string `json:"key_origin,omitempty"`
}

// newKeyMetadata builds the current-schema record for attrs.
func newKeyMetadata(attrs *types.KeyAttributes) *keyMetadata {
	return &keyMetadata{
		SchemaVersion: keyMetadataSchemaVersion,
		CN:            attrs.CN,
		KeyType:       attrs.KeyType.String(),
		StoreType:     string(attrs.StoreType),
		KeyAlgorithm:  attrs.KeyAlgorithm.String(),
		TenantID:      attrs.TenantID,
		Partition:     string(attrs.Partition),
		Exportable:    attrs.Exportable,
		Hash:          uint(attrs.Hash),
		KeyOrigin:     string(attrs.KeyOrigin),
	}
}

// metadataPath returns the storage path of keyID's metadata record.
//
// This package has always written the record to "meta/{id}", where
// pkg/storage's shared storage.MetadataPath helper uses "meta/{id}.json".
// Moving to the shared helper would leave every record written before that
// move unreadable, which would silently downgrade every existing exportable
// key to non-exportable, so the path this package already wrote is the path
// it keeps. Unifying the two requires a migration that reads both.
func metadataPath(keyID string) string {
	return "meta/" + keyID
}

// loadKeyMetadata returns the metadata record for keyID, or nil when no
// readable record exists.
//
// A missing or corrupt record is not an error: keys written before this
// package persisted metadata have none at all, and failing ListKeys for that
// reason would hide every one of them. Callers fall back to reading the
// identifier itself, which is how those keys were always read.
func (b *PKCS8Backend) loadKeyMetadata(ctx context.Context, keyID string) *keyMetadata {
	data, err := b.storage.Get(ctx, metadataPath(keyID))
	if err != nil {
		// Metadata is recoverable; a missing record only costs the attributes
		// the identifier cannot carry, so log at debug and keep listing.
		slog.Debug("pkcs8: failed to load key metadata",
			"keyID", keyID, "metaKey", metadataPath(keyID), "error", err)
		return nil
	}
	var metadata keyMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		slog.Debug("pkcs8: failed to parse key metadata",
			"keyID", keyID, "metaKey", metadataPath(keyID), "error", err)
		return nil
	}
	if metadata.SchemaVersion != keyMetadataSchemaVersion {
		// There is a single supported schema, so a record stamped with any
		// other version -- including the pre-tenant shape that predates
		// SchemaVersion existing at all, which decodes as 0 -- is invalid
		// data, not a shape to interpret. It is discarded exactly like a
		// corrupt record: the identifier's own parse stands, and
		// resolveKeyOrigin resolves KeyOriginUnknown for it.
		slog.Debug("pkcs8: key metadata record uses an unsupported schema version",
			"keyID", keyID, "metaKey", metadataPath(keyID),
			"schemaVersion", metadata.SchemaVersion, "want", keyMetadataSchemaVersion)
		return nil
	}
	return &metadata
}

// deleteKeyMetadata removes keyID's metadata record.
//
// storage.ErrNotFound is swallowed rather than propagated: a key written
// before this package persisted metadata never had a record, and deleting it
// must still succeed.
func (b *PKCS8Backend) deleteKeyMetadata(ctx context.Context, keyID string) error {
	if err := b.storage.Delete(ctx, metadataPath(keyID)); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return &errs.Wrapped{Msg: "failed to delete key metadata", Err: err}
	}
	return nil
}

// GenerateKey generates a new private key with the given attributes.
// The key is encoded in PKCS#8 format and stored using the KeyStorage.
//
// Supported algorithms:
//   - RSA: Requires RSAAttributes with KeySize (minimum 2048 bits)
//   - ECDSA: Requires ECCAttributes with Curve (P-256, P-384, P-521)
//   - Ed25519: No additional attributes required
//
// X25519 keys are supported via CustomKeyAlgorithm when X25519Attributes are present.
//
// If attrs.Password is provided, the key will be encrypted using PKCS#8 encryption.
func (b *PKCS8Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// b.mu serializes the encode+store+metadata sequence within this process and
	// guards b.closed. It is no longer the uniqueness mechanism: the
	// authoritative key-ID uniqueness guard is the storage layer's atomic
	// PutIfAbsent (storage.SaveKeyIfAbsent), which a replicated/clustered Backend
	// makes linearizable across nodes — something an in-process lock cannot do.
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()

	// Generate key based on algorithm
	var privateKey crypto.PrivateKey
	var err error

	// Check for X25519 key agreement key
	if attrs.X25519Attributes != nil {
		privateKey, err = b.generateX25519Key()
	} else {
		switch attrs.KeyAlgorithm {
		case x509.RSA:
			privateKey, err = b.generateRSAKey(attrs.RSAAttributes)
		case x509.ECDSA:
			privateKey, err = b.generateECDSAKey(attrs.ECCAttributes)
		case x509.Ed25519:
			privateKey, err = b.generateEd25519Key()
		default:
			return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: attrs.KeyAlgorithm.String()}
		}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "key generation failed", Err: err}
	}

	// Encode the key, then store it atomically only if its ID is unused. The
	// PutIfAbsent result is the authoritative uniqueness decision.
	keyData, err := b.encodeKey(privateKey, attrs.Password)
	if err != nil {
		return nil, err
	}
	stored, err := storage.SaveKeyIfAbsent(ctx, b.storage, keyID, keyData)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to store key", Err: err}
	}
	if !stored {
		return nil, &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: keyID}
	}

	// Store the metadata record. It carries the attributes the key identifier
	// cannot unambiguously encode -- the tenant above all -- so it is written
	// in the same operation as the key material and rolled back with it.
	metadataBytes, err := json.Marshal(newKeyMetadata(attrs))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}
	metaKey := metadataPath(keyID)
	if err := b.storage.Put(ctx, metaKey, metadataBytes); err != nil {
		// Roll back the key blob so a failed generation does not leave an
		// orphaned key that blocks regenerating under the same ID.
		if delErr := storage.DeleteKey(ctx, b.storage, keyID); delErr != nil {
			return nil, &errs.Affix{Prefix: "failed to store metadata: ", Err: err, Suffix: fmt.Sprintf(" (rollback of key %s also failed: %v)", keyID, delErr)}
		}
		return nil, &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	return privateKey, nil
}

// GetKey retrieves an existing private key by its attributes.
// Returns an error if the key does not exist.
func (b *PKCS8Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()
	keyData, err := storage.GetKey(ctx, b.storage, keyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: keyID}
		}
		return nil, &errs.Wrapped{Msg: "failed to retrieve key", Err: err}
	}

	// Decode the key
	privateKey, err := b.decodeKey(keyData, attrs.Password)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// DeleteKey removes a key identified by its attributes.
// Returns an error if the key does not exist.
func (b *PKCS8Backend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()
	if err := storage.DeleteKey(ctx, b.storage, keyID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: keyID}
		}
		return &errs.Wrapped{Msg: "failed to delete key", Err: err}
	}

	// Remove the metadata record so a deleted key leaves no orphaned tenant or
	// Exportable flag behind for a future key of the same identifier to
	// inherit.
	if err := b.deleteKeyMetadata(ctx, keyID); err != nil {
		return err
	}

	return nil
}

// storageKeyID holds the attribute segments recovered from a stored key
// identifier.
type storageKeyID struct {
	TenantID  string
	Partition string
	StoreType string
	KeyType   string
	CN        string
	Algorithm string
}

// parseStorageKeyID splits a stored key identifier into the attributes
// types.KeyAttributes.ID() encoded into it.
//
// The identifier is [tenant:][partition:]storetype:keytype:cn:algorithm, so
// the segment count tells all but one thing:
//
//	4 segments: neither tenant nor partition.
//	5 segments: one of the two is present, and the string does not say which.
//	6 segments: both, in that order.
//
// The five-segment case is read as a partition, which is how it was read
// before tenants existed and therefore what every key written back then
// means. That is the only case a caller must not rely on: ListKeys overlays
// the persisted metadata record, which states the tenant outright, and only
// falls back to this reading for keys that have no record.
//
// Note that the ambiguity is confined to the leading segment. Store type, key
// type, common name and algorithm sit at the same offsets from the end under
// either reading, so those four are recovered correctly regardless.
func parseStorageKeyID(id string) storageKeyID {
	parts := strings.Split(id, ":")

	switch {
	case len(parts) == 4:
		return storageKeyID{
			StoreType: parts[0],
			KeyType:   parts[1],
			CN:        parts[2],
			Algorithm: parts[3],
		}
	case len(parts) == 5:
		return storageKeyID{
			Partition: parts[0],
			StoreType: parts[1],
			KeyType:   parts[2],
			CN:        parts[3],
			Algorithm: parts[4],
		}
	case len(parts) >= 6:
		return storageKeyID{
			TenantID:  parts[0],
			Partition: parts[1],
			StoreType: parts[2],
			KeyType:   parts[3],
			CN:        strings.Join(parts[4:len(parts)-1], ":"),
			Algorithm: parts[len(parts)-1],
		}
	default:
		// Not an identifier this package produced. Treat the whole string as
		// a common name and apply the same defaults as before.
		return storageKeyID{
			StoreType: "pkcs8",
			KeyType:   "tls",
			CN:        id,
			Algorithm: "rsa",
		}
	}
}

// ListKeys returns attributes for all keys managed by this backend.
// Returns an empty slice if no keys exist.
//
// Attributes are recovered from the stored key identifier and from the
// metadata record persisted next to the key material. The record is
// authoritative for the tenant and the partition, which the identifier cannot
// distinguish from one another; see keyMetadata and parseStorageKeyID.
//
// Recovering the tenant is what makes a tenant-scoped view of this backend
// work at all: that view filters this listing on
// types.KeyAttributes.TenantID, and callers resolve a key by matching a common
// name against the result. While the tenant was dropped here, every key
// reported no owner, so a tenant saw an empty listing and could not resolve
// even its own keys.
func (b *PKCS8Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyIDs, err := storage.ListKeys(ctx, b.storage)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys", Err: err}
	}

	attrs := make([]*types.KeyAttributes, 0, len(keyIDs))
	for _, id := range keyIDs {
		parsed := parseStorageKeyID(id)

		// Skip symmetric keys - they are handled by the symmetric backend
		if strings.EqualFold(parsed.KeyType, "secret") {
			continue
		}

		// Skip quantum keys - they are handled by the quantum backend
		algoLower := strings.ToLower(parsed.Algorithm)
		quantumAlgo := types.QuantumAlgorithm(strings.ToUpper(parsed.Algorithm))
		if quantumAlgo.IsSignature() || quantumAlgo.IsKEM() {
			continue
		}

		attr := &types.KeyAttributes{
			CN:        parsed.CN,
			KeyType:   types.ParseKeyType(parsed.KeyType),
			StoreType: types.ParseStoreType(parsed.StoreType),
			TenantID:  parsed.TenantID,
			Partition: types.Partition(parsed.Partition),
		}

		// Parse key algorithm
		switch algoLower {
		case "rsa":
			attr.KeyAlgorithm = x509.RSA
			attr.RSAAttributes = &types.RSAAttributes{KeySize: 2048} // Default
		case "ecdsa":
			attr.KeyAlgorithm = x509.ECDSA
			curve, err := types.ParseCurve("P-256") // Default curve
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to resolve default curve", Err: err}
			}
			attr.ECCAttributes = &types.ECCAttributes{Curve: curve}
		case "ed25519":
			attr.KeyAlgorithm = x509.Ed25519
		case "x25519":
			// An X25519 agreement key is declared by X25519Attributes with
			// KeyAlgorithm left unset: that is the shape GenerateKey accepts
			// and the software backend's validateKeyType requires on
			// re-import (#154). It used to fall through to the RSA default
			// below and be listed as RSA-2048.
			attr.X25519Attributes = &types.X25519Attributes{}
		default:
			// An algorithm this backend does not produce is reported as
			// unknown: KeyAlgorithm stays UnknownPublicKeyAlgorithm and no
			// algorithm attributes are attached. Renaming it to RSA-2048, as
			// the defaults block once did, told a caller the key was
			// something it is not, and every re-import driven off the
			// listing then failed for the wrong reason (#154).
		}

		// Ensure we have valid defaults
		if attr.KeyType == 0 {
			attr.KeyType = types.KeyTypeTLS
		}
		if attr.StoreType == "" {
			attr.StoreType = types.StoreSoftware
		}

		// Overlay the persisted record. It is authoritative for the tenant and
		// the partition, which the identifier's own parse cannot distinguish
		// from each other; a key with no readable record keeps whatever the
		// identifier parse produced.
		metadata := b.loadKeyMetadata(ctx, id)
		if metadata != nil {
			attr.Exportable = metadata.Exportable
			attr.TenantID = metadata.TenantID
			attr.Partition = types.Partition(metadata.Partition)
			if metadata.Hash != 0 {
				attr.Hash = crypto.Hash(metadata.Hash)
			}
		}
		attr.KeyOrigin = resolveKeyOrigin(metadata)

		// AttestLevel needs no metadata round trip, unlike KeyOrigin: this
		// backend encodes every key as PKCS#8, which is software cryptography
		// by construction — there is no PKCS#8 record that could describe a
		// hardware-resident key, so the answer is the same for a key written
		// before this field existed as for one written after. A caller that
		// stamped a different value in memory before GenerateKey/ImportKey
		// wrote it (there should be none — see PIVKeyGenerator.AttestLevel,
		// which classifies this backend as software for exactly this reason)
		// is corrected here rather than trusted, the same way GenerateKey does
		// not accept a caller-supplied KeyOrigin.
		attr.AttestLevel = types.AttestLevelSoftware

		attrs = append(attrs, attr)
	}

	return attrs, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
// This allows the key to be used for signing operations without
// exposing the private key material.
func (b *PKCS8Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrKeyNotSigner
	}

	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
// This allows the key to be used for decryption operations without
// exposing the private key material.
func (b *PKCS8Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, ErrKeyNotDecrypter
	}

	return decrypter, nil
}

// Close releases any resources held by the backend.
// After calling Close, the backend should not be used.
func (b *PKCS8Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	return b.storage.Close()
}

// generateRSAKey generates a new RSA private key.
func (b *PKCS8Backend) generateRSAKey(attrs *types.RSAAttributes) (*rsa.PrivateKey, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "RSA attributes are required"}
	}

	// types.ValidateRSAKeySize is the one place the project's RSA modulus
	// floor and ceiling are written down; a local "< 2048" check here had no
	// ceiling at all, so a caller-supplied size (e.g. 65536) reached
	// rsa.GenerateKey uncancellably and pinned a CPU core for minutes to
	// hours (go-xkms#1260).
	if err := types.ValidateRSAKeySize(attrs.KeySize); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: err.Error()}
	}

	return rsa.GenerateKey(rand.Reader, attrs.KeySize)
}

// generateECDSAKey generates a new ECDSA private key.
func (b *PKCS8Backend) generateECDSAKey(attrs *types.ECCAttributes) (*ecdsa.PrivateKey, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "ECC attributes are required"}
	}

	if attrs.Curve == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "curve is required"}
	}

	return ecdsa.GenerateKey(attrs.Curve, rand.Reader)
}

// generateEd25519Key generates a new Ed25519 private key.
func (b *PKCS8Backend) generateEd25519Key() (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	return privateKey, err
}

// generateX25519Key generates a new X25519 private key for key agreement.
func (b *PKCS8Backend) generateX25519Key() (crypto.PrivateKey, error) {
	ka := x25519.New()
	keyPair, err := ka.GenerateKey()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "X25519 key generation failed", Err: err}
	}

	// Wrap the X25519 private key to implement crypto.PrivateKey
	wrappedKey, err := x25519.NewPrivateKeyStorage(keyPair.PrivateKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap X25519 private key", Err: err}
	}

	return wrappedKey, nil
}

// encodeKey encodes a private key in PKCS#8 format. When password is non-empty
// the encrypted-PKCS#8 form is produced; otherwise the unencrypted form is
// used. X25519 wrapped keys are unwrapped to their raw ecdh.PrivateKey before
// encoding. It performs no storage I/O.
func (b *PKCS8Backend) encodeKey(privateKey crypto.PrivateKey, password types.Password) ([]byte, error) {
	// Unwrap X25519 wrapped key if needed
	actualPrivateKey := privateKey
	if wrapped, ok := privateKey.(*x25519.PrivateKeyStorage); ok {
		// For X25519, store the raw ecdh.PrivateKey
		actualPrivateKey = wrapped.PrivateKey()
	}

	// Get password bytes if provided
	var passwordBytes []byte
	if password != nil {
		passwordBytes = password.Bytes()
	}

	// Encode the key
	if len(passwordBytes) > 0 {
		// Encrypted PKCS#8
		keyData, err := pkcs8.MarshalPrivateKey(actualPrivateKey, passwordBytes, encoding.PKCS8EncryptOpts)
		if err != nil {
			return nil, &errs.Detail{Err: ErrKeyEncodingFailed, Detail: fmt.Sprintf("%v", err)}
		}
		return keyData, nil
	}

	// Fail-closed: refuse unencrypted persistence unless explicitly opted in.
	// This protects CA signing keys and any other sensitive material that has
	// not been given a password. Callers that intentionally want plaintext
	// storage (e.g., ephemeral test backends, volume-encrypted deployments)
	// must set AllowPlaintextKeys: true in Config.
	if !b.allowPlaintext {
		return nil, ErrPlaintextKeyNotAllowed
	}

	// Unencrypted PKCS#8 — AllowPlaintextKeys is explicitly true.
	keyData, err := x509.MarshalPKCS8PrivateKey(actualPrivateKey)
	if err != nil {
		return nil, &errs.Detail{Err: ErrKeyEncodingFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return keyData, nil
}

// decodeKey decodes a PKCS#8 encoded private key.
// X25519 keys are automatically wrapped in PrivateKeyStorage for consistency.
func (b *PKCS8Backend) decodeKey(keyData []byte, password types.Password) (crypto.PrivateKey, error) {
	var passwordBytes []byte
	var err error

	if password != nil {
		passwordBytes = password.Bytes()
	}

	var privateKey crypto.PrivateKey

	// Try encrypted PKCS#8 if password provided
	if len(passwordBytes) > 0 {
		privateKey, err = pkcs8.ParsePKCS8PrivateKey(keyData, passwordBytes)
		if err != nil {
			return nil, &errs.Detail{Err: ErrKeyDecodingFailed, Detail: fmt.Sprintf("%v", err)}
		}
	} else {
		// Try unencrypted PKCS#8
		privateKey, err = x509.ParsePKCS8PrivateKey(keyData)
		if err != nil {
			// If a password interface was provided but returned empty/nil, and
			// unencrypted parsing failed, this likely means password retrieval
			// failed (e.g., TPM unseal error) and the key is actually encrypted.
			if password != nil {
				return nil, &errs.Detail{Err: ErrKeyDecodingFailed, Detail: fmt.Sprintf("unencrypted parsing failed and password retrieval returned empty (possible TPM unseal failure or key is encrypted): %v", err)}
			}
			return nil, &errs.Detail{Err: ErrKeyDecodingFailed, Detail: fmt.Sprintf("%v", err)}
		}
	}

	// Wrap X25519 keys for consistency
	if ecdhPrivKey, ok := privateKey.(*ecdh.PrivateKey); ok {
		if ecdhPrivKey.Curve() == ecdh.X25519() {
			wrapped, err := x25519.NewPrivateKeyStorage(ecdhPrivKey)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to wrap X25519 key", Err: err}
			}
			return wrapped, nil
		}
	}

	return privateKey, nil
}

// Public returns the public key corresponding to the private key.
// This is a helper method for signing operations.
func (b *PKCS8Backend) Public(ctx context.Context, attrs *types.KeyAttributes) (crypto.PublicKey, error) {
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *x25519.PrivateKeyStorage:
		return k.Public(), nil
	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("%T", key)}
	}
}

// Sign signs digest with the private key identified by attrs.
// This is a convenience method that wraps Signer().
func (b *PKCS8Backend) Sign(ctx context.Context, attrs *types.KeyAttributes, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signer, err := b.Signer(ctx, attrs)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, digest, opts)
}

// RotateKey rotates/updates a key identified by attrs.
// For PKCS#8 software keys, rotation means generating a new key and replacing the old one.
func (b *PKCS8Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if attrs == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	// Delete the old key
	if err := b.DeleteKey(ctx, attrs); err != nil && !errors.Is(err, backend.ErrKeyNotFound) {
		return &errs.Wrapped{Msg: "failed to delete old key", Err: err}
	}

	// Generate a new key with the same attributes
	_, err := b.GenerateKey(ctx, attrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to generate new key", Err: err}
	}

	return nil
}

// DeriveSharedSecret performs ECDH key agreement between the private key
// identified by attrs and the provided public key.
//
// Supports:
//   - X25519 keys for key agreement (32 bytes)
//   - NIST curves (P-256, P-384, P-521) via ECDSA keys
//
// Both keys must be compatible (same curve).
// The shared secret is the raw output of ECDH - use a KDF to derive encryption keys.
func (b *PKCS8Backend) DeriveSharedSecret(ctx context.Context, attrs *types.KeyAttributes, publicKey crypto.PublicKey) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	if publicKey == nil {
		return nil, &errs.Message{Msg: "public key cannot be nil"}
	}

	// Get the private key
	privateKey, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	// Handle different key types
	switch privKey := privateKey.(type) {
	case *x25519.PrivateKeyStorage:
		// X25519 key agreement
		pubKeyStorage, ok := publicKey.(*x25519.PublicKeyStorage)
		if !ok {
			return nil, &errs.Message{Msg: "public key must be X25519 for X25519 private key"}
		}
		ka := x25519.New()
		return ka.DeriveSharedSecret(privKey.PrivateKey(), pubKeyStorage.PublicKey())

	case *ecdsa.PrivateKey:
		// NIST curve ECDH (P-256, P-384, P-521)
		pubKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, &errs.Message{Msg: "public key must be ECDSA for ECDSA private key"}
		}
		// Use the ECDH package from pkg/crypto/ecdh
		return deriveECDHSharedSecret(privKey, pubKeyECDSA)

	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("%T does not support key agreement", privateKey)}
	}
}

// deriveECDHSharedSecret is a helper that performs ECDH with NIST curves (P-256, P-384, P-521).
func deriveECDHSharedSecret(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Check that curves match
	if privateKey.Curve != publicKey.Curve {
		return nil, &errs.Message{Msg: fmt.Sprintf("curve mismatch: private key uses %s, public key uses %s", privateKey.Curve.Params().Name, publicKey.Curve.Params().Name)}
	}

	// Use the ecdh package from pkg/crypto/ecdh for NIST curves
	return ecdhpkg.DeriveSharedSecret(privateKey, publicKey)
}

// Verify interface compliance at compile time.
var _ types.KeyProvider = (*PKCS8Backend)(nil)
var _ types.KeyAgreement = (*PKCS8Backend)(nil)

// resolveKeyOrigin returns the key's origin from its persisted record: a
// plain read, with no inference. A record with no origin recorded --
// because it has none at all, or because its key_origin field is empty --
// resolves to types.KeyOriginUnknown, exactly what the zero value means: the
// absence of a claim, not a claim of generation. Every security check that
// consumes this value (see pkg/xkms.refuseUnattestableKey) must fail closed
// on KeyOriginUnknown rather than treat it as safe.
func resolveKeyOrigin(metadata *keyMetadata) types.KeyOrigin {
	if metadata == nil {
		return types.KeyOriginUnknown
	}
	return types.KeyOrigin(metadata.KeyOrigin)
}

// WriteKeyMetadata persists attrs' metadata record for keyID into store.
//
// It exists because key material does not always arrive through this package.
// SoftwareBackend.ImportKey writes the PKCS#8 bytes to the same storage under
// the same identifier but bypasses PKCS8Backend entirely, so an imported key
// had no metadata record at all — and ListKeys, which reads the record, could
// therefore report neither the tenant, the exportability, nor the origin of
// any key that arrived by import. Those are exactly the attributes the
// identifier cannot express, which is why the record exists.
//
// The record's shape and path are this package's, so the writer lives here
// rather than being reimplemented by each caller against a format it would
// have to keep in step.
func WriteKeyMetadata(ctx context.Context, store storage.Backend, keyID string, attrs *types.KeyAttributes) error {
	if attrs == nil {
		return nil
	}
	data, err := json.Marshal(newKeyMetadata(attrs))
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal key metadata", Err: err}
	}
	if err := store.Put(ctx, metadataPath(keyID), data); err != nil {
		return &errs.Wrapped{Msg: "failed to store key metadata", Err: err}
	}
	return nil
}
