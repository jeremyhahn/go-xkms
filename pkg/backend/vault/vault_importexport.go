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

//go:build vault

// Package vault's import/export half implements HashiCorp Vault Transit's
// own "bring your own key" (BYOK) ceremony for importing symmetric key
// material, and Transit's raw key export for keys created with
// exportable=true. Both are genuine Vault Transit capabilities, not local
// emulation: the wrapping key in GetImportParameters is the one
// transit/wrapping_key returns (Vault's own RSA public key, whose private
// half never leaves Vault), and ImportKey's ciphertext is unwrapped inside
// Vault's own transit/keys/:name/import endpoint. Two operations this
// interface defines have no Vault-native equivalent and refuse with a typed
// error rather than emulating one locally: UnwrapKey (the unwrapping half of
// the BYOK ceremony runs inside Vault during ImportKey, exactly as it does
// for AWS KMS) and ExportKey (Vault has no server-side primitive to wrap key
// material out for an arbitrary third-party recipient; only
// ExportKeyMaterial, for keys created exportable, is genuine).
package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// vaultBYOKKeyType is the only Transit key type this backend's BYOK ceremony
// imports: 256-bit AES-GCM, matching the sole type GenerateSymmetricKey
// creates.
const vaultBYOKKeyType = "aes256-gcm96"

// vaultBYOKEphemeralKeySize is the ephemeral AES key size, in bytes, this
// backend generates to wrap target key material for Vault's BYOK ceremony.
// HashiCorp's Transit "Importing Keys" documentation specifies AES-256.
const vaultBYOKEphemeralKeySize = 32

// GetImportParameters retrieves Vault Transit's own wrapping public key from
// transit/wrapping_key. The private half never leaves Vault: it is generated
// and held internally, and Vault rotates it periodically, so (unlike AWS
// KMS's per-request import token) there is no token to associate with this
// call and no fixed expiry to report -- both ImportParameters.ImportToken
// and ExpiresAt are left unset, which the type's own doc comments say is
// valid for a backend that doesn't use them.
//
// Only algorithm is backend.WrappingAlgorithmVaultTransitBYOK: it is the one
// wire format transit/keys/:name/import accepts, so a caller cannot select
// one of the project's other wrapping algorithms here the way it can for a
// backend with its own hybrid RSA+AES-KWP wrapping.
func (b *Backend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: ErrAsymmetricImportNotSupported, Detail: attrs.KeyAlgorithm.String()}
	}
	if algorithm != backend.WrappingAlgorithmVaultTransitBYOK {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf(
			"%s; Vault Transit BYOK import requires %s", algorithm, backend.WrappingAlgorithmVaultTransitBYOK)}
	}

	path := fmt.Sprintf("%s/wrapping_key", b.config.TransitPath)
	secret, err := b.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read Vault Transit wrapping key", Err: err}
	}
	if secret == nil || secret.Data == nil {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no wrapping key returned"}
	}

	pemStr, ok := secret.Data["public_key"].(string)
	if !ok || pemStr == "" {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "wrapping key response has no public_key"}
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "wrapping key is not valid PEM"}
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse Vault Transit wrapping key", Err: err}
	}
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: ErrWrappingKeyNotRSA, Detail: fmt.Sprintf("%T", pubKey)}
	}

	return &backend.ImportParameters{
		WrappingPublicKey: rsaPub,
		Algorithm:         algorithm,
		KeySpec:           vaultBYOKKeyType,
	}, nil
}

// WrapKey wraps keyMaterial for Vault Transit's BYOK ceremony: an ephemeral
// AES-256 key is generated, keyMaterial is sealed under it with AES-256-GCM
// using an all-zero 96-bit nonce (safe only because the ephemeral key is
// used exactly once and is never reused or persisted), and the ephemeral key
// itself is sealed with RSA-OAEP-SHA256 under Vault's wrapping public key.
// The two sealed values are concatenated -- RSA-OAEP output first, at its
// fixed modulus-sized length, then the GCM ciphertext -- exactly as
// HashiCorp's Transit "Importing Keys" documentation specifies. Vault
// recovers the split point itself from its own wrapping key's modulus size,
// so no length prefix travels on the wire.
func (b *Backend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "key material cannot be nil or empty"}
	}
	if params == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import parameters cannot be nil"}
	}
	if params.Algorithm != backend.WrappingAlgorithmVaultTransitBYOK {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf(
			"%s; Vault Transit BYOK import requires %s", params.Algorithm, backend.WrappingAlgorithmVaultTransitBYOK)}
	}
	rsaPub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "wrapping public key must be an *rsa.PublicKey"}
	}

	ephemeralKey := make([]byte, vaultBYOKEphemeralKeySize)
	if _, err := rand.Read(ephemeralKey); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate ephemeral wrapping key", Err: err}
	}

	wrappedEphemeral, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, ephemeralKey, nil)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap ephemeral key with RSA-OAEP", Err: err}
	}

	block, err := aes.NewCipher(ephemeralKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create ephemeral cipher", Err: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create ephemeral GCM", Err: err}
	}
	// The all-zero nonce is the format Vault documents for this ceremony.
	// It is only safe because ephemeralKey is freshly generated above and
	// used for this single Seal call: reusing a key with a fixed nonce for
	// more than one message is the catastrophic AES-GCM failure this
	// project's own AEAD safety tracker exists to prevent elsewhere, but
	// there is no second message here for it to fail against.
	nonce := make([]byte, gcm.NonceSize())
	sealed := gcm.Seal(nil, nonce, keyMaterial, nil)

	combined := make([]byte, 0, len(wrappedEphemeral)+len(sealed))
	combined = append(combined, wrappedEphemeral...)
	combined = append(combined, sealed...)

	return &backend.WrappedKeyMaterial{
		WrappedKey: combined,
		Algorithm:  params.Algorithm,
		Metadata:   map[string]string{"hash_function": "SHA256"},
	}, nil
}

// UnwrapKey is not supported: Vault performs the unwrap for its own BYOK
// ceremony internally, inside transit/keys/:name/import, using the private
// half of the wrapping key that transit/wrapping_key never exposes. This
// mirrors AWS KMS's UnwrapKey exactly, and for the identical reason -- the
// private unwrapping key never leaves the service boundary that makes the
// import meaningful.
func (b *Backend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: "Vault Transit performs unwrapping internally during ImportKey"}
}

// ImportKey imports symmetric key material into a new Vault Transit key
// using transit/keys/:name/import, the server-side half of the BYOK
// ceremony WrapKey prepared the ciphertext for.
func (b *Backend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}
	if wrapped == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material cannot be nil"}
	}
	if len(wrapped.WrappedKey) == 0 {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material is empty"}
	}
	if !attrs.IsSymmetric() {
		return &errs.Detail{Err: ErrAsymmetricImportNotSupported, Detail: attrs.KeyAlgorithm.String()}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := attrs.Validate(); err != nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	exists, err := storage.KeyExists(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to check key existence", Err: err}
	}
	if exists {
		return &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: attrs.CN}
	}

	keyName := b.sanitizeKeyName(attrs.CN)
	path := fmt.Sprintf("%s/keys/%s/import", b.config.TransitPath, keyName)
	data := map[string]interface{}{
		"ciphertext":             base64.StdEncoding.EncodeToString(wrapped.WrappedKey),
		"type":                   vaultBYOKKeyType,
		"hash_function":          "SHA256",
		"exportable":             attrs.Exportable,
		"allow_plaintext_backup": false,
	}

	if _, err := b.client.Logical().WriteWithContext(ctx, path, data); err != nil {
		return &errs.Wrapped{Msg: "failed to import key material into vault", Err: err}
	}

	// Metadata mirrors GenerateSymmetricKey's record exactly (see
	// vault_symmetric.go), since every other operation on this key --
	// GetSymmetricKey, SymmetricEncrypter, ExportKeyMaterial -- reads it back
	// through that same shape regardless of whether the key was generated or
	// imported.
	metadata := map[string]interface{}{
		"cn":                  attrs.CN,
		"symmetric_algorithm": string(attrs.SymmetricAlgorithm),
		"key_type":            string(attrs.KeyType),
		"store_type":          backend.STORE_VAULT,
		"vault_name":          keyName,
		"key_size":            256,
		"symmetric":           true,
		"exportable":          attrs.Exportable,
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}
	if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
		return &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	if b.tracker != nil {
		aeadOpts := attrs.AEADOptions
		if aeadOpts == nil {
			aeadOpts = types.DefaultAEADOptions()
		}
		if err := b.tracker.SetAEADOptions(attrs.CN, aeadOpts); err != nil {
			return &errs.Wrapped{Msg: "failed to set AEAD options", Err: err}
		}
	}

	return nil
}

// ExportKey has no genuine Vault-native equivalent: Transit's wrapping key
// exists to receive BYOK material, not to wrap material out for an
// arbitrary third-party recipient, so there is no server-side primitive to
// build a real implementation on. Faking one with a locally generated
// ephemeral keypair (the way the software and symmetric backends' ExportKey
// do for their own local ceremony) would not be genuine either: it would
// silently produce material only THIS process can ever unwrap, since Vault
// itself never sees or uses that keypair, which is not what a caller
// migrating a key to a different backend is asking for.
//
// A symmetric key created with Exportable=true remains reachable through
// ExportKeyMaterial, which is genuine.
func (b *Backend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	return nil, &errs.Detail{Err: backend.ErrOperationNotSupported, Detail: ErrWrappedExportNotSupported.Error()}
}

// ExportKeyMaterial returns the raw key material for a symmetric key created
// with Exportable=true, using Vault Transit's own transit/export endpoint --
// the one operation in this file's ceremony Vault performs exactly as
// documented, with no local emulation of any kind.
func (b *Backend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if !attrs.IsSymmetric() {
		return nil, backend.ErrAsymmetricKeyExportNotAllowed
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	metadataBytes, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: attrs.CN}
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unmarshal metadata", Err: err}
	}

	exportable, _ := metadata["exportable"].(bool)
	if !exportable {
		return nil, backend.ErrKeyNotExportable
	}
	keyName, ok := metadata["vault_name"].(string)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "missing vault_name"}
	}

	path := fmt.Sprintf("%s/export/encryption-key/%s/latest", b.config.TransitPath, keyName)
	secret, err := b.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to export key material from vault", Err: err}
	}
	if secret == nil || secret.Data == nil {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no key material returned"}
	}

	keysMap, ok := secret.Data["keys"].(map[string]interface{})
	if !ok || len(keysMap) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "export response has no keys"}
	}

	// The "latest" version request returns exactly one version's material;
	// which key of the map holds it is Vault's internal version number, not
	// something the caller named, so the first (and only) entry is taken
	// rather than a version this backend would have to track separately.
	var encoded string
	for _, v := range keysMap {
		s, ok := v.(string)
		if !ok {
			return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "export response key material is not a string"}
		}
		encoded = s
		break
	}

	keyMaterial, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode exported key material", Err: err}
	}
	return keyMaterial, nil
}

// Verify interface compliance at compile time. *Backend implements the
// symmetric-only BYOK import ceremony and genuine raw-material export for
// real; UnwrapKey and ExportKey above always refuse with a typed,
// correctly-classified error for the reasons their own doc comments give,
// which is what "this backend does not have a server-side primitive for
// that specific operation" looks like -- not a stub, since neither one has
// an incomplete-but-someday version to write.
var _ backend.ImportBackend = (*Backend)(nil)
var _ backend.ExportBackend = (*Backend)(nil)
var _ backend.ImportExportBackend = (*Backend)(nil)
