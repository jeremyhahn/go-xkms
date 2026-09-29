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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/google/uuid"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/importtoken"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Ensure Backend implements backend.ImportExportBackend interface
var _ backend.ImportExportBackend = (*Backend)(nil)

// azureBYOKKEKName is the fixed name of the RSA-HSM key-encryption key
// (KEK) this backend creates in the vault for Azure Key Vault's native BYOK
// import flow. One KEK is shared by every import ceremony the backend
// performs against a given vault: Azure Key Vault BYOK does not require a
// fresh KEK per import (unlike AWS KMS's GetParametersForImport, which
// issues a new wrapping keypair per call), and the KEK's private half never
// leaves Azure's HSM boundary regardless of how many times it is reused.
const azureBYOKKEKName = "xkms-byok-kek"

// azureBYOKKEKKeySize is the RSA key size, in bits, used for the BYOK KEK.
// 2048 is the minimum Azure Key Vault accepts for an RSA-HSM key and is
// sufficient here: the KEK only ever wraps a single ephemeral AES-256 key
// per import (via CKM_RSA_AES_KEY_WRAP -- see WrapKey), never the target
// key material directly.
const azureBYOKKEKKeySize = int32(2048)

// kekHandle names the Azure Key Vault BYOK key-encryption key GetImportParameters
// handed its caller a wrapping public key from.
type kekHandle struct {
	kid       string
	publicKey *rsa.PublicKey
}

// kekBinding records, for one in-flight import ceremony, the KEK
// GetImportParameters issued its wrapping public key from and the wrapping
// algorithm it was issued for, keyed by the opaque import token returned as
// ImportParameters.ImportToken. ImportKey binds both back: wrapped.Algorithm
// must match algorithm exactly, and the KEK Azure Key Vault reports at
// import time must still carry the same kid -- otherwise the blob was
// wrapped under a KEK that has since been rotated or recreated, and Azure's
// HSM can never unwrap it (go-xkms#1342). kekBinding never holds key
// material -- only bookkeeping -- so importtoken.Store needs no destroy
// callback for it.
type kekBinding struct {
	kekKID    string
	algorithm backend.WrappingAlgorithm
}

// GetImportParameters retrieves the parameters needed to import a key into
// Azure Key Vault using its native BYOK (bring-your-own-key) flow.
//
// Azure Key Vault's key_hsm transfer format is CKM_RSA_AES_KEY_WRAP:
// target key material is wrapped with an ephemeral AES-256 key using
// AES-KWP, and that AES key is wrapped with RSA-OAEP under a key-encryption
// key (KEK) whose private half never leaves Azure's HSM boundary. This
// backend therefore:
//
//  1. Ensures a vault-scoped RSA-HSM KEK exists (creating it with the
//     "import" key operation on first use, and reusing it on every
//     subsequent call -- see ensureKEK).
//  2. Returns the KEK's public half as WrappingPublicKey, so WrapKey never
//     needs Azure Key Vault to unwrap anything on this backend's behalf and
//     the target key's plaintext never exists inside this process (unlike
//     the ephemeral-local-RSA-keypair ceremony this backend used before
//     go-xkms#1342, which unwrapped key material locally before handing
//     Azure a plaintext JWK).
//
// The returned ImportParameters.ImportToken is a fresh, random, opaque
// handle bound (via b.importTokens) to the KEK's kid and to algorithm, so
// ImportKey can refuse a mismatched algorithm or a KEK that has since
// changed before ever presenting a wrapped blob to Azure Key Vault.
// b.importTokens enforces the ceremony's TTL and a hard cap on in-flight
// ceremonies (go-xkms#1261), exactly as it did for the local-unwrap
// ceremony it replaces.
func (b *Backend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if attrs == nil {
		return nil, &errs.Message{Msg: "attributes cannot be nil"}
	}

	// Azure Key Vault's key_hsm blob is always the CKM_RSA_AES_KEY_WRAP
	// hybrid construction -- RSA-OAEP wraps an ephemeral AES-256 key, which
	// then wraps the target key material with AES-KWP. Plain RSA-OAEP
	// wrapping (with no AES-KWP layer) is not a valid key_hsm encoding on
	// its own, so it is refused here rather than accepted and failing
	// later inside Azure.
	switch algorithm {
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Supported
	default:
		return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: fmt.Sprintf("Azure Key Vault BYOK requires a hybrid RSA+AES-KWP wrapping algorithm, got %s", algorithm)}
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	kek, err := b.ensureKEK(ctx)
	if err != nil {
		return nil, err
	}

	// The handle is random and carries no key material.
	token := uuid.New().String()

	// Put enforces the store's TTL and hard cap and sweeps expired
	// ceremonies before inserting this one. The entry records the KEK's kid
	// and algorithm alongside it, so ImportKey can refuse a mismatched
	// algorithm or a rotated KEK before ever presenting wrapped.WrappedKey
	// to Azure Key Vault (go-xkms#1342).
	expiresAt, err := b.importTokens.Put(token, &kekBinding{kekKID: kek.kid, algorithm: algorithm})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to store import token", Err: err}
	}

	// Determine key spec from attributes
	keySpec := ""
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
			keySpec = fmt.Sprintf("RSA_%d", attrs.RSAAttributes.KeySize)
		} else {
			keySpec = "RSA_2048"
		}
	case x509.ECDSA:
		if attrs.ECCAttributes != nil {
			keySpec = fmt.Sprintf("ECC_%s", attrs.ECCAttributes.Curve)
		} else {
			keySpec = "ECC_P256"
		}
	}

	return &backend.ImportParameters{
		WrappingPublicKey: kek.publicKey,
		ImportToken:       []byte(token),
		Algorithm:         algorithm,
		ExpiresAt:         &expiresAt,
		KeySpec:           keySpec,
	}, nil
}

// ensureKEK returns the vault's BYOK key-encryption key, creating it if it
// does not already exist. Creation is idempotent the same way CreateKey and
// CreateSecretKey (azurekv.go) already are: GetKey is tried first, and any
// failure -- not found, or otherwise -- falls through to CreateKey, which
// is safe because Azure Key Vault key names are unique and a second create
// against an existing name fails loudly rather than corrupting the first.
func (b *Backend) ensureKEK(ctx context.Context) (*kekHandle, error) {
	if resp, err := b.client.GetKey(ctx, azureBYOKKEKName, "", nil); err == nil && resp.Key != nil && resp.Key.KID != nil {
		return b.kekHandleFor(ctx, string(*resp.Key.KID))
	}

	// Not found (or otherwise unreadable): create it. RSA-HSM with the
	// "import" key operation is Azure Key Vault's key-encryption key for
	// BYOK -- Azure holds its private half inside its own HSM boundary and
	// only ever uses it to unwrap a key_hsm blob presented to ImportKey. It
	// is never returned to a caller, so the target key's plaintext never
	// exists outside Azure's HSM (go-xkms#1342).
	keyType := azkeys.KeyTypeRSAHSM
	keySize := azureBYOKKEKKeySize
	params := azkeys.CreateKeyParameters{
		Kty:     &keyType,
		KeySize: &keySize,
		KeyOps:  []*azkeys.KeyOperation{ptrKeyOp(azkeys.KeyOperationImport)},
	}
	resp, err := b.client.CreateKey(ctx, azureBYOKKEKName, params, nil)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create Azure Key Vault BYOK key-encryption key", Err: err}
	}
	if resp.Key == nil || resp.Key.KID == nil {
		return nil, &errs.Message{Msg: "invalid response creating Azure Key Vault BYOK key-encryption key"}
	}
	return b.kekHandleFor(ctx, string(*resp.Key.KID))
}

// kekHandleFor resolves the BYOK KEK's public key through the same
// GetPublicKey + parsePublicKey path Signer and Decrypter already use
// (azurekv.go), rather than decoding N/E off the raw GetKey/CreateKey JWK
// response: GetPublicKey is the one KeyVaultClient method this package
// treats as authoritative for a key's public half.
func (b *Backend) kekHandleFor(ctx context.Context, kid string) (*kekHandle, error) {
	pubKeyBytes, err := b.client.GetPublicKey(ctx, azureBYOKKEKName, "")
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to retrieve Azure Key Vault BYOK key-encryption key public key", Err: err}
	}
	pub, err := parsePublicKey(pubKeyBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse Azure Key Vault BYOK key-encryption key public key", Err: err}
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "Azure Key Vault BYOK key-encryption key is not RSA"}
	}
	return &kekHandle{kid: kid, publicKey: rsaPub}, nil
}

// WrapKey wraps key material for secure transport to Azure Key Vault using
// CKM_RSA_AES_KEY_WRAP -- RSA-OAEP wraps an ephemeral AES-256 key, which
// wraps keyMaterial with AES-KWP -- Azure Key Vault's native BYOK key_hsm
// transfer format. Wrapping happens entirely client-side against the KEK's
// public half from GetImportParameters; only the wrapped ciphertext is ever
// transmitted, and Azure Key Vault performs the corresponding unwrap
// itself, inside its HSM, during ImportKey.
func (b *Backend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, &errs.Message{Msg: "key material cannot be empty"}
	}
	if params == nil {
		return nil, &errs.Message{Msg: "import parameters cannot be nil"}
	}
	if params.WrappingPublicKey == nil {
		return nil, &errs.Message{Msg: "wrapping public key cannot be nil"}
	}

	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Message{Msg: "wrapping public key must be an *rsa.PublicKey"}
	}

	switch params.Algorithm {
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Azure Key Vault BYOK's key_hsm transfer format: CKM_RSA_AES_KEY_WRAP.
	default:
		return nil, &errs.Detail{Err: ErrInvalidAlgorithm, Detail: params.Algorithm.String()}
	}

	wrappedKey, err := wrapping.WrapRSAAES(keyMaterial, rsaPubKey, params.Algorithm)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key material", Err: err}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrappedKey,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey is not supported: Azure Key Vault's HSM performs the
// CKM_RSA_AES_KEY_WRAP unwrap itself, inside the vault, when ImportKey
// presents the wrapped blob as the JWK key_hsm field. This backend never
// holds the KEK's private half, so it has no way to unwrap key material
// locally even if it wanted to -- and it must not, since the entire point
// of the native BYOK flow is that the target key's plaintext never exists
// outside Azure's HSM boundary (go-xkms#1342). This mirrors gcpkms's
// UnwrapKey, which is native for the same reason.
func (b *Backend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: "unwrapping is performed by Azure Key Vault's HSM during import"}
}

// ImportKey imports externally generated key material into Azure Key Vault
// using its native BYOK flow. wrapped.WrappedKey is never unwrapped by this
// process: it is presented to Azure Key Vault as-is, as the JWK key_hsm (T)
// field, and Azure's HSM performs the CKM_RSA_AES_KEY_WRAP unwrap using the
// KEK's private half, which never leaves the HSM boundary. The target key's
// plaintext therefore never exists inside xkms at any point in the ceremony
// (go-xkms#1342).
//
// The import token is single-use: this call Takes it from b.importTokens
// whether or not the rest of the ceremony succeeds, so a completed or
// failed import cannot be replayed against different key material. Unknown,
// expired and already-consumed tokens are indistinguishable and all report
// backend.ErrKeyNotFound. wrapped.Algorithm must match the algorithm the
// token was issued for, and the vault's current KEK must still carry the
// kid GetImportParameters recorded -- a rotated or recreated KEK cannot
// unwrap a blob that was encrypted under its predecessor's public key.
func (b *Backend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if attrs == nil {
		return &errs.Message{Msg: "attributes cannot be nil"}
	}
	if wrapped == nil {
		return &errs.Message{Msg: "wrapped key material cannot be nil"}
	}
	if len(wrapped.ImportToken) == 0 {
		return &errs.Message{Msg: "import token is required"}
	}
	if len(wrapped.WrappedKey) == 0 {
		return &errs.Message{Msg: "wrapped key material is empty"}
	}

	if err := b.initClient(ctx); err != nil {
		return err
	}

	// Take the token: this call owns it whether or not the rest of the
	// ceremony succeeds, so a completed or failed import can never be
	// replayed.
	binding, err := b.importTokens.Take(string(wrapped.ImportToken))
	if err != nil {
		return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "invalid or expired import token"}
	}

	if binding.algorithm != wrapped.Algorithm {
		return &importtoken.AlgorithmMismatchError{Issued: binding.algorithm, Requested: wrapped.Algorithm}
	}

	// Re-resolve the KEK: if it was deleted and recreated since
	// GetImportParameters issued this token, its kid changed and the
	// wrapped blob -- encrypted under the previous public key -- can never
	// be unwrapped by Azure's HSM. Refuse here instead of sending Azure a
	// doomed import request.
	kek, err := b.ensureKEK(ctx)
	if err != nil {
		return err
	}
	if kek.kid != binding.kekKID {
		return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "Azure Key Vault BYOK key-encryption key changed since import parameters were issued"}
	}

	azureJWK, err := nativeAzureJWK(attrs, wrapped.WrappedKey)
	if err != nil {
		return err
	}

	params := azkeys.ImportKeyParameters{
		Key: azureJWK,
		HSM: ptrBool(true),
		KeyAttributes: &azkeys.KeyAttributes{
			Enabled: ptrBool(true),
		},
	}

	if _, err := b.client.ImportKey(ctx, attrs.CN, params, nil); err != nil {
		return &errs.Wrapped{Msg: "failed to import key into Azure Key Vault", Err: err}
	}

	// Store metadata
	metadata := map[string]interface{}{
		"cn":          attrs.CN,
		"algorithm":   attrs.KeyAlgorithm.String(),
		"key_type":    attrs.KeyType.String(), // see the CreateKey comment in azurekv.go
		"imported":    true,
		"import_time": time.Now().Unix(),
		"kek_kid":     kek.kid,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
		return &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	return nil
}

// nativeAzureJWK builds the JWK ImportKey sends to Azure Key Vault for the
// native BYOK flow: Kty names the HSM-protected key type Azure should
// materialize once it unwraps wrappedKey, and T (key_hsm) carries the
// CKM_RSA_AES_KEY_WRAP blob itself. No key components (N, E, D, X, Y, ...)
// are ever set here -- unlike the plaintext-JWK path this function replaces
// (go-xkms#1342), Azure's HSM recovers those from wrappedKey once it
// unwraps it, so this process never sees them.
func nativeAzureJWK(attrs *types.KeyAttributes, wrappedKey []byte) (*azkeys.JSONWebKey, error) {
	jwk := &azkeys.JSONWebKey{T: wrappedKey}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		keyType := azkeys.KeyTypeRSAHSM
		jwk.Kty = &keyType
		jwk.KeyOps = rsaKeyOpsFor(attrs)

	case x509.ECDSA:
		keyType := azkeys.KeyTypeECHSM
		jwk.Kty = &keyType
		curveName, err := eccCurveName(attrs)
		if err != nil {
			return nil, err
		}
		jwk.Crv = &curveName
		jwk.KeyOps = []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationSign),
			ptrKeyOp(azkeys.KeyOperationVerify),
		}

	default:
		return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: fmt.Sprintf("cannot import keys of type %s", attrs.KeyAlgorithm)}
	}

	return jwk, nil
}

// rsaKeyOpsFor returns the key operations ImportKey requests for an
// imported RSA key, based on attrs.KeyType. Neither signing nor encryption
// (an attrs.KeyType this backend does not recognize) leaves KeyOps unset,
// matching the JWK's own zero value.
func rsaKeyOpsFor(attrs *types.KeyAttributes) []*azkeys.KeyOperation {
	switch attrs.KeyType {
	case backend.KEY_TYPE_SIGNING:
		return []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationSign),
			ptrKeyOp(azkeys.KeyOperationVerify),
		}
	case backend.KEY_TYPE_ENCRYPTION:
		return []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationEncrypt),
			ptrKeyOp(azkeys.KeyOperationDecrypt),
			ptrKeyOp(azkeys.KeyOperationWrapKey),
			ptrKeyOp(azkeys.KeyOperationUnwrapKey),
		}
	default:
		return nil
	}
}

// eccCurveName maps attrs.ECCAttributes.Curve to Azure Key Vault's curve
// name, defaulting to P-256 exactly as getKeyParameters (azurekv.go) does
// for a generated (non-imported) ECDSA key.
func eccCurveName(attrs *types.KeyAttributes) (azkeys.CurveName, error) {
	curve := elliptic.P256()
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		curve = attrs.ECCAttributes.Curve
	}
	switch curve.Params().Name {
	case "P-256":
		return azkeys.CurveNameP256, nil
	case "P-384":
		return azkeys.CurveNameP384, nil
	case "P-521":
		return azkeys.CurveNameP521, nil
	default:
		return "", &errs.Message{Msg: fmt.Sprintf("unsupported curve: %s", curve.Params().Name)}
	}
}

// ExportKey exports a key in wrapped form for secure transport.
// Azure Key Vault does not support exporting private keys directly.
// This method returns ErrNotSupported.
//
// Capabilities().Export is unconditionally false for this backend, so
// there is no attrs.Exportable branch to check here, matching the awskms
// and gcpkms ExportKey contracts.
func (b *Backend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	return nil, backend.ErrNotSupported
}

// ExportKeyTo is not supported for the same reason ExportKey is not: Azure
// Key Vault does not expose an API to release private key material, so
// there is no plaintext for this backend to wrap for a destination's
// parameters in the first place.
func (b *Backend) ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if dstParams == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "destination import parameters cannot be nil"}
	}
	return nil, &errs.Detail{Err: backend.ErrExportToUnsupported, Detail: "Azure Key Vault does not support releasing private key material for re-wrapping"}
}

// ExportKeyMaterial returns the raw key material for extractable symmetric keys only.
// Azure Key Vault does not support exporting raw key material.
// This method returns ErrNotSupported.
func (b *Backend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Azure Key Vault does not support exporting raw key material
	return nil, backend.ErrNotSupported
}
