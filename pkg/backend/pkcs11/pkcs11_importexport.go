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

//go:build pkcs11

package pkcs11

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/miekg/pkcs11"
)

// Ensure Backend implements ImportExportBackend interface
var _ backend.ImportExportBackend = (*Backend)(nil)

// PKCS#11 wrapping key constants
const (
	// wrappingKeyLabel is the label for the HSM wrapping key used for import/export
	wrappingKeyLabel = "go-xkms-wrapping-key"

	// wrappingKeySize is the size of the RSA wrapping key in bits
	wrappingKeySize = 4096
)

// ErrImportedKeyUnaddressable is returned when C_UnwrapKey created a key object
// but the token would not give it the CKA_LABEL and CKA_ID the backend
// addresses keys by. Such an object can never be found again, so ImportKey
// destroys it and reports this rather than claiming success.
var ErrImportedKeyUnaddressable = errors.New("pkcs11: imported key could not be labelled with its CKA_LABEL/CKA_ID")

// ErrImportTokenMismatch is returned when the import token carried by the
// wrapped material does not name this backend's own wrapping key. The token
// selects the private key that C_UnwrapKey — and, on the hybrid path,
// C_Decrypt — runs under, and GetImportParameters only ever issues
// wrappingKeyLabel, so any other value is refused rather than honoured.
var ErrImportTokenMismatch = errors.New("pkcs11: import token does not name the backend wrapping key")

// ErrImportRollbackFailed is returned when a stage of ImportKey after
// C_UnwrapKey failed and the key object the unwrap created could not be
// destroyed, leaving key material on the token that the backend does not
// track.
var ErrImportRollbackFailed = errors.New("pkcs11: imported key could not be rolled back after a failed import")

// ErrEphemeralKEKNotDestroyed is returned when the temporary key-encryption
// key that the hybrid import installs on the token could not be destroyed. The
// object is session-only, so the session teardown still bounds its lifetime,
// but the import is failed rather than reported as clean.
var ErrEphemeralKEKNotDestroyed = errors.New("pkcs11: ephemeral key-encryption key could not be destroyed")

// GetImportParameters retrieves the parameters needed to import a key into the PKCS#11 HSM.
// This method finds or creates a wrapping key in the HSM and returns its public key.
//
// PKCS#11 wrapping keys are stored permanently in the HSM token and reused for multiple imports.
// The wrapping key is an RSA 4096-bit key pair with the private key marked as non-extractable
// and sensitive, ensuring it never leaves the HSM.
//
// For PKCS#11, import tokens are not required since the wrapping key is permanently stored
// in the HSM and referenced by its label.
func (b *Backend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Validate wrapping algorithm
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Supported algorithms
	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("%s for PKCS#11", algorithm)}
	}

	// Find or create wrapping key in HSM
	wrappingKeyID := []byte(wrappingKeyLabel)

	// Try to find existing wrapping key
	wrappingKeySigner, err := findKeyPairByID(b.pool, wrappingKeyID)
	if err != nil || wrappingKeySigner == nil {
		// Wrapping key doesn't exist, create it with explicit wrap/unwrap capabilities
		wrappingKeySigner, err = b.generateWrappingKeyPair(wrappingKeyID)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to generate wrapping key", Err: err}
		}
	}

	// Get the public key from the wrapping key
	wrappingPublicKey := wrappingKeySigner.Public()

	// Determine key spec from attributes
	keySpec := determineKeySpec(attrs)

	// For PKCS#11, wrapping keys don't expire as they're permanently stored in HSM
	// We return nil for ExpiresAt
	return &backend.ImportParameters{
		WrappingPublicKey: wrappingPublicKey,
		ImportToken:       wrappingKeyID, // Use wrapping key ID as token
		Algorithm:         algorithm,
		ExpiresAt:         nil, // No expiration for PKCS#11 wrapping keys
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps key material for secure transport using the specified parameters.
// This uses the standard wrapping functions from pkg/crypto/wrapping.
//
// The actual wrapping is performed locally using the wrapping public key from ImportParameters.
// The wrapped key can then be securely transmitted and imported via ImportKey, which will
// unwrap it using the corresponding private key in the HSM.
func (b *Backend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "key material cannot be nil or empty"}
	}

	if params == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import parameters cannot be nil"}
	}

	// Ensure we have an RSA public key
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "wrapping public key must be RSA"}
	}

	var wrapped []byte
	var err error

	// Wrap based on algorithm
	switch params.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Direct RSA-OAEP wrapping (for small keys like symmetric keys)
		wrapped, err = wrapping.WrapRSAOAEP(keyMaterial, rsaPubKey, params.Algorithm)

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Hybrid wrapping (for large keys like RSA private keys)
		wrapped, err = wrapping.WrapRSAAES(keyMaterial, rsaPubKey, params.Algorithm)

	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: params.Algorithm.String()}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key material", Err: err}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrapped,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey unwraps key material that was previously wrapped with WrapKey.
// For PKCS#11, unwrapping happens in the HSM during import via C_UnwrapKey, so this
// method returns ErrNotSupported. This method exists to satisfy the ImportExportBackend
// interface but is not used for PKCS#11 imports.
//
// The actual unwrapping is performed by the HSM's C_UnwrapKey function during ImportKey,
// ensuring the plaintext key material never leaves the HSM hardware boundary.
func (b *Backend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: "unwrapping is performed by PKCS#11 HSM during import"}
}

// ImportKey imports externally generated key material into the PKCS#11 HSM.
// The key material must be wrapped using parameters obtained from GetImportParameters.
//
// This method uses the PKCS#11 C_UnwrapKey function to securely import the wrapped key
// into the HSM. The unwrapping happens entirely within the HSM hardware, ensuring the
// plaintext key material never exists outside the secure boundary.
//
// The imported key is marked as:
//   - CKA_TOKEN: true (stored permanently in the token)
//   - CKA_PRIVATE: true (requires authentication to access - for private keys)
//   - CKA_SENSITIVE: true (the value is never revealed in plaintext)
//   - CKA_EXTRACTABLE: attrs.Exportable (false seals the key in the token for
//     good; true still only permits export in wrapped form, through ExportKey)
//
// The key is addressed by createKeyID(attrs) in both CKA_LABEL and CKA_ID, the
// identifier every other operation on this backend uses.
//
// wrapped.ImportToken must name this backend's own wrapping key; anything else
// is refused with ErrImportTokenMismatch rather than used as an unwrapping
// key. See the check itself for why.
//
// The call is all-or-nothing. If any stage after C_UnwrapKey fails — the
// token refusing the key's identity, metadata that will not marshal, a
// storage backend that will not accept it — the key object is destroyed
// before the error is returned, so a failed ImportKey never leaves key
// material on the token that the backend cannot address or account for.
//
// HSM Compatibility Note:
// While the PKCS#11 2.40 specification supports C_UnwrapKey with CKM_RSA_PKCS_OAEP for secret keys,
// some HSM implementations (including SoftHSM2) may return CKR_ARGUMENTS_BAD when attempting this
// operation. This is a known limitation of certain HSM implementations. Production hardware HSMs
// with complete PKCS#11 2.40 support should work correctly.
func (b *Backend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return ErrNotInitialized
	}

	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	if wrapped == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material cannot be nil"}
	}

	// The import token names the private key that C_UnwrapKey — and, on the
	// hybrid path, C_Decrypt — is run under, and it reaches this method
	// straight from the caller: the REST and gRPC handlers copy
	// ImportKeyRequest.ImportToken through untouched. GetImportParameters
	// only ever issues this backend's own wrapping key label, so any other
	// value is a request to press some other private key on the token into
	// service as an unwrapping and decryption key. Honouring it would turn
	// every CKA_DECRYPT private key on the token — including the RSA keys
	// this backend itself imports — into an RSA-OAEP decryption oracle for
	// attacker-chosen ciphertext, with success and failure distinguishable
	// from which stage of the import reported the error. Pin it to the one
	// key this ceremony is defined over.
	//
	// The supplied token is deliberately not echoed into the error: it is
	// caller-controlled and would otherwise reach the logs verbatim.
	if !bytes.Equal(wrapped.ImportToken, []byte(wrappingKeyLabel)) {
		return &errs.Detail{Err: ErrImportTokenMismatch, Detail: wrappingKeyLabel}
	}

	// Initialize low-level PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return &errs.Message{Msg: fmt.Sprintf("failed to load PKCS#11 library: %s", b.config.Library)}
		}

		if err := p.Initialize(); err != nil {
			if !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return &errs.Wrapped{Msg: "failed to initialize PKCS#11", Err: err}
			}
		}

		b.p11ctx = p
	}

	// Resolve the token slot by configured Slot/TokenLabel. Using slots[0]
	// directly breaks when more than one token is present in the same
	// SoftHSM/HSM (the wrong token — hence the wrong PIN — would be selected).
	slot, err := b.resolveSlot()
	if err != nil {
		return err
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to open session", Err: err}
	}
	defer func() {
		if closeErr := b.p11ctx.CloseSession(session); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Login as user (only logout if we performed the login)
	var didLogin bool
	userPIN, err := b.userPIN()
	if err != nil {
		return err
	}
	if err := b.p11ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
		if !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return &errs.Wrapped{Msg: "failed to login", Err: err}
		}
		// Already logged in, don't logout later
		didLogin = false
	} else {
		// We logged in successfully, logout when done
		didLogin = true
	}
	if didLogin {
		defer func() {
			if logoutErr := b.p11ctx.Logout(session); logoutErr != nil {
				err = errors.Join(err, logoutErr)
			}
		}()
	}

	// Find the wrapping key (private key handle). The label is the package
	// constant, never wrapped.ImportToken, which was only checked for equality
	// against it above.
	wrappingKeyID := []byte(wrappingKeyLabel)
	wrappingKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, wrappingKeyID),
	}

	wrappingKeyHandle, err := b.findOneObject(session, wrappingKeyTemplate)
	if err != nil {
		return err
	}

	if wrappingKeyHandle == 0 {
		return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "wrapping key not found in HSM"}
	}

	// Create key ID and label. Every other object this backend creates or looks
	// up — generated key pairs, generated secret keys, the symmetric
	// encrypter/decrypter, ExportKeyMaterial — addresses a key by
	// createKeyID(attrs) in both CKA_LABEL and CKA_ID, so an imported key must
	// use the same identifier or it is unreachable through the rest of the API.
	keyID := []byte(createKeyID(attrs))
	keyLabel := keyID

	// Build the key template based on key type
	keyTemplate, err := b.buildImportKeyTemplate(attrs, keyID, keyLabel)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to build key template", Err: err}
	}

	// Every stage from C_UnwrapKey onwards can still fail, and a failure that
	// leaves the unwrapped key on the token is worse than no import at all:
	// the object is unreachable through the metadata index the rest of the
	// backend consults, and a retry would put a second object under the same
	// CKA_ID for later lookups to choose between. PKCS#11 3.2 §5.1 requires a
	// function call to accomplish "either its entire goal, or nothing at all",
	// so the key is rolled back on every failing path — and, because the
	// rollback is deferred, on a panic as well. It is armed the moment a
	// handle exists and disarmed only once the import is complete.
	//
	// Defers run LIFO, so this rollback runs before the session logout and
	// close registered above it, while the session is still usable.
	var keyHandle pkcs11.ObjectHandle
	committed := false

	defer func() {
		if committed || keyHandle == 0 {
			return
		}

		destroyErr := b.p11ctx.DestroyObject(session, keyHandle)
		if destroyErr == nil {
			return
		}

		// Report the rollback failure without discarding whatever failed
		// first: an orphaned key object on the token is an operator-visible
		// event, but it is not the root cause.
		if err == nil {
			err = &errs.Joined{Lead: ErrImportRollbackFailed, Cause: destroyErr}
			return
		}
		err = &errs.Joined{Lead: err, Detail: ErrImportRollbackFailed.Error(), Cause: destroyErr}
	}()

	// Determine the unwrapping mechanism based on the wrapping algorithm
	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Direct RSA-OAEP unwrapping (for small keys)
		// Note: This doesn't work with SoftHSM2 for secret keys - use hybrid wrapping instead
		var hashMech, mgfMech uint
		if wrapped.Algorithm == backend.WrappingAlgorithmRSAES_OAEP_SHA_1 {
			hashMech = pkcs11.CKM_SHA_1
			mgfMech = pkcs11.CKG_MGF1_SHA1
		} else {
			hashMech = pkcs11.CKM_SHA256
			mgfMech = pkcs11.CKG_MGF1_SHA256
		}

		unwrapMechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(
			hashMech,
			mgfMech,
			pkcs11.CKZ_DATA_SPECIFIED,
			[]byte{}, // Empty label to match wrapping.WrapRSAOAEP which uses nil label
		))

		keyHandle, err = b.p11ctx.UnwrapKey(session, []*pkcs11.Mechanism{unwrapMechanism}, wrappingKeyHandle, wrapped.WrappedKey, keyTemplate)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to unwrap key with RSA-OAEP", Err: err}
		}

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Hybrid unwrapping using two-step process (works with SoftHSM2):
		// 1. Unwrap the AES key using RSA-OAEP
		// 2. Unwrap the target key using the AES key
		keyHandle, err = b.importKeyHybrid(session, attrs, wrapped, wrappingKeyHandle, keyID, keyLabel, keyTemplate)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to import key with hybrid unwrapping", Err: err}
		}

	default:
		return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: wrapped.Algorithm.String()}
	}

	// CKA_LABEL and CKA_ID are part of the C_UnwrapKey template, so a token that
	// honoured the template has already applied them. Confirm it: a key the
	// backend cannot address afterwards is an orphaned token object, and
	// PKCS#11 3.2 §5.1 requires a function call to accomplish "either its
	// entire goal, or nothing at all". Destroy the object and fail rather than
	// leave unreachable key material behind. The deferred rollback above
	// performs the destroy.
	if identityErr := b.verifyImportedKeyIdentity(session, keyHandle, keyID, keyLabel); identityErr != nil {
		return identityErr
	}

	// Store metadata about the imported key
	metadata := map[string]interface{}{
		"key_handle":    keyHandle,
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType,
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_PKCS11,
		"imported":      true,
	}

	metadataBytes, marshalErr := json.Marshal(metadata)
	if marshalErr != nil {
		return &errs.Wrapped{Msg: "failed to marshal metadata", Err: marshalErr}
	}

	if b.config.KeyStorage != nil {
		if saveErr := storage.SaveKey(ctx, b.config.KeyStorage, attrs.ID(), metadataBytes); saveErr != nil {
			return &errs.Wrapped{Msg: "failed to save metadata", Err: saveErr}
		}
	}

	// The key is on the token and the backend can find it again. Disarm the
	// rollback; from here the import is the caller's to undo with DeleteKey.
	committed = true

	return nil
}

// verifyImportedKeyIdentity confirms that the freshly unwrapped object carries
// the CKA_LABEL and CKA_ID the backend addresses it by, repairing them with
// C_SetAttributeValue if the token dropped them from the C_UnwrapKey template.
//
// Both attributes are modifiable after object creation (PKCS#11 3.2 §4.9 marks
// CKA_LABEL and CKA_ID footnote 8, "may be modified after object is created"),
// so a token that refuses them in an unwrap template can still be corrected
// here. If it cannot, the caller destroys the object.
func (b *Backend) verifyImportedKeyIdentity(session pkcs11.SessionHandle, keyHandle pkcs11.ObjectHandle, keyID, keyLabel []byte) error {
	identity := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	current, err := b.p11ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err == nil && len(current) == 2 &&
		bytes.Equal(current[0].Value, keyLabel) && bytes.Equal(current[1].Value, keyID) {
		return nil
	}

	if err := b.p11ctx.SetAttributeValue(session, keyHandle, identity); err != nil {
		return &errs.Joined{Lead: ErrImportedKeyUnaddressable, Cause: err}
	}

	return nil
}

// importKeyHybrid implements the two-step hybrid unwrapping process for PKCS#11.
// SoftHSM2 Compatibility Workaround:
//  1. Parse the wrapped key material to extract wrapped AES key and wrapped target key
//  2. Use C_Decrypt with CKM_RSA_PKCS_OAEP to decrypt the AES key (workaround for SoftHSM2)
//  3. Hand the plaintext key-encryption key to unwrapWithEphemeralKEK, which
//     installs it, unwraps the target key under it, destroys the temporary
//     token object and wipes the host-side plaintext
//
// Step 2 is the only stage of the whole ceremony in which plaintext key
// material exists outside the token. It is deliberately a single expression
// wide: the decrypt is immediately followed by the call that takes ownership
// of the result, so there is no statement in between that could return early
// and strand the plaintext for the garbage collector.
//
// Note that this detour exists only because SoftHSM2 rejects C_UnwrapKey with
// CKM_RSA_PKCS_OAEP for secret keys. A token that implements that call would
// keep the key-encryption key inside the hardware boundary from end to end,
// and would never need step 2 at all.
func (b *Backend) importKeyHybrid(session pkcs11.SessionHandle, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial, wrappingKeyHandle pkcs11.ObjectHandle, keyID, keyLabel []byte, keyTemplate []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	// Parse the hybrid wrapped format: [4-byte length][wrapped AES key][wrapped key material]
	if len(wrapped.WrappedKey) < 4 {
		return 0, &errs.Message{Msg: "wrapped key too short for hybrid format"}
	}

	// Extract the wrapped AES key length. The arithmetic is deliberately done
	// in uint64: the length is attacker-controlled, and computing 4+length in
	// uint32 wraps for any prefix above 0xFFFFFFFB, which turns the bounds
	// check below into a no-op and makes the slice expression panic.
	wrappedAESKeyLen := uint64(binary.BigEndian.Uint32(wrapped.WrappedKey[:4]))

	if wrappedAESKeyLen == 0 || uint64(len(wrapped.WrappedKey)) < 4+wrappedAESKeyLen {
		return 0, &errs.Message{Msg: "wrapped key corrupted: insufficient data"}
	}

	wrappedAESKey := wrapped.WrappedKey[4 : 4+wrappedAESKeyLen]
	wrappedTargetKey := wrapped.WrappedKey[4+wrappedAESKeyLen:]

	// Step 1: recover the AES key-encryption key with RSA-OAEP. The hash must
	// match the one wrapping.WrapRSAAES used.
	var hashMech, mgfMech uint
	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		hashMech = pkcs11.CKM_SHA256
		mgfMech = pkcs11.CKG_MGF1_SHA256
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		hashMech = pkcs11.CKM_SHA_1
		mgfMech = pkcs11.CKG_MGF1_SHA1
	default:
		return 0, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: wrapped.Algorithm.String()}
	}

	// SoftHSM2 doesn't support C_UnwrapKey with CKM_RSA_PKCS_OAEP for secret keys.
	// Workaround: Use C_Decrypt to decrypt the wrapped AES key, then C_CreateObject to import it.
	decryptMech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(
		hashMech,
		mgfMech,
		pkcs11.CKZ_DATA_SPECIFIED,
		[]byte{},
	))

	// Decrypt the wrapped AES key using the wrapping private key
	if err := b.p11ctx.DecryptInit(session, []*pkcs11.Mechanism{decryptMech}, wrappingKeyHandle); err != nil {
		return 0, &errs.Wrapped{Msg: "failed to init decrypt for AES key", Err: err}
	}

	aesKeyBytes, err := b.p11ctx.Decrypt(session, wrappedAESKey)
	if err != nil {
		return 0, &errs.Wrapped{Msg: "failed to decrypt AES key", Err: err}
	}

	// Step 2: hand the plaintext key-encryption key straight to the stage that
	// consumes and erases it. Nothing between the decrypt above and this call
	// may fail, so the KEK cannot escape down an error path.
	return b.unwrapWithEphemeralKEK(session, aesKeyBytes, wrappedTargetKey, keyTemplate)
}

// unwrapWithEphemeralKEK completes the second stage of a hybrid import. It
// installs kek as a session-only AES key on the token, unwraps the target key
// under it with CKM_AES_KEY_WRAP_PAD, and destroys the temporary object before
// returning.
//
// This function takes ownership of kek and wipes it on every path — success,
// error and panic alike. kek is the one point in the whole ceremony where a
// plaintext key-encryption key exists in host memory rather than inside the
// token, so the caller must not use kek after this call and must not retain
// another reference to it.
//
// What the wipe does and does not buy: zeroization in a garbage-collected
// runtime narrows the exposure window, it does not guarantee erasure. The Go
// runtime may already have copied the backing array while growing or moving
// the heap, and this function can only reach the array it was handed; the
// copies it cannot see stay readable until they are collected and reused.
// Wiping still removes the copy that would otherwise survive for an unbounded
// time after the import — the copy most likely to be paged to swap or written
// into a core dump — so it is a real reduction in exposure, not a proof of
// absence. secure.Wipe is used rather than a hand-written loop because it is
// the wipe the rest of go-xkms uses (pkg/crypto/wrapping, the other half of
// this ceremony, wipes through the same package) and because it is written to
// resist being optimized away.
func (b *Backend) unwrapWithEphemeralKEK(session pkcs11.SessionHandle, kek, wrappedTargetKey []byte, keyTemplate []*pkcs11.Attribute) (handle pkcs11.ObjectHandle, err error) {
	defer secure.Wipe(kek)

	kekHandle, createErr := b.p11ctx.CreateObject(session, ephemeralKEKTemplate(kek))
	if createErr != nil {
		return 0, &errs.Wrapped{Msg: "failed to create AES key object", Err: createErr}
	}

	// Deferred so the KEK object is destroyed on the unwrap's error paths and
	// on a panic, not only on success. A destroy that fails is reported rather
	// than swallowed: the caller's rollback then removes the target key too,
	// so the import still resolves to all or nothing.
	defer func() {
		destroyErr := b.p11ctx.DestroyObject(session, kekHandle)
		if destroyErr == nil {
			return
		}
		if err != nil {
			err = &errs.Joined{Lead: err, Detail: ErrEphemeralKEKNotDestroyed.Error(), Cause: destroyErr}
			return
		}
		err = &errs.Joined{Lead: ErrEphemeralKEKNotDestroyed, Cause: destroyErr}
	}()

	targetUnwrapMech := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)

	targetKeyHandle, unwrapErr := b.p11ctx.UnwrapKey(session, []*pkcs11.Mechanism{targetUnwrapMech}, kekHandle, wrappedTargetKey, keyTemplate)
	if unwrapErr != nil {
		return 0, &errs.Wrapped{Msg: "failed to unwrap target key with AES-KWP", Err: unwrapErr}
	}

	return targetKeyHandle, nil
}

// ephemeralKEKTemplate builds the object template for the temporary AES
// key-encryption key that a hybrid import installs on the token.
//
// Every protection attribute is written explicitly rather than left to the
// token's defaults. PKCS#11 3.2 §4.9 gives a secret key created by
// C_CreateObject CKA_SENSITIVE CK_FALSE and CKA_EXTRACTABLE CK_TRUE by
// default, which would leave the key-encryption key — the value that protects
// the key material being imported — readable in plaintext through
// C_GetAttributeValue for as long as the object lives. The two attributes are
// one-way on a created object, so setting them here is the only chance to set
// them at all.
//
// CKA_TOKEN is false so the object is session-only and cannot survive the
// session even if C_DestroyObject fails, and CKA_UNWRAP is the sole usage the
// object is granted: it exists to run one CKM_AES_KEY_WRAP_PAD unwrap and
// nothing else.
func ephemeralKEKTemplate(kek []byte) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, kek),
	}
}

// keyObjectClass reports the PKCS#11 object class that holds the key described
// by attrs: CKO_PRIVATE_KEY for an asymmetric algorithm, CKO_SECRET_KEY for a
// symmetric one. It returns backend.ErrInvalidAlgorithm for anything the
// import/export ceremony cannot represent.
//
// Import and export must agree on the class, otherwise C_FindObjectsInit for an
// export would match a sibling object (an RSA key pair stores its public and
// private halves under the same CKA_ID) and the export would read attributes
// off the wrong object.
func keyObjectClass(attrs *types.KeyAttributes) (uint, error) {
	switch attrs.KeyAlgorithm {
	case x509.RSA, x509.ECDSA:
		return pkcs11.CKO_PRIVATE_KEY, nil
	}

	switch attrs.SymmetricAlgorithm {
	case types.SymmetricAES128GCM, types.SymmetricAES192GCM, types.SymmetricAES256GCM:
		return pkcs11.CKO_SECRET_KEY, nil
	}

	return 0, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported key algorithm for import/export: %v (symmetric: %v)", attrs.KeyAlgorithm, attrs.SymmetricAlgorithm)}
}

// buildImportKeyTemplate builds the PKCS#11 attribute template for the key
// object that C_UnwrapKey creates.
//
// Both protection flags are always written explicitly rather than left to the
// token. PKCS#11 3.2 §5.18.4 states that a key produced by C_UnwrapKey has
// "the CKA_EXTRACTABLE attribute ... by default set to CK_TRUE", and the
// §4.9 Common Secret Key Attributes table gives CKA_SENSITIVE a default of
// CK_FALSE. Relying on those defaults would make the protection level of an
// imported key vary from token to token — SoftHSM2 happens to be stricter than
// the specification requires, so a template that passes there would silently
// import a plaintext-readable key on a conforming HSM.
//
// CKA_EXTRACTABLE carries the caller's attrs.Exportable policy: a key imported
// without it can never leave the token again, in any form. CKA_SENSITIVE is
// CK_TRUE unconditionally, so even an exportable key leaves only through
// C_WrapKey — per the footnote to the §4.9 attribute tables, a key whose
// CKA_SENSITIVE is CK_TRUE never reveals its value in plaintext.
func (b *Backend) buildImportKeyTemplate(attrs *types.KeyAttributes, keyID, keyLabel []byte) ([]*pkcs11.Attribute, error) {
	class, err := keyObjectClass(attrs)
	if err != nil {
		return nil, err
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, attrs.Exportable),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return append(template,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		), nil

	case x509.ECDSA:
		return append(template,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		), nil
	}

	return append(template,
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	), nil
}

// ExportKey exports a key in wrapped form for secure transport.
// This method checks if the key has the CKA_EXTRACTABLE attribute set to true.
// If the key is extractable, it uses the PKCS#11 C_WrapKey function to export it
// using the HSM's wrapping key.
//
// Security considerations:
//   - Only keys marked as exportable (attrs.Exportable=true) can be exported
//   - The exported key is wrapped using the HSM's wrapping key
//   - Keys imported with CKA_EXTRACTABLE=false cannot be exported
//   - The export operation happens entirely within the HSM for maximum security
func (b *Backend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (wrapped *backend.WrappedKeyMaterial, err error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Check if backend supports export
	if !b.Capabilities().Export {
		return nil, backend.ErrExportNotSupported
	}

	// Check if key is marked as exportable
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	// Initialize low-level PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return nil, &errs.Message{Msg: fmt.Sprintf("failed to load PKCS#11 library: %s", b.config.Library)}
		}

		if err := p.Initialize(); err != nil {
			if !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return nil, &errs.Wrapped{Msg: "failed to initialize PKCS#11", Err: err}
			}
		}

		b.p11ctx = p
	}

	// Resolve the token slot by configured Slot/TokenLabel. Using slots[0]
	// directly breaks when more than one token is present in the same
	// SoftHSM/HSM (the wrong token — hence the wrong PIN — would be selected).
	slot, err := b.resolveSlot()
	if err != nil {
		return nil, err
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to open session", Err: err}
	}
	defer func() {
		if closeErr := b.p11ctx.CloseSession(session); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Login as user (only logout if we performed the login)
	var didLogin bool
	userPIN, err := b.userPIN()
	if err != nil {
		return nil, err
	}
	if err := b.p11ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
		if !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, &errs.Wrapped{Msg: "failed to login", Err: err}
		}
		// Already logged in, don't logout later
		didLogin = false
	} else {
		// We logged in successfully, logout when done
		didLogin = true
	}
	if didLogin {
		defer func() {
			if logoutErr := b.p11ctx.Logout(session); logoutErr != nil {
				err = errors.Join(err, logoutErr)
			}
		}()
	}

	// Find the key to export. The class is part of the template because an RSA
	// or ECDSA key pair stores both halves under the same CKA_ID, and only the
	// private half is the export target.
	keyClass, err := keyObjectClass(attrs)
	if err != nil {
		return nil, err
	}

	keyID := []byte(createKeyID(attrs))
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, keyClass),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	keyHandle, err := b.findOneObject(session, keyTemplate)
	if err != nil {
		return nil, err
	}

	if keyHandle == 0 {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: attrs.CN}
	}

	// Check if key is extractable (CKA_EXTRACTABLE attribute in HSM)
	// This provides defense-in-depth: we check attrs.Exportable above (policy),
	// and CKA_EXTRACTABLE here (actual HSM capability)
	extractableAttr, err := b.p11ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get extractable attribute", Err: err}
	}

	if len(extractableAttr) == 0 || len(extractableAttr[0].Value) == 0 {
		return nil, &errs.Message{Msg: "failed to determine if key is extractable"}
	}

	isExtractable := extractableAttr[0].Value[0] != 0
	if !isExtractable {
		return nil, backend.ErrKeyNotExportable
	}

	// Find the wrapping key. This is a second C_FindObjectsInit on the same
	// session; PKCS#11 3.2 §5.7.7 allows "at most one search operation ...
	// active at a given time in a given session", so findOneObject finalizes
	// the previous search before this one starts.
	wrappingKeyID := []byte(wrappingKeyLabel)
	wrappingKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, wrappingKeyID),
	}

	wrappingKeyHandle, err := b.findOneObject(session, wrappingKeyTemplate)
	if err != nil {
		return nil, err
	}

	if wrappingKeyHandle == 0 {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "wrapping key not found in HSM"}
	}

	// Determine the wrapping mechanism. The hashes offered here mirror the
	// direct-OAEP branch of ImportKey so that a key exported from one token can
	// be imported into another without renegotiating the algorithm.
	var wrapMechanism *pkcs11.Mechanism
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1:
		wrapMechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(
			pkcs11.CKM_SHA_1,
			pkcs11.CKG_MGF1_SHA1,
			pkcs11.CKZ_DATA_SPECIFIED,
			[]byte{}, // Empty label, matching wrapping.WrapRSAOAEP.
		))

	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		wrapMechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(
			pkcs11.CKM_SHA256,
			pkcs11.CKG_MGF1_SHA256,
			pkcs11.CKZ_DATA_SPECIFIED,
			[]byte{}, // Empty label for consistency
		))

	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("%s for export", algorithm)}
	}

	// Wrap the key using C_WrapKey
	wrappedKey, err := b.p11ctx.WrapKey(session, []*pkcs11.Mechanism{wrapMechanism}, wrappingKeyHandle, keyHandle)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key", Err: err}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrappedKey,
		Algorithm:   algorithm,
		ImportToken: wrappingKeyID,
		Metadata:    make(map[string]string),
	}, nil
}

// ExportKeyTo has no HSM-native equivalent: C_WrapKey wraps under a
// wrapping-key HANDLE that must already exist as an object inside this
// HSM's own token -- exactly the wrappingKeyLabel object GetImportParameters
// finds or creates above. A destination backend's ImportParameters carry a
// crypto.PublicKey value, not an HSM object handle, and there is no PKCS#11
// primitive here to press an arbitrary externally supplied public key into
// service as a C_WrapKey wrapping key without first provisioning it as a
// CKA_WRAP object on this token -- a ceremony this backend does not perform
// and should not invent unreviewed. Refuse rather than approximate it with a
// software RSA-OAEP encrypt that never touches the HSM boundary this
// backend's whole design exists to preserve (go-xkms#154).
func (b *Backend) ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if dstParams == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "destination import parameters cannot be nil"}
	}
	return nil, &errs.Detail{
		Err:    backend.ErrExportToUnsupported,
		Detail: "PKCS#11 C_WrapKey wraps under a wrapping-key object provisioned on this HSM's own token, not an arbitrary destination-supplied public key",
	}
}

// findOneObject runs a complete C_FindObjectsInit / C_FindObjects /
// C_FindObjectsFinal cycle and returns the first matching object handle, or
// CK_INVALID_HANDLE (0) when nothing matches.
//
// The search is finalized before this function returns, which is what makes
// consecutive lookups on one session legal: PKCS#11 3.2 §5.7.7 permits "at
// most one search operation ... active at a given time in a given session",
// and a second C_FindObjectsInit while a search is still open fails with
// CKR_OPERATION_ACTIVE.
func (b *Backend) findOneObject(session pkcs11.SessionHandle, template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if err := b.p11ctx.FindObjectsInit(session, template); err != nil {
		return 0, &errs.Wrapped{Msg: "failed to init object search", Err: err}
	}

	handles, _, findErr := b.p11ctx.FindObjects(session, 1)

	// C_FindObjectsFinal must run even when C_FindObjects failed, otherwise the
	// session is left with a search operation active and every later search on
	// it returns CKR_OPERATION_ACTIVE.
	if err := b.p11ctx.FindObjectsFinal(session); err != nil {
		return 0, &errs.Wrapped{Msg: "failed to finalize object search", Err: err}
	}

	if findErr != nil {
		return 0, &errs.Wrapped{Msg: "failed to find object", Err: findErr}
	}

	if len(handles) == 0 {
		return 0, nil
	}

	return handles[0], nil
}

// generateWrappingKeyPair generates an RSA key pair with wrap/unwrap/encrypt/decrypt capabilities.
// This is used for import/export operations. The key pair is created using the raw PKCS#11 API
// with explicit wrap/unwrap attributes, then wrapped in a pkcs11RSASigner.
func (b *Backend) generateWrappingKeyPair(keyID []byte) (crypto.Signer, error) {
	signer, err := generateRSAWrappingKeyPair(b.pool, keyID, wrappingKeySize)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate wrapping key pair", Err: err}
	}
	return signer, nil
}

// determineKeySpec determines the key spec string from key attributes.
func determineKeySpec(attrs *types.KeyAttributes) string {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
			return fmt.Sprintf("RSA_%d", attrs.RSAAttributes.KeySize)
		}
		return "RSA_2048" // Default
	case x509.ECDSA:
		if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
			// Convert curve to string representation
			curveName := attrs.ECCAttributes.Curve.Params().Name
			return fmt.Sprintf("EC_%s", curveName)
		}
		return "EC_P256" // Default
	default:
		// Check symmetric algorithms
		switch attrs.SymmetricAlgorithm {
		case types.SymmetricAES128GCM:
			return "AES_128"
		case types.SymmetricAES192GCM:
			return "AES_192"
		case types.SymmetricAES256GCM:
			return "AES_256"
		default:
			return "UNKNOWN"
		}
	}
}

// ExportKeyMaterial returns the raw key material for extractable symmetric keys only.
// This method provides direct access to the plaintext key bytes without wrapping.
//
// Security restrictions:
//   - ONLY works for symmetric keys (AES, etc.)
//   - Returns ErrAsymmetricKeyExportNotAllowed for asymmetric keys (RSA, ECDSA, Ed25519)
//   - Key must have CKA_EXTRACTABLE=true in the HSM
//   - Returns ErrKeyNotExportable if the key is not marked as extractable
//
// For PKCS#11 backends, this requires:
//  1. The key object to have CKA_EXTRACTABLE = CK_TRUE
//  2. The key to be a CKO_SECRET_KEY (symmetric key)
//
// Note: Most HSM security policies will prevent keys from having CKA_EXTRACTABLE=true.
// This is primarily useful for testing with SoftHSM or specific compliance scenarios.
func (b *Backend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) (keyMaterial []byte, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "key attributes cannot be nil"}
	}

	// Check if this is an asymmetric key - we don't allow raw export of those
	switch attrs.KeyAlgorithm {
	case x509.RSA, x509.ECDSA, x509.Ed25519, x509.DSA:
		return nil, backend.ErrAsymmetricKeyExportNotAllowed
	}

	// Initialize low-level PKCS#11 context if needed
	if b.p11ctx == nil {
		return nil, &errs.Message{Msg: "PKCS#11 context not initialized for export operations"}
	}

	// Resolve the token slot by configured Slot/TokenLabel. Using slots[0]
	// directly breaks when more than one token is present in the same
	// SoftHSM/HSM (the wrong token — hence the wrong PIN — would be selected).
	slot, err := b.resolveSlot()
	if err != nil {
		return nil, err
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to open session", Err: err}
	}
	defer func() {
		if closeErr := b.p11ctx.CloseSession(session); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Login if required
	if b.config.PIN != nil {
		userPIN, err := b.userPIN()
		if err != nil {
			return nil, err
		}
		if err := b.p11ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
			if !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return nil, &errs.Wrapped{Msg: "failed to login", Err: err}
			}
		}
	}

	// Find the secret key
	keyLabel := createKeyID(attrs)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	keyHandle, err := b.findOneObject(session, template)
	if err != nil {
		return nil, err
	}

	if keyHandle == 0 {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: attrs.CN}
	}

	// Check if the key is extractable
	extractableAttr, err := b.p11ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get extractable attribute", Err: err}
	}

	if len(extractableAttr) == 0 || len(extractableAttr[0].Value) == 0 {
		return nil, backend.ErrKeyNotExportable
	}

	// PKCS#11 boolean is typically a single byte: 0x00 = false, 0x01 = true
	if extractableAttr[0].Value[0] == 0x00 {
		return nil, backend.ErrKeyNotExportable
	}

	// Get the key value
	valueAttr, err := b.p11ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		// This could fail if the key is sensitive (CKA_SENSITIVE=true)
		return nil, &errs.Detail{Err: backend.ErrKeyNotExportable, Detail: fmt.Sprintf("failed to extract key value (key may be sensitive): %v", err)}
	}

	if len(valueAttr) == 0 || len(valueAttr[0].Value) == 0 {
		return nil, &errs.Detail{Err: backend.ErrKeyNotExportable, Detail: "empty key value returned"}
	}

	return valueAttr[0].Value, nil
}
