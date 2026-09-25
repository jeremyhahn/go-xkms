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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivpkcs11 "github.com/jeremyhahn/go-xkms/pkg/pivcert/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
)

// PKCS#11 v3.0 Edwards curve constants
// These are defined in PKCS#11 v3.0 specification but may not be in older versions of miekg/pkcs11
const (
	CKK_EC_EDWARDS              = 0x00000040 // Edwards curve key type
	CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055 // Edwards curve key pair generation mechanism
	CKM_EDDSA                   = 0x00001057 // EdDSA signature mechanism
)

// PKCS#11 v3.2 post-quantum cryptography constants
// These are defined in OASIS PKCS#11 v3.2 CSD01 (pkcs11t.h) for ML-DSA and ML-KEM algorithms.
// The key type values (CKK_*) follow the official PKCS#11 v3.2 specification numbering.
// The mechanism values (CKM_*) match the standard mechanism type assignments.
const (
	// CKK_ML_DSA is the ML-DSA (FIPS 204) key type for post-quantum digital signatures.
	CKK_ML_DSA = 0x0000004A

	// CKM_ML_DSA_KEY_PAIR_GEN generates ML-DSA key pairs on the HSM.
	CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001c

	// CKM_ML_DSA performs ML-DSA signing and verification on the HSM.
	CKM_ML_DSA = 0x0000001d

	// CKK_ML_KEM is the ML-KEM (FIPS 203) key type for post-quantum key encapsulation.
	CKK_ML_KEM = 0x00000049

	// CKM_ML_KEM_KEY_PAIR_GEN generates ML-KEM key pairs on the HSM.
	CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000f

	// CKM_ML_KEM performs ML-KEM encapsulation and decapsulation on the HSM.
	CKM_ML_KEM = 0x00000017
)

// validAESKeySizes holds the AES key lengths in bits that FIPS 197 defines and
// that CKM_AES_KEY_GEN therefore accepts. A map keeps the check O(1) and keeps
// the accepted set in one place, so the generator and any future validator
// cannot drift apart.
var validAESKeySizes = map[int]bool{128: true, 192: true, 256: true}

// Backend implements the types.KeyProvider interface for PKCS#11 hardware security modules.
// It provides secure key storage where private keys never leave the HSM hardware.
//
// The backend uses a channel-based session pool over miekg/pkcs11 for all operations.
// This eliminates the dual-init conflict that occurred with the crypto11 wrapper library.
//
// Thread Safety:
// All operations are protected by read-write mutexes, making the backend safe for
// concurrent access from multiple goroutines.
//
// HSM Support:
// - SoftHSM (software HSM for testing)
// - YubiKey HSM
// - Thales nShield
// - Any PKCS#11 compatible HSM
type Backend struct {
	config        *Config
	p11ctx        *pkcs11.Ctx
	pool          *SessionPool
	ownsP11ctx    bool // tracks if this backend owns the *pkcs11.Ctx object (should Destroy)
	ownsP11Init   bool // tracks if this backend's own C_Initialize call succeeded (should Finalize)
	tracker       types.AEADSafetyTracker
	supportsMLDSA bool // dynamically detected ML-DSA mechanism support
	supportsMLKEM bool // dynamically detected ML-KEM mechanism support

	// supportsAESCBC, supportsAESCBCPad and supportsAESECB record whether the
	// token advertised CKM_AES_CBC, CKM_AES_CBC_PAD and CKM_AES_ECB in its
	// mechanism list (see probeQuantumMechanisms, which despite its name is
	// this backend's single mechanism-detection pass). A cipher mode whose
	// mechanism the token does not advertise is refused with a typed,
	// capability-classified error instead of reaching C_EncryptInit /
	// C_DecryptInit and failing with CKR_MECHANISM_INVALID.
	supportsAESCBC    bool
	supportsAESCBCPad bool
	supportsAESECB    bool
	slotModel         pivcert.SlotModel // nil for generic (non-PIV) tokens
	mu                sync.RWMutex
	types.KeyProvider
}

// NewBackend creates a new PKCS#11 backend instance.
// It validates the configuration but does not initialize the PKCS#11 context.
// Call Initialize() to set up the HSM token and Login() to authenticate.
//
// Parameters:
//   - config: PKCS#11 configuration including library path, token label, and PINs
//
// Returns an error if the configuration is invalid.
func NewBackend(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid configuration", Err: err}
	}

	// Initialize tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	return &Backend{
		config:  config,
		tracker: tracker,
	}, nil
}

// Type returns the backend type (PKCS#11).
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypePKCS11
}

// Config returns the PKCS#11 configuration.
func (b *Backend) Config() *Config {
	return b.config
}

// userPIN borrows the configured user PIN as a plain string, the shape
// miekg/pkcs11's Login and this package's session-pool helpers require. This
// is the documented third-party-SDK boundary (go-xkms#610): the plaintext
// leaves the PIN's SecretValue enclave only for the duration of this
// accessor's return value. Returns "" when no PIN is configured.
func (b *Backend) userPIN() (string, error) {
	pin, err := types.SecretValueBytes(b.config.PIN)
	if err != nil {
		return "", err
	}
	return string(pin), nil
}

// soPIN borrows the configured Security Officer PIN as a plain string, for
// the same miekg/pkcs11 boundary userPIN documents. Returns "" when no SO
// PIN is configured.
func (b *Backend) soPIN() (string, error) {
	pin, err := types.SecretValueBytes(b.config.SOPIN)
	if err != nil {
		return "", err
	}
	return string(pin), nil
}

// SlotModel returns the slot model for this backend, or nil if the token
// does not use predefined slots (e.g., generic SoftHSM tokens).
func (b *Backend) SlotModel() pivcert.SlotModel {
	return b.slotModel
}

// Capabilities returns the capabilities of this backend.
// PKCS#11 is a hardware-backed security module interface.
// Quantum capabilities (QuantumSigning and KeyEncapsulation) are dynamically
// detected from the token's mechanism list during initialization.
// SecurityLevel is High - keys are protected by local HSM hardware.
func (b *Backend) Capabilities() types.Capabilities {
	caps := types.NewHardwareCapabilities()
	caps.SymmetricEncryption = true
	caps.Import = true // PKCS#11 supports key import
	caps.Export = true // PKCS#11 supports key export (if CKA_EXTRACTABLE=true)
	caps.QuantumSigning = b.supportsMLDSA

	// KeyEncapsulation stays false even on a token that advertises ML-KEM.
	//
	// The flag feeds pkg/xkms/algorithms.go, which publishes ML-KEM-1024 as an
	// algorithm this backend offers — but the backend implements no
	// encapsulate or decapsulate operation at all, and types.KeyProvider
	// defines none, so an ML-KEM key here can be generated, listed, resolved
	// and deleted and never actually used. Advertising an algorithm the
	// backend cannot perform is the defect; b.supportsMLKEM is retained
	// because it correctly records what the TOKEN supports, which is what a
	// future implementation will gate on.
	//
	// Making this true requires Encapsulate/Decapsulate on the multi-backend
	// KeyProvider contract, which this project requires to ship a complete
	// implementation for every backend in one change set.
	caps.KeyEncapsulation = false

	caps.SecurityLevel = types.SecurityLevelHigh // Explicit for clarity
	return caps
}

// probeQuantumMechanisms queries the token's mechanism list to detect support
// for PKCS#11 v3.2 post-quantum mechanisms (ML-DSA and ML-KEM), and for the
// AES cipher-mode mechanisms (CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_ECB) the
// symmetric encrypter's non-AEAD modes need. Results are stored in
// supportsMLDSA, supportsMLKEM, supportsAESCBC, supportsAESCBCPad and
// supportsAESECB. This method is safe to call when p11ctx is nil (no-op).
func (b *Backend) probeQuantumMechanisms() {
	if b.p11ctx == nil {
		return
	}

	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return
	}

	var slot uint
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	} else {
		slot = slots[0]
	}

	mechs, err := b.p11ctx.GetMechanismList(slot)
	if err != nil {
		return
	}

	for _, mech := range mechs {
		switch mech.Mechanism {
		case CKM_ML_DSA_KEY_PAIR_GEN:
			b.supportsMLDSA = true
		case CKM_ML_KEM_KEY_PAIR_GEN:
			b.supportsMLKEM = true
		case pkcs11.CKM_AES_CBC:
			b.supportsAESCBC = true
		case pkcs11.CKM_AES_CBC_PAD:
			b.supportsAESCBCPad = true
		case pkcs11.CKM_AES_ECB:
			b.supportsAESECB = true
		}
	}
}

// Get reports that key material cannot be read out of a PKCS#11 token through
// the file-oriented storage interface, for any extension.
//
// A token exists precisely so that private key material never leaves the
// device, and the public half is obtained from the crypto.Signer that Signer()
// returns rather than as opaque bytes. Since no key on the token can satisfy
// this call, it answers backend.ErrNotSupported without consulting the device:
// searching for the key first would spend a session on a lookup whose outcome
// cannot change the answer, and would report a missing key as the reason a
// supported operation failed.
func (b *Backend) Get(attrs *types.KeyAttributes, extension types.FSExtension) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: "PKCS#11 private keys cannot be exported; use Signer() for the public key"}
}

// Save stores key metadata to the PKCS#11 backend.
// Note: This doesn't store the actual key material - keys are created via GenerateKey methods
// and live only within the HSM.
//
// This method can be used to store associated metadata if needed.
func (b *Backend) Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return ErrNotInitialized
	}

	// For PKCS#11, saving key material directly is not supported
	// Keys must be generated on the HSM using GenerateRSA/GenerateECDSA
	return &errs.Detail{Err: backend.ErrNotSupported, Detail: "use GenerateKey methods to create keys on HSM"}
}

// DeleteKey removes a key from the PKCS#11 backend.
// This finds the key object and destroys it using the low-level PKCS#11 API.
//
// Note: Some HSMs may not support key deletion or may require special permissions.
// The behavior depends on the specific HSM and its configuration.
// findObjectsBatchSize is the number of object handles requested per
// C_FindObjects call. It trades round trips against the size of the handle
// buffer the token fills; it is not a limit on the result, because
// findAllObjects keeps calling until the search is exhausted.
const findObjectsBatchSize = 256

// findAllObjects returns every object on the token matching template.
//
// C_FindObjects is an iterative interface (PKCS#11 v3.0 section 5.7): each call
// returns at most the requested number of handles and must be repeated until it
// returns none. A single call therefore answers "here is a batch", not "here is
// everything", and treating it as the latter truncates the result silently,
// which a caller reads as a complete answer.
//
// The search is finalized on every path, including the error path, because a
// session that still has a search active rejects the next C_FindObjectsInit
// with CKR_OPERATION_ACTIVE.
func (b *Backend) findAllObjects(session pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := b.p11ctx.FindObjectsInit(session, template); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to init find objects", Err: err}
	}

	var objs []pkcs11.ObjectHandle
	for {
		batch, _, err := b.p11ctx.FindObjects(session, findObjectsBatchSize)
		if err != nil {
			if finalErr := b.p11ctx.FindObjectsFinal(session); finalErr != nil {
				return nil, &errs.Wrapped{Msg: "failed to find objects, and the search could not be finalized", Err: err}
			}
			return nil, &errs.Wrapped{Msg: "failed to find objects", Err: err}
		}
		if len(batch) == 0 {
			break
		}
		objs = append(objs, batch...)
	}

	if err := b.p11ctx.FindObjectsFinal(session); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to finalize find objects", Err: err}
	}
	return objs, nil
}

// findObjectsByClassAndID locates all PKCS#11 objects with the given CKA_CLASS
// and CKA_ID within an open session. Caller must hold b.mu.
func (b *Backend) findObjectsByClassAndID(session pkcs11.SessionHandle, class uint, id []byte) ([]pkcs11.ObjectHandle, error) {
	return b.findAllObjects(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
}

// deleteKeyInSession performs the find+destroy sequence for both the private
// and public key objects matching id, then verifies the objects are gone. It
// returns an error that wraps hardware.ErrDeleteNotSupportedOnToken when an
// object survives DestroyObject, which happens on YubiKey PIV because
// libykcs11 silently no-ops the call.
func (b *Backend) deleteKeyInSession(session pkcs11.SessionHandle, id []byte, cn string) error {
	privObjs, err := b.findObjectsByClassAndID(session, pkcs11.CKO_PRIVATE_KEY, id)
	if err != nil {
		return err
	}
	for _, obj := range privObjs {
		if err := b.p11ctx.DestroyObject(session, obj); err != nil {
			return &errs.Wrapped{Msg: "failed to destroy private key", Err: err}
		}
	}

	pubObjs, err := b.findObjectsByClassAndID(session, pkcs11.CKO_PUBLIC_KEY, id)
	if err != nil {
		return err
	}
	for _, obj := range pubObjs {
		if err := b.p11ctx.DestroyObject(session, obj); err != nil {
			return &errs.Wrapped{Msg: "failed to destroy public key", Err: err}
		}
	}

	if len(privObjs) == 0 && len(pubObjs) == 0 {
		return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", cn)}
	}

	return b.verifyKeyRemoved(session, id, cn)
}

// verifyKeyRemoved reports an error when either half of the key pair is still
// present in the session's view of the token. YubiKey PIV libykcs11 accepts
// C_DestroyObject under CKU_SO but leaves the PIV slot contents in place, so a
// successful C_DestroyObject is not evidence that the key is gone.
//
// The session matters: a token that hides private objects from the logged-in
// user type reports the key as absent no matter what, which is why DeleteKey
// repeats this check under CKU_USER after deleting under CKU_SO.
func (b *Backend) verifyKeyRemoved(session pkcs11.SessionHandle, id []byte, cn string) error {
	if remaining, verr := b.findObjectsByClassAndID(session, pkcs11.CKO_PRIVATE_KEY, id); verr == nil && len(remaining) > 0 {
		return &errs.Detail{Err: hardware.ErrDeleteNotSupportedOnToken, Detail: fmt.Sprintf("private key %q still present after DestroyObject -- token does not support deletion (YubiKey PIV slots must be overwritten or reset via 'ykman piv reset')", cn)}
	}
	if remaining, verr := b.findObjectsByClassAndID(session, pkcs11.CKO_PUBLIC_KEY, id); verr == nil && len(remaining) > 0 {
		return &errs.Detail{Err: hardware.ErrDeleteNotSupportedOnToken, Detail: fmt.Sprintf("public key %q still present after DestroyObject -- token does not support deletion (YubiKey PIV slots must be overwritten or reset via 'ykman piv reset')", cn)}
	}

	return nil
}

// DeleteKey removes a private/public key pair from the PKCS#11 token.
//
// For YubiKey PIV, C_DestroyObject is rejected under CKU_USER with
// CKR_USER_TYPE_INVALID, so the delete is executed under CKU_SO
// (management key) via SessionPool.WithSOSession. Even then, libykcs11
// may silently accept the call without actually clearing the slot, so
// the operation verifies removal and returns hardware.ErrDeleteNotSupportedOnToken
// with actionable guidance when the object persists.
func (b *Backend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return ErrNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return err
	}

	fn := func(session pkcs11.SessionHandle) error {
		return b.deleteKeyInSession(session, id, attrs.CN)
	}

	if b.config.IsYubiKeyPIV() && b.config.SOPIN != nil {
		soPIN, err := b.soPIN()
		if err != nil {
			return err
		}
		userPIN, err := b.userPIN()
		if err != nil {
			return err
		}
		if err := b.pool.WithSOSession(soPIN, userPIN, fn); err != nil {
			return err
		}
		// A CKU_SO session cannot see private objects on every token, so the
		// verification inside deleteKeyInSession may have been blind to a
		// private key that survived. Repeat it under the restored CKU_USER
		// login, where private objects are visible, so a token that quietly
		// keeps the key can never be reported as a successful deletion.
		return b.pool.WithSession(func(session pkcs11.SessionHandle) error {
			return b.verifyKeyRemoved(session, id, attrs.CN)
		})
	}
	return b.pool.WithSession(fn)
}

// Delete removes a key from the PKCS#11 backend.
// This is an alias for DeleteKey to satisfy the Storage interface.
func (b *Backend) Delete(attrs *types.KeyAttributes) error {
	return b.DeleteKey(context.Background(), attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
// It enumerates all private key objects on the PKCS#11 token and returns
// their key attributes including algorithm type and PIV slot mapping.
func (b *Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	var results []*types.KeyAttributes
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		handles, err := b.findAllObjects(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "list keys", Err: err}
		}

		for _, h := range handles {
			readAttrs, err := b.p11ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			})
			if err != nil || len(readAttrs) < 3 {
				continue
			}

			ka := &types.KeyAttributes{
				StoreType: types.StorePKCS11,
			}

			// Map CKA_ID to PIV slot if applicable
			if len(readAttrs[0].Value) == 1 {
				if slot, ok := pivpkcs11.CKAIDToPIVSlot(readAttrs[0].Value[0]); ok {
					ka.PIVSlot = string(slot)
				}
			}

			decodeKeyType(ka, ckULong(readAttrs[2].Value), string(readAttrs[1].Value))

			results = append(results, ka)
		}
		return nil
	})

	return results, err
}

// ckULong decodes a CK_ULONG attribute value. PKCS#11 returns these as the
// raw little-endian bytes of the platform's CK_ULONG, so the whole value is
// reassembled rather than assuming the interesting bits sit in the low byte.
func ckULong(value []byte) uint {
	var n uint
	for i, b := range value {
		n |= uint(b) << (8 * i)
	}
	return n
}

// keyTypeDecoder fills in the algorithm-dependent attributes of an enumerated
// key from the CKA_LABEL the generator wrote.
type keyTypeDecoder func(ka *types.KeyAttributes, label string)

// keyTypeDecoders maps CKA_KEY_TYPE to the decoder for that key type. Every
// algorithm this backend can generate must appear here: a key type that is
// missing enumerates with no algorithm at all, which then makes resolveKeyID
// compute the wrong CKA_ID and route operations such as DeleteKey to the wrong
// object (or to no object).
var keyTypeDecoders = map[uint]keyTypeDecoder{
	pkcs11.CKK_RSA: classicalKeyDecoder(x509.RSA),
	pkcs11.CKK_EC:  classicalKeyDecoder(x509.ECDSA),
	CKK_EC_EDWARDS: classicalKeyDecoder(x509.Ed25519),
	CKK_ML_DSA:     decodeQuantumKey,
	CKK_ML_KEM:     decodeQuantumKey,
}

// decodeKeyType populates ka from a token object's CKA_KEY_TYPE and CKA_LABEL.
// An unrecognized key type leaves ka carrying only its CN, which is the most
// that can be said about it.
func decodeKeyType(ka *types.KeyAttributes, keyType uint, label string) {
	decode, ok := keyTypeDecoders[keyType]
	if !ok {
		ka.CN = label
		return
	}
	decode(ka, label)
}

// classicalKeyDecoder builds the decoder for a key type that maps onto an
// x509.PublicKeyAlgorithm. CKA_LABEL carries the composite key ID createKeyID
// wrote, so the algorithm suffix is stripped back off. Without this the
// returned attributes would not resolve to the same CKA_ID and every
// enumerated key would be unaddressable.
func classicalKeyDecoder(algorithm x509.PublicKeyAlgorithm) keyTypeDecoder {
	return func(ka *types.KeyAttributes, label string) {
		ka.KeyAlgorithm = algorithm
		ka.CN = keyIDToCN(label, algorithm)
	}
}

// decodeQuantumKey recovers the CN and the post-quantum parameter set from the
// composite key ID createQuantumKeyID wrote.
//
// CKA_KEY_TYPE alone cannot answer this: CKK_ML_DSA is one key type covering
// ML-DSA-44, -65 and -87, and x509.PublicKeyAlgorithm has no ML-DSA member at
// all, so the parameter set is reported through QuantumAttributes and read back
// out of the label.
func decodeQuantumKey(ka *types.KeyAttributes, label string) {
	cn, algorithm, ok := quantumKeyIDToCN(label)
	if !ok {
		ka.CN = label
		return
	}
	ka.CN = cn
	ka.QuantumAttributes = &types.QuantumAttributes{Algorithm: algorithm}
}

// Decrypter returns a crypto.Decrypter for the specified key.
// This allows the key to be used for decryption operations without
// exposing the private key material.
func (b *Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	// For PKCS#11, decryption is handled through the HSM.
	// RSA signers implement crypto.Decrypter (PKCS1v15 and OAEP).
	signer, err := b.Signer(ctx, attrs)
	if err != nil {
		return nil, err
	}

	// Check if the signer also implements crypto.Decrypter
	if decrypter, ok := signer.(crypto.Decrypter); ok {
		return decrypter, nil
	}

	return nil, &errs.Detail{Err: backend.ErrOperationNotSupported, Detail: "key does not support decryption"}
}

// RotateKey rotates/updates a key identified by attrs.
// For PKCS#11, this is not typically supported as keys are managed on the HSM.
func (b *Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return &errs.Detail{Err: backend.ErrOperationNotSupported, Detail: "key rotation not supported for PKCS#11"}
}

// GenerateRandom generates cryptographically secure random bytes using the HSM's
// hardware random number generator. This provides true hardware entropy from the PKCS#11 device.
//
// Parameters:
//   - length: Number of random bytes to generate (must be > 0)
//
// Returns the random bytes or an error if generation fails.
//
// Note: Some PKCS#11 devices have limits on the maximum number of bytes that can
// be generated in a single call. If you need more than 1024 bytes, consider making
// multiple calls.
func (b *Backend) GenerateRandom(length int) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	if length <= 0 {
		return nil, &errs.Message{Msg: fmt.Sprintf("pkcs11: invalid length %d, must be > 0", length)}
	}

	var randomBytes []byte
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		randomBytes, err = b.p11ctx.GenerateRandom(session, length)
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: failed to generate random bytes", Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

// Close releases the PKCS#11 session pool and any associated resources.
// This method is idempotent and can be called multiple times safely.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var err error
	if b.pool != nil {
		err = b.pool.Close()
		b.pool = nil
	}

	if b.p11ctx != nil && b.ownsP11ctx {
		if b.ownsP11Init {
			if finalizeErr := b.p11ctx.Finalize(); finalizeErr != nil {
				err = errors.Join(err, finalizeErr)
			}
		}
		b.p11ctx.Destroy()
		b.p11ctx = nil
	}

	return err
}

// Initialize sets up the PKCS#11 token with the provided SO PIN and user PIN.
// This is typically done once during initial token setup.
//
// For SoftHSM, this will automatically configure and initialize the token.
// For hardware HSMs, ensure the token is properly set up before calling this method.
//
// Parameters:
//   - soPIN: Security Officer PIN (administrative)
//   - userPIN: User PIN (for normal operations)
//
// Returns ErrAlreadyInitialized if the token is already initialized.
func (b *Backend) Initialize(soPIN, userPIN string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Validate PIN lengths
	if len(soPIN) < 4 {
		return ErrInvalidSOPINLength
	}
	if len(userPIN) < 4 {
		return ErrInvalidPINLength
	}

	b.config.SOPIN = types.NewLiteralSecretValue([]byte(soPIN))
	b.config.PIN = types.NewLiteralSecretValue([]byte(userPIN))

	// If pool already exists, we're already initialized
	if b.pool != nil {
		return ErrAlreadyInitialized
	}

	// Initialize token using low-level PKCS#11
	if err := b.initializeToken(soPIN, userPIN); err != nil {
		// If already initialized, that's okay
		if !errors.Is(err, ErrAlreadyInitialized) {
			return &errs.Wrapped{Msg: "failed to initialize token", Err: err}
		}
	}

	// Login to establish session pool
	return b.loginUser(userPIN)
}

// Login authenticates with the PKCS#11 token using the user PIN.
// This must be called before performing cryptographic operations.
//
// The method uses a cached context if available to avoid re-initialization.
//
// Returns an error if login fails or if the token is not initialized.
func (b *Backend) Login() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.config.PIN == nil {
		return ErrInvalidUserPIN
	}

	pin, err := b.userPIN()
	if err != nil {
		return err
	}
	return b.loginUser(pin)
}

// loginUser initializes the raw PKCS#11 context and creates the session pool.
// Must be called with mutex held.
func (b *Backend) loginUser(pin string) error {
	// Initialize raw PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return &errs.Message{Msg: fmt.Sprintf("failed to load PKCS#11 library: %s", b.config.Library)}
		}
		// C_Initialize/C_Finalize are process-global, not per-Ctx: only the
		// backend whose call actually performed the initialization may
		// Finalize it later. A backend that attaches to a library another
		// backend already initialized (CKR_CRYPTOKI_ALREADY_INITIALIZED) must
		// leave ownsP11Init false, or Close on both backends calls C_Finalize
		// on the one shared module and the second call fails with
		// CKR_CRYPTOKI_NOT_INITIALIZED (see errors.Join on Close's return).
		// Destroying this backend's own *pkcs11.Ctx (unloading its private
		// dlopen handle) is independent of that and always safe, so
		// ownsP11ctx stays true regardless.
		ownsInit := true
		if err := p.Initialize(); err != nil {
			if !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				p.Destroy()
				return &errs.Wrapped{Msg: "failed to initialize PKCS#11", Err: err}
			}
			ownsInit = false
		}
		b.p11ctx = p
		b.ownsP11ctx = true
		b.ownsP11Init = ownsInit
	}

	// Resolve slot by token label or configured slot number
	slotID, err := b.resolveSlot()
	if err != nil {
		return &errs.Wrapped{Msg: "failed to resolve slot", Err: err}
	}

	// Create session pool
	poolSize := b.config.SessionPoolSize
	if poolSize <= 0 {
		poolSize = DefaultSessionPoolSize
	}
	pool, err := NewSessionPool(b.p11ctx, slotID, pin, poolSize)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to create session pool", Err: err}
	}
	b.pool = pool

	// Attach PIV slot model for YubiKey PIV tokens.
	if b.config.IsYubiKeyPIV() {
		sm, smErr := pivpkcs11.NewPIVSlotModel(b.pool)
		if smErr == nil {
			b.slotModel = sm
		}
		// Non-fatal: slot model is optional enhancement
	}

	// Probe for quantum mechanism support after establishing context
	b.probeQuantumMechanisms()

	return nil
}

// resolveSlot determines the PKCS#11 slot ID based on configuration.
// If a slot number is configured, it is used directly. Otherwise, the slot
// is resolved by matching the token label against available tokens.
func (b *Backend) resolveSlot() (uint, error) {
	if b.config.Slot != nil {
		return uint(*b.config.Slot), nil
	}

	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return 0, &errs.Wrapped{Msg: "failed to get slot list", Err: err}
	}
	if len(slots) == 0 {
		return 0, ErrTokenNotFound
	}

	// If token label is set, find the matching slot
	if b.config.TokenLabel != "" {
		for _, slot := range slots {
			tokenInfo, err := b.p11ctx.GetTokenInfo(slot)
			if err != nil {
				continue
			}
			// PKCS#11 pads token labels with spaces to 32 characters
			if strings.TrimRight(tokenInfo.Label, " ") == strings.TrimRight(b.config.TokenLabel, " ") {
				return slot, nil
			}
		}
		return 0, &errs.Detail{Err: ErrTokenNotFound, Detail: fmt.Sprintf("token label %q not found", b.config.TokenLabel)}
	}

	// Default to first available slot
	return slots[0], nil
}

// initializeToken initializes a PKCS#11 token with SO and user PINs.
// Must be called with mutex held.
func (b *Backend) initializeToken(soPIN, userPIN string) (err error) {
	// Initialize low-level PKCS#11 context
	p := pkcs11.New(b.config.Library)
	if p == nil {
		return &errs.Message{Msg: fmt.Sprintf("failed to load PKCS#11 library: %s", b.config.Library)}
	}

	if err := p.Initialize(); err != nil {
		// Check if already initialized
		if isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			p.Destroy()
			return ErrAlreadyInitialized
		}
		p.Destroy()
		return &errs.Wrapped{Msg: "failed to initialize PKCS#11", Err: err}
	}

	defer p.Destroy()
	defer func() {
		if finalizeErr := p.Finalize(); finalizeErr != nil {
			err = errors.Join(err, finalizeErr)
		}
	}()

	// Get token slot
	slots, slotErr := p.GetSlotList(true)
	if slotErr != nil {
		return &errs.Wrapped{Msg: "failed to get slot list", Err: slotErr}
	}

	if len(slots) == 0 {
		return ErrTokenNotFound
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	// Get token info to check initialization status
	tokenInfo, infoErr := p.GetTokenInfo(slot)
	if infoErr != nil {
		return &errs.Wrapped{Msg: "failed to get token info", Err: infoErr}
	}

	// Check if token needs initialization
	if tokenInfo.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
		// Initialize token
		if initErr := p.InitToken(slot, soPIN, b.config.TokenLabel); initErr != nil {
			return &errs.Wrapped{Msg: "failed to init token", Err: initErr}
		}

		// Open session and init user PIN
		session, sessionErr := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if sessionErr != nil {
			return &errs.Wrapped{Msg: "failed to open session", Err: sessionErr}
		}
		defer func() {
			if closeErr := p.CloseSession(session); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}()

		// Login as SO
		if loginErr := p.Login(session, pkcs11.CKU_SO, soPIN); loginErr != nil {
			return &errs.Wrapped{Msg: "failed to login as SO", Err: loginErr}
		}
		defer func() {
			if logoutErr := p.Logout(session); logoutErr != nil {
				err = errors.Join(err, logoutErr)
			}
		}()

		// Initialize user PIN
		if pinErr := p.InitPIN(session, userPIN); pinErr != nil {
			return &errs.Wrapped{Msg: "failed to init user PIN", Err: pinErr}
		}
	} else {
		return ErrAlreadyInitialized
	}

	return nil
}

// GenerateKey dispatches key generation to the appropriate algorithm-specific method.
// Supports RSA, ECDSA, Ed25519, and post-quantum algorithms (ML-DSA, ML-KEM)
// when QuantumAttributes are specified.
func (b *Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Check for quantum key generation first
	if attrs.QuantumAttributes != nil {
		return b.generateQuantumKey(attrs)
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.GenerateRSA(attrs)
	case x509.ECDSA:
		return b.GenerateECDSA(attrs)
	case x509.Ed25519:
		return b.GenerateEd25519(attrs)
	default:
		return nil, ErrUnsupportedKeyAlgorithm
	}
}

// quantumFamily describes one post-quantum algorithm family as PKCS#11 v3.2
// models it: the CKA_KEY_TYPE its keys carry, the mechanism that generates
// them, and the mechanism that uses them.
//
// One record per family is the single source of truth for every layer that has
// to agree on those numbers. Generation picks the family from the requested
// parameter set; key lookup picks the same family back out of the CKA_KEY_TYPE
// it reads off the token. Splitting that correspondence across two independent
// switch statements is what previously let generation write a key type that
// lookup did not recognise.
type quantumFamily struct {
	// name is the parameter-set prefix, for example "ML-DSA".
	name string

	// keyType is the CKA_KEY_TYPE that objects of this family carry.
	keyType uint

	// keyPairGen is the CKM_* mechanism that generates a key pair.
	keyPairGen uint

	// operation is the CKM_* mechanism that uses the key.
	operation uint

	// signs reports whether operation is a signature mechanism. ML-KEM is a
	// key-encapsulation mechanism, so C_SignInit and C_VerifyInit are not
	// defined over it and a conforming token answers CKR_MECHANISM_INVALID.
	signs bool

	// supported reports whether the token advertised this family's generation
	// mechanism when the backend probed it.
	supported func(b *Backend) bool
}

// quantumFamilyMLDSA is the ML-DSA (FIPS 204) signature family.
var quantumFamilyMLDSA = &quantumFamily{
	name:       "ML-DSA",
	keyType:    CKK_ML_DSA,
	keyPairGen: CKM_ML_DSA_KEY_PAIR_GEN,
	operation:  CKM_ML_DSA,
	signs:      true,
	supported:  func(b *Backend) bool { return b.supportsMLDSA },
}

// quantumFamilyMLKEM is the ML-KEM (FIPS 203) key-encapsulation family.
var quantumFamilyMLKEM = &quantumFamily{
	name:       "ML-KEM",
	keyType:    CKK_ML_KEM,
	keyPairGen: CKM_ML_KEM_KEY_PAIR_GEN,
	operation:  CKM_ML_KEM,
	signs:      false,
	supported:  func(b *Backend) bool { return b.supportsMLKEM },
}

// quantumFamilies holds every post-quantum family this backend implements.
var quantumFamilies = []*quantumFamily{quantumFamilyMLDSA, quantumFamilyMLKEM}

// quantumFamilyForAlgorithm returns the family that owns a parameter set such
// as "ML-DSA-65", and reports whether one was found.
func quantumFamilyForAlgorithm(algorithm string) (*quantumFamily, bool) {
	for _, family := range quantumFamilies {
		if strings.HasPrefix(algorithm, family.name) {
			return family, true
		}
	}
	return nil, false
}

// parameterSet recovers the exact parameter set a key object's identifier
// encodes, for example "ML-DSA-65" from "signing-key.ml-dsa-65".
//
// The identifier is what generateQuantumKey wrote to CKA_ID and CKA_LABEL, so
// a key this backend created always yields its parameter set. A key some other
// tool put on the token under an identifier of its own choosing yields the
// family name instead: the parameter set is reported metadata, whereas the
// mechanism that actually drives the token comes from CKA_KEY_TYPE, so an
// unrecognised identifier costs precision and not correctness.
func (f *quantumFamily) parameterSet(id []byte) string {
	if _, algorithm, ok := quantumKeyIDToCN(string(id)); ok && strings.HasPrefix(string(algorithm), f.name) {
		return string(algorithm)
	}
	return f.name
}

// generateQuantumKey generates a post-quantum key pair on the HSM using PKCS#11 v3.2 mechanisms.
// It supports ML-DSA (signing) and ML-KEM (key encapsulation) algorithms. The private key
// never leaves the HSM hardware; a wrapper type carrying the object handles is returned.
//
// For ML-DSA the returned value implements crypto.Signer and signs on the token.
// For ML-KEM it carries the key-encapsulation handles; signing with it is refused,
// because C_SignInit is not defined over CKM_ML_KEM.
func (b *Backend) generateQuantumKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	if attrs.QuantumAttributes == nil {
		return nil, ErrInvalidKeyAttributes
	}

	algorithm := string(attrs.QuantumAttributes.Algorithm)

	family, ok := quantumFamilyForAlgorithm(algorithm)
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("unsupported quantum algorithm: %s", algorithm)}
	}
	if !family.supported(b) {
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("token does not support %s", family.name)}
	}

	id := []byte(createQuantumKeyID(attrs))
	publicKeyTemplate, privateKeyTemplate := quantumKeyTemplates(family.keyType, id)

	var pubHandle, privHandle pkcs11.ObjectHandle
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		pubHandle, privHandle, err = b.p11ctx.GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(family.keyPairGen, nil)},
			publicKeyTemplate,
			privateKeyTemplate,
		)
		return err
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to generate %s key pair", algorithm), Err: err}
	}

	// The same wrapper findKeyPairByID hands back for a key read off the
	// token, so a key is used through one code path whether it was just
	// generated or found later by CKA_ID.
	return newQuantumSigner(family, b.pool, pubHandle, privHandle, id)
}

// newQuantumSigner builds the wrapper that delegates post-quantum operations on
// a key pair to the token.
func newQuantumSigner(family *quantumFamily, pool *SessionPool, pubHandle, privHandle pkcs11.ObjectHandle, id []byte) (crypto.Signer, error) {
	return &pkcs11MLDSASigner{
		pool:          pool,
		publicHandle:  pubHandle,
		privateHandle: privHandle,
		label:         string(id),
		algorithm:     family.parameterSet(id),
		family:        family,
	}, nil
}

// quantumKeyTemplates builds the public and private CKA templates for a
// post-quantum key pair of the given CKA_KEY_TYPE.
//
// id is written to both CKA_ID and CKA_LABEL, which is the convention every
// generation path in this backend follows. ListKeys recovers the CN and the
// parameter set from CKA_LABEL and resolveKeyID rebuilds CKA_ID from the
// attributes it reported, so a label holding anything else -- the bare CN, for
// instance -- would enumerate a key whose reported CN resolves to a CKA_ID no
// object has, leaving every listed post-quantum key unaddressable.
//
// The private half is created CKA_SENSITIVE and CKA_PRIVATE so the key is
// unreadable and unlistable outside an authenticated session, which is the
// whole point of generating it on the token.
func quantumKeyTemplates(keyType uint, id []byte) (public, private []*pkcs11.Attribute) {
	public = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	private = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	return public, private
}

// GenerateRSA creates an RSA key pair on the HSM with the specified key size.
// The private key never leaves the HSM hardware.
//
// Parameters:
//   - attrs: Key attributes (CN, key type, algorithm, etc.)
//   - keySize: RSA key size in bits (e.g., 2048, 3072, 4096)
//
// Default key size is 2048 bits if keySize is 0 or invalid.
func (b *Backend) GenerateRSAWithSize(attrs *types.KeyAttributes, keySize int) (crypto.Signer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	// Apply default key size if not specified or invalid
	if keySize == 0 || keySize < 512 {
		keySize = 2048
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	soPIN, err := b.soPIN()
	if err != nil {
		return nil, err
	}
	userPIN, err := b.userPIN()
	if err != nil {
		return nil, err
	}
	signer, err := generateRSAKeyPair(b.pool, id, id, keySize, b.config.IsYubiKeyPIV(), soPIN, userPIN)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate RSA key", Err: err}
	}

	return signer, nil
}

// GenerateRSA creates an RSA key pair on the HSM with default 2048-bit key size.
// The private key never leaves the HSM hardware.
//
// For custom key sizes, use GenerateRSAWithSize instead.
func (b *Backend) GenerateRSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	// Extract key size from attributes, default to 2048 if not specified
	keySize := 2048
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
		keySize = attrs.RSAAttributes.KeySize
	}
	return b.GenerateRSAWithSize(attrs, keySize)
}

// GenerateECDSAWithCurve creates an ECDSA key pair on the HSM with the specified curve.
// The private key never leaves the HSM hardware.
//
// Parameters:
//   - attrs: Key attributes (CN, key type, algorithm, etc.)
//   - curve: Elliptic curve (e.g., P-256, P-384, P-521)
//
// Default curve is P-256 if curve is nil.
func (b *Backend) GenerateECDSAWithCurve(attrs *types.KeyAttributes, curve elliptic.Curve) (crypto.Signer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	// Apply default curve if not specified
	if curve == nil || curve.Params() == nil {
		curve = elliptic.P256()
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	soPIN, err := b.soPIN()
	if err != nil {
		return nil, err
	}
	userPIN, err := b.userPIN()
	if err != nil {
		return nil, err
	}
	signer, err := generateECDSAKeyPair(b.pool, id, id, curve, b.config.IsYubiKeyPIV(), soPIN, userPIN)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate ECDSA key", Err: err}
	}

	return signer, nil
}

// GenerateECDSA creates an ECDSA key pair on the HSM with default P-256 curve.
// The private key never leaves the HSM hardware.
//
// For custom curves, use GenerateECDSAWithCurve instead.
func (b *Backend) GenerateECDSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	// Extract curve from attributes, default to P-256 if not specified
	var curve elliptic.Curve
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		curve = attrs.ECCAttributes.Curve
	} else {
		curve = elliptic.P256()
	}
	return b.GenerateECDSAWithCurve(attrs, curve)
}

// GenerateEd25519 creates an Ed25519 key pair on the HSM.
// The private key never leaves the HSM hardware.
//
// Note: Ed25519 support requires PKCS#11 v3.0 or later and HSM support for Edwards curves.
// SoftHSM v2.6+ supports Ed25519.
func (b *Backend) GenerateEd25519(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.config != nil && b.config.IsYubiKeyPIV() {
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: "YubiKey PIV does not support Ed25519 keys; use ECDSA P-256 or RSA instead"}
	}

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	// CKA_LABEL carries the same key ID as CKA_ID, matching the RSA, ECDSA and
	// secret key generators and the repair step the import path applies after
	// C_UnwrapKey. A generated key and an imported one must be labelled
	// identically or ListKeys reports two different names for the same key.
	label := id

	// Ed25519 OID (1.3.101.112) - RFC 8410
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	var pubKey, privKey pkcs11.ObjectHandle
	err = b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		pubKey, privKey, err = b.p11ctx.GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)},
			publicKeyTemplate,
			privateKeyTemplate,
		)
		return err
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate Ed25519 key pair", Err: err}
	}

	signer, err := newEd25519Signer(b.pool, pubKey, privKey, label)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read generated Ed25519 public key", Err: err}
	}

	return signer, nil
}

// GenerateSecretKey generates an AES secret key on the HSM.
// The secret key never leaves the HSM hardware and can be used for symmetric
// encryption/decryption operations.
//
// Supported key sizes:
//   - 128 bits (16 bytes) - AES-128
//   - 192 bits (24 bytes) - AES-192
//   - 256 bits (32 bytes) - AES-256
//
// Parameters:
//   - attrs: Key attributes (CN, key type, etc.)
//   - keySize: AES key size in bits (128, 192 or 256)
//
// Returns the object handle of the generated secret key, or an error if generation fails.
func (b *Backend) GenerateSecretKey(attrs *types.KeyAttributes, keySize int) (pkcs11.ObjectHandle, error) {
	// NOTE: Caller must hold b.mu.Lock()
	if b.pool == nil {
		return 0, ErrNotInitialized
	}

	// FIPS 197 defines three AES key sizes and PKCS#11 CKM_AES_KEY_GEN accepts
	// all three, so refusing 192 here would reject a size the token advertises
	// as supported through CK_MECHANISM_INFO's ulMinKeySize/ulMaxKeySize range.
	if !validAESKeySizes[keySize] {
		return 0, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("AES key size %d bits (only 128, 192 and 256 are supported)", keySize)}
	}

	label := createKeyID(attrs)
	valueLenBytes := uint(keySize / 8)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(label)),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, valueLenBytes),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}

	var handle pkcs11.ObjectHandle
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		handle, err = b.p11ctx.GenerateKey(session, mechanism, template)
		return err
	})
	if err != nil {
		return 0, &errs.Wrapped{Msg: "failed to generate AES secret key", Err: err}
	}

	return handle, nil
}

// FindSecretKey finds an existing secret key by label.
//
// Parameters:
//   - attrs: Key attributes including the CN to search for
//
// Returns the object handle of the secret key, or an error if not found.
func (b *Backend) FindSecretKey(attrs *types.KeyAttributes) (pkcs11.ObjectHandle, error) {
	if b.pool == nil {
		return 0, ErrNotInitialized
	}

	label := createKeyID(attrs)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	var handle pkcs11.ObjectHandle
	err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		found, searchErr := b.pool.FindObjectHandle(session, template)
		if searchErr != nil {
			return &errs.Wrapped{Msg: "failed to find objects", Err: searchErr}
		}
		if found == 0 {
			return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
		}
		handle = found
		return nil
	})
	if err != nil {
		return 0, err
	}
	return handle, nil
}

// GetKey retrieves an existing private key by its attributes.
// For PKCS#11, this returns a crypto.Signer that performs operations on the HSM.
// The private key material never leaves the hardware module.
func (b *Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Delegate to Signer since PKCS#11 keys are always hardware-backed signers
	return b.Signer(ctx, attrs)
}

// GetSignerByID retrieves a crypto.Signer for the specified key by name.
func (b *Backend) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_PKCS11,
	}
	key, err := b.GetKey(context.Background(), attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("key %s does not implement crypto.Signer", keyID)}
	}
	return signer, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter for the specified key by name.
func (b *Backend) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_PKCS11,
	}
	key, err := b.GetKey(context.Background(), attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("key %s does not implement crypto.Decrypter", keyID)}
	}
	return decrypter, nil
}

// Signer returns a crypto.Signer for the specified key.
// The signer performs operations using the HSM without exposing private key material.
func (b *Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	signer, err := findKeyPairByID(b.pool, id)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to find key", Err: err}
	}
	if signer == nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

	return signer, nil
}

// Sign signs a digest using the specified key on the HSM.
func (b *Backend) Sign(attrs *types.KeyAttributes, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signer, err := b.Signer(context.Background(), attrs)
	if err != nil {
		return nil, err
	}

	return signer.Sign(nil, digest, opts)
}

// Verify verifies a signature using the public key.
// Classical signatures are checked in software using the public key retrieved
// from the HSM; post-quantum signatures are checked on the token.
//
// For RSA, attrs.SignatureAlgorithm selects both the digest and the padding
// scheme; see verifyRSA for why it is required rather than defaulted. For
// ECDSA the signature is ASN.1 DER as CKM_ECDSA produces it via the signer.
// For Ed25519 the digest argument is the message itself, because Ed25519
// signs the message rather than a pre-computed digest (RFC 8032 section 4).
// For ML-DSA the digest argument is likewise the message, and the check runs
// on the token because Go's standard library has no ML-DSA public key type to
// verify against in software.
func (b *Backend) Verify(attrs *types.KeyAttributes, digest, signature []byte) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return ErrNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return err
	}

	signer, err := findKeyPairByID(b.pool, id)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to find key", Err: err}
	}
	if signer == nil {
		return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

	return verifyPublicKey(signer.Public(), attrs, digest, signature)
}

// verifyPublicKey routes a signature check to the scheme that belongs to the
// public key the token handed back.
//
// It is separate from Verify so the routing can be exercised for a key type the
// test token cannot hold: SoftHSM2 refuses post-quantum objects, so the ML-DSA
// branch is unreachable through Verify itself.
func verifyPublicKey(public crypto.PublicKey, attrs *types.KeyAttributes, digest, signature []byte) error {
	switch pub := public.(type) {
	case *rsa.PublicKey:
		return verifyRSA(pub, attrs, digest, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return &errs.Message{Msg: "signature verification failed"}
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, digest, signature) {
			return &errs.Message{Msg: "signature verification failed"}
		}
		return nil
	case *pkcs11QuantumPublicKey:
		return verifyQuantum(pub, digest, signature)
	default:
		return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "unsupported key type for verification"}
	}
}

// verifyQuantum checks a post-quantum signature with C_VerifyInit and C_Verify
// against the public key object on the token.
//
// The token is the only thing that can answer: the private key never left it,
// the public half is an opaque object handle rather than exportable bytes for
// any type Go models, and CKM_ML_DSA is defined over the message, so digest
// carries the message itself.
//
// A signature the token rejects is reported as a verification failure, matching
// the classical branches, while a device or session fault keeps its CKR_ detail
// so an outage is not mistaken for a bad signature.
func verifyQuantum(pub *pkcs11QuantumPublicKey, digest, signature []byte) error {
	if pub.family == nil {
		return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "post-quantum public key has no algorithm family"}
	}
	if !pub.family.signs {
		return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("%s is a key encapsulation mechanism and produces no signature to verify", pub.algorithm)}
	}
	if pub.pool == nil {
		return &errs.Message{Msg: "pkcs11: session pool not initialized"}
	}

	return pub.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := pub.pool.Ctx().VerifyInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pub.family.operation, nil),
		}, pub.handle); err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("pkcs11: %s VerifyInit", pub.algorithm), Err: err}
		}

		if err := pub.pool.Ctx().Verify(session, digest, signature); err != nil {
			if isSignatureRejection(err) {
				return &errs.Message{Msg: "signature verification failed"}
			}
			return &errs.Wrapped{Msg: fmt.Sprintf("pkcs11: %s Verify", pub.algorithm), Err: err}
		}
		return nil
	})
}

// signatureRejections holds the CKR_ codes a token returns when C_Verify
// completes and the signature does not check out, as opposed to the codes that
// report the operation could not be carried out at all.
var signatureRejections = map[pkcs11.Error]bool{
	pkcs11.CKR_SIGNATURE_INVALID:   true,
	pkcs11.CKR_SIGNATURE_LEN_RANGE: true,
}

// isSignatureRejection reports whether a C_Verify error means the token
// checked the signature and found it wrong.
func isSignatureRejection(err error) bool {
	var ckr pkcs11.Error
	if !errors.As(err, &ckr) {
		return false
	}
	return signatureRejections[ckr]
}

// rsaScheme describes how one x509.SignatureAlgorithm verifies an RSA
// signature: the digest it is defined over, and the padding scheme.
type rsaScheme struct {
	hash   crypto.Hash
	verify func(pub *rsa.PublicKey, hash crypto.Hash, digest, signature []byte) error
}

// rsaSchemes maps an RSA signature algorithm to its digest and padding scheme.
//
// The two paddings are kept apart deliberately. Verifying a PSS signature as
// PKCS#1 v1.5 (or the reverse) does not merely fail: it answers a question the
// caller did not ask, so a signature could be accepted under a scheme the
// caller never agreed to. SHA-1 algorithms are absent because a SHA-1 RSA
// signature is not a result this backend will vouch for.
var rsaSchemes = map[x509.SignatureAlgorithm]rsaScheme{
	x509.SHA256WithRSA:    {hash: crypto.SHA256, verify: verifyRSAPKCS1v15},
	x509.SHA384WithRSA:    {hash: crypto.SHA384, verify: verifyRSAPKCS1v15},
	x509.SHA512WithRSA:    {hash: crypto.SHA512, verify: verifyRSAPKCS1v15},
	x509.SHA256WithRSAPSS: {hash: crypto.SHA256, verify: verifyRSAPSS},
	x509.SHA384WithRSAPSS: {hash: crypto.SHA384, verify: verifyRSAPSS},
	x509.SHA512WithRSAPSS: {hash: crypto.SHA512, verify: verifyRSAPSS},
}

// verifyRSA verifies an RSA signature over digest using the scheme named by
// attrs.SignatureAlgorithm.
//
// The algorithm has to be stated rather than inferred. attrs.Hash names the
// digest but says nothing about the padding, and PKCS#1 v1.5 and PSS are not
// interchangeable, so defaulting to either one would decide on the caller's
// behalf which scheme a signature is accepted under. A missing or unsupported
// algorithm is reported as backend.ErrInvalidAlgorithm naming the field.
func verifyRSA(pub *rsa.PublicKey, attrs *types.KeyAttributes, digest, signature []byte) error {
	if attrs.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: "RSA verification requires KeyAttributes.SignatureAlgorithm; PKCS#1 v1.5 and PSS cannot be distinguished from the digest alone"}
	}

	scheme, ok := rsaSchemes[attrs.SignatureAlgorithm]
	if !ok {
		return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported RSA signature algorithm: %s", attrs.SignatureAlgorithm)}
	}

	if attrs.Hash != crypto.Hash(0) && attrs.Hash != scheme.hash {
		return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("KeyAttributes.Hash is %s but %s is defined over %s", attrs.Hash, attrs.SignatureAlgorithm, scheme.hash)}
	}

	if len(digest) != scheme.hash.Size() {
		return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("%s expects a %d byte digest, got %d", attrs.SignatureAlgorithm, scheme.hash.Size(), len(digest))}
	}

	return scheme.verify(pub, scheme.hash, digest, signature)
}

// verifyRSAPKCS1v15 verifies an RFC 8017 RSASSA-PKCS1-v1_5 signature.
func verifyRSAPKCS1v15(pub *rsa.PublicKey, hash crypto.Hash, digest, signature []byte) error {
	if err := rsa.VerifyPKCS1v15(pub, hash, digest, signature); err != nil {
		return &errs.Message{Msg: "signature verification failed"}
	}
	return nil
}

// verifyRSAPSS verifies an RFC 8017 RSASSA-PSS signature.
//
// The salt length is taken from the signature (rsa.PSSSaltLengthAuto) because
// the signer's choice is recoverable from the encoding and is not part of the
// agreement between signer and verifier.
func verifyRSAPSS(pub *rsa.PublicKey, hash crypto.Hash, digest, signature []byte) error {
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash}
	if err := rsa.VerifyPSS(pub, hash, digest, signature, opts); err != nil {
		return &errs.Message{Msg: "signature verification failed"}
	}
	return nil
}

// Pool returns the session pool. Returns nil if not initialized.
func (b *Backend) Pool() *SessionPool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pool
}

// SetSessionPool allows an external manager to inject a pre-created session pool.
// This is the key integration point that eliminates the dual-init problem — the
// PKCS#11 module manager can create a pool and share it with the backend.
func (b *Backend) SetSessionPool(pool *SessionPool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pool = pool
	b.p11ctx = pool.Ctx()
	b.ownsP11ctx = false
	b.ownsP11Init = false
	b.probeQuantumMechanisms()
}

// findKey finds a key object by its resolved CKA_ID.
// Must be called with mutex held.
//
// The CKA_ID comes from resolveKeyID, the same routing Signer uses, so a PIV
// or post-quantum key is looked up under the identifier it was created with
// rather than under a CN-and-algorithm composite it does not carry.
func (b *Backend) findKey(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	signer, err := findKeyPairByID(b.pool, id)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to find key", Err: err}
	}
	if signer == nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

	return signer, nil
}

// signerFactory builds the wrapper that performs operations on one key pair,
// from the handles findKeyPairByID located on the token.
type signerFactory func(pool *SessionPool, pubHandle, privHandle pkcs11.ObjectHandle, id []byte) (crypto.Signer, error)

// signerFactories maps CKA_KEY_TYPE to the wrapper construction for that key
// type.
//
// Every key type keyTypeDecoders can enumerate must appear here. Signer, Sign,
// Verify and findKey all reach the token through this table, so a key type that
// is listable but missing here describes a key that can be generated and
// enumerated and then never used again.
var signerFactories = map[uint]signerFactory{
	pkcs11.CKK_RSA: newRSASigner,
	pkcs11.CKK_EC:  newECDSASigner,
	CKK_EC_EDWARDS: newEd25519Signer,
	CKK_ML_DSA:     quantumSignerFactory(quantumFamilyMLDSA),
	CKK_ML_KEM:     quantumSignerFactory(quantumFamilyMLKEM),
}

// newRSASigner builds the wrapper for an RSA key pair. The public key is read
// off the token so signatures can be verified without another lookup.
func newRSASigner(pool *SessionPool, pubHandle, privHandle pkcs11.ObjectHandle, id []byte) (crypto.Signer, error) {
	pub, err := exportRSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, err
	}
	return &pkcs11RSASigner{
		pool:          pool,
		privateHandle: privHandle,
		publicKey:     pub,
		label:         string(id),
	}, nil
}

// newECDSASigner builds the wrapper for an EC key pair.
func newECDSASigner(pool *SessionPool, pubHandle, privHandle pkcs11.ObjectHandle, id []byte) (crypto.Signer, error) {
	pub, err := exportECDSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, err
	}
	return &pkcs11ECDSASigner{
		pool:          pool,
		privateHandle: privHandle,
		publicKey:     pub,
		label:         string(id),
	}, nil
}

// newEd25519Signer builds the wrapper for an Edwards key pair. The public key
// is read off the token here, like newRSASigner and newECDSASigner do for
// their key types, so a construction failure is reported to the caller
// instead of being deferred to a later, error-swallowing Public() call.
func newEd25519Signer(pool *SessionPool, pubHandle, privHandle pkcs11.ObjectHandle, id []byte) (crypto.Signer, error) {
	pub, err := exportEd25519PublicKey(pool, pubHandle)
	if err != nil {
		return nil, err
	}
	return &pkcs11Ed25519Signer{
		pool:           pool,
		publicHandle:   pubHandle,
		privateHandle:  privHandle,
		label:          string(id),
		publicKeyBytes: pub,
	}, nil
}

// exportEd25519PublicKey reads CKA_EC_POINT off a PKCS#11 Ed25519 public key
// object and decodes it to the raw 32-byte Ed25519 public key.
func exportEd25519PublicKey(pool *SessionPool, pubHandle pkcs11.ObjectHandle) (ed25519.PublicKey, error) {
	var pub ed25519.PublicKey
	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		attrs, err := pool.Ctx().GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: get Ed25519 public key attributes", Err: err}
		}
		if len(attrs) == 0 || len(attrs[0].Value) == 0 {
			return &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "missing EC point"}
		}

		ecPoint := attrs[0].Value

		// CKA_EC_POINT is DER-encoded: an OCTET STRING wrapping the raw
		// 32-byte point, i.e. 0x04 0x20 <32 bytes>. Some tokens report the
		// bare point instead; both are accepted, anything else is not.
		switch {
		case len(ecPoint) == 34 && ecPoint[0] == 0x04 && ecPoint[1] == 0x20:
			pub = ed25519.PublicKey(append([]byte(nil), ecPoint[2:34]...))
		case len(ecPoint) == ed25519.PublicKeySize:
			pub = ed25519.PublicKey(append([]byte(nil), ecPoint...))
		default:
			return &errs.Detail{
				Err:    ErrInvalidKeyAttributes,
				Detail: fmt.Sprintf("CKA_EC_POINT has unexpected length %d for Ed25519", len(ecPoint)),
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// quantumSignerFactory builds the signerFactory for one post-quantum family,
// binding the family so the wrapper drives the token with the mechanism that
// belongs to the key type it was found under.
func quantumSignerFactory(family *quantumFamily) signerFactory {
	return func(pool *SessionPool, pubHandle, privHandle pkcs11.ObjectHandle, id []byte) (crypto.Signer, error) {
		return newQuantumSigner(family, pool, pubHandle, privHandle, id)
	}
}

// findKeyPairByID locates a key pair on the token by CKA_ID and returns the
// wrapper for its key type, dispatched through signerFactories.
// Returns nil, nil if no key is found.
func findKeyPairByID(pool *SessionPool, id []byte) (crypto.Signer, error) {
	var keyType uint
	var privHandle, pubHandle pkcs11.ObjectHandle
	var found bool

	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		// Find private key (any type)
		priv, err := pool.FindObjectHandle(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: find private key", Err: err}
		}
		if priv == 0 {
			return nil // not found
		}
		privHandle = priv

		// Get key type
		attrs, err := pool.Ctx().GetAttributeValue(session, privHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: GetAttributeValue for key type", Err: err}
		}
		if len(attrs) == 0 || len(attrs[0].Value) == 0 {
			return &errs.Message{Msg: "pkcs11: could not determine key type"}
		}
		keyType = ckULong(attrs[0].Value)

		// Find public key
		pub, err := pool.FindObjectHandle(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: find public key", Err: err}
		}
		pubHandle = pub
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	newSigner, ok := signerFactories[keyType]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("unknown key type 0x%04x", keyType)}
	}
	return newSigner(pool, pubHandle, privHandle, id)
}

// resolveKeyID determines the PKCS#11 CKA_ID for a key based on:
//  1. KeyAttributes.PIVSlot (explicit PIV slot from caller) - highest priority
//  2. Config.Slot for YubiKey PIV (existing behavior)
//  3. createQuantumKeyID for post-quantum keys (CN.quantum-algorithm format)
//  4. createKeyID for generic PKCS#11 tokens (CN.algorithm format)
//
// The post-quantum branch exists because generateQuantumKey writes a CKA_ID
// built from the parameter set, not from KeyAlgorithm, which is unset for an
// ML-DSA or ML-KEM key. Without it every operation that resolves a key by
// attributes would look for "CN." and miss the object entirely.
func (b *Backend) resolveKeyID(attrs *types.KeyAttributes) ([]byte, error) {
	if attrs.PIVSlot != "" {
		slot := pivcert.PIVSlot(attrs.PIVSlot)
		if !slot.IsValid() {
			return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: fmt.Sprintf("invalid PIV slot: %s", attrs.PIVSlot)}
		}
		ckaID, ok := pivpkcs11.PIVSlotToCKAID(slot)
		if !ok {
			return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: fmt.Sprintf("no CKA_ID mapping for slot %s", attrs.PIVSlot)}
		}
		return []byte{ckaID}, nil
	}
	if b.config.IsYubiKeyPIV() && b.config.Slot != nil {
		return createSlotID(uint(*b.config.Slot)), nil
	}
	if attrs.QuantumAttributes != nil {
		return []byte(createQuantumKeyID(attrs)), nil
	}
	return []byte(createKeyID(attrs)), nil
}

// createKeyID generates a PKCS#11 object identifier for a key.
// Format: {CN}.{algorithm}
func createKeyID(attrs *types.KeyAttributes) string {
	if attrs.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return fmt.Sprintf("%s.", attrs.CN)
	}
	return fmt.Sprintf("%s.%s", attrs.CN, strings.ToLower(attrs.KeyAlgorithm.String()))
}

// keyIDToCN recovers the common name from a PKCS#11 object label that
// createKeyID produced. It is the exact inverse of createKeyID, so attributes
// reported by ListKeys resolve back to the CKA_ID they were read from. A
// label that was not written by createKeyID is returned unchanged.
func keyIDToCN(label string, algorithm x509.PublicKeyAlgorithm) string {
	suffix := "."
	if algorithm != x509.UnknownPublicKeyAlgorithm {
		suffix += strings.ToLower(algorithm.String())
	}
	return strings.TrimSuffix(label, suffix)
}

// createQuantumKeyID generates a PKCS#11 object identifier for a quantum key.
// Format: {CN}.{quantum-algorithm}
//
// It exists separately from createKeyID because a post-quantum key carries no
// x509.PublicKeyAlgorithm: the parameter set (ML-DSA-65, ML-KEM-768, ...) lives
// in QuantumAttributes, and it is the parameter set, not the bare key type,
// that has to be recoverable from the object on the token.
func createQuantumKeyID(attrs *types.KeyAttributes) string {
	if attrs.QuantumAttributes == nil {
		return fmt.Sprintf("%s.", attrs.CN)
	}
	return fmt.Sprintf("%s.%s", attrs.CN, strings.ToLower(string(attrs.QuantumAttributes.Algorithm)))
}

// quantumKeyIDs maps the lowercased suffix createQuantumKeyID writes back to
// the canonical parameter set. Reversing the algorithm through a table rather
// than through strings.ToUpper keeps an arbitrary label from being reported as
// a post-quantum algorithm that the stack does not implement.
var quantumKeyIDs = map[string]types.QuantumAlgorithm{
	strings.ToLower(string(types.QuantumAlgorithmMLDSA44)):   types.QuantumAlgorithmMLDSA44,
	strings.ToLower(string(types.QuantumAlgorithmMLDSA65)):   types.QuantumAlgorithmMLDSA65,
	strings.ToLower(string(types.QuantumAlgorithmMLDSA87)):   types.QuantumAlgorithmMLDSA87,
	strings.ToLower(string(types.QuantumAlgorithmMLKEM512)):  types.QuantumAlgorithmMLKEM512,
	strings.ToLower(string(types.QuantumAlgorithmMLKEM768)):  types.QuantumAlgorithmMLKEM768,
	strings.ToLower(string(types.QuantumAlgorithmMLKEM1024)): types.QuantumAlgorithmMLKEM1024,
}

// quantumKeyIDToCN splits a label that createQuantumKeyID produced back into
// its common name and parameter set. It reports false for a label that does not
// end in a known post-quantum algorithm, so a caller can fall back to treating
// the label as an opaque name instead of inventing an algorithm for it.
func quantumKeyIDToCN(label string) (string, types.QuantumAlgorithm, bool) {
	dot := strings.LastIndex(label, ".")
	if dot < 0 {
		return "", "", false
	}
	algorithm, ok := quantumKeyIDs[label[dot+1:]]
	if !ok {
		return "", "", false
	}
	return label[:dot], algorithm, true
}

// createSlotID generates a PKCS#11 CKA_ID from a YubiKey PIV slot number,
// for example slot 0x9a (Authentication) -> CKA_ID 0x01.
//
// The translation is delegated to the canonical PIV slot table in
// pkg/pivcert/pkcs11 so that a key and the certificate issued for it always
// land on the same CKA_ID. Slot numbers that table does not define keep their
// raw byte value.
func createSlotID(slot uint) []byte {
	if ckaID, ok := pivpkcs11.PIVSlotToCKAID(pivcert.PIVSlot(fmt.Sprintf("%02x", slot))); ok {
		return []byte{ckaID}
	}
	// Not a PIV slot: use the raw value.
	return []byte{byte(slot)}
}

// pkcs11Ed25519Signer implements crypto.Signer for Ed25519 keys stored in PKCS#11.
// It wraps the PKCS#11 key handles and performs signing operations using the HSM.
//
// publicKeyBytes is populated once, at construction, by exportEd25519PublicKey
// (see newEd25519Signer). Unlike the RSA and ECDSA wrappers, which have always
// read their public key eagerly, this one used to defer the HSM read to the
// first call to Public() and swallow any error, so a read failure surfaced as
// a silent nil rather than a construction error. Reading it up front, like
// the other key types, means Public() can be a total function.
type pkcs11Ed25519Signer struct {
	pool           *SessionPool
	publicHandle   pkcs11.ObjectHandle
	privateHandle  pkcs11.ObjectHandle
	label          string
	publicKeyBytes ed25519.PublicKey
}

// Public returns the public key corresponding to the opaque private key. It
// never touches the HSM: the key was read and validated once, when this
// signer was constructed, so this is a pure accessor.
func (s *pkcs11Ed25519Signer) Public() crypto.PublicKey {
	return s.publicKeyBytes
}

// Sign signs the given digest using Ed25519 with the PKCS#11 private key.
// For Ed25519, the digest parameter is actually the full message, not a hash.
// Ed25519 performs its own hashing internally.
func (s *pkcs11Ed25519Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if s.pool == nil {
		return nil, &errs.Message{Msg: "pkcs11: session pool not initialized"}
	}

	var signature []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().SignInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(CKM_EDDSA, nil),
		}, s.privateHandle); err != nil {
			return &errs.Wrapped{Msg: "pkcs11: Ed25519 SignInit", Err: err}
		}

		var err error
		signature, err = s.pool.Ctx().Sign(session, digest)
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: Ed25519 Sign", Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// pkcs11MLDSASigner implements crypto.Signer for ML-DSA and ML-KEM keys stored in PKCS#11.
// It wraps the PKCS#11 key handles and delegates all cryptographic operations to the HSM.
// The private key material never leaves the hardware module.
type pkcs11MLDSASigner struct {
	pool          *SessionPool
	publicHandle  pkcs11.ObjectHandle
	privateHandle pkcs11.ObjectHandle
	label         string
	algorithm     string         // e.g., "ML-DSA-44", "ML-DSA-65", "ML-KEM-768"
	family        *quantumFamily // the family whose mechanisms drive the token
	publicKey     crypto.PublicKey
	mu            sync.RWMutex
}

// Public returns the public key corresponding to the opaque private key.
// For ML-DSA/ML-KEM, we return a pkcs11QuantumPublicKey wrapper since Go's
// standard library does not have native types for post-quantum keys.
//
// The wrapper carries the session pool as well as the handle, because a
// post-quantum signature can only be checked by the token: there is no ML-DSA
// type in Go's standard library to verify it against in software.
func (s *pkcs11MLDSASigner) Public() crypto.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.publicKey != nil {
		return s.publicKey
	}

	// Wrap the public handle in a quantum public key type
	s.publicKey = &pkcs11QuantumPublicKey{
		pool:      s.pool,
		handle:    s.publicHandle,
		algorithm: s.algorithm,
		family:    s.family,
	}
	return s.publicKey
}

// Sign signs the given digest using ML-DSA with the PKCS#11 private key.
// The signing operation is performed entirely within the HSM hardware.
//
// An ML-KEM key is refused here rather than at the token: FIPS 203 defines a
// key-encapsulation mechanism, C_SignInit is not defined over CKM_ML_KEM, and
// a caller is better served by being told that than by CKR_MECHANISM_INVALID.
func (s *pkcs11MLDSASigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.family == nil {
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: "post-quantum signer has no algorithm family"}
	}
	if !s.family.signs {
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("%s is a key encapsulation mechanism and cannot sign", s.algorithm)}
	}
	if s.pool == nil {
		return nil, &errs.Message{Msg: "pkcs11: session pool not initialized"}
	}

	var signature []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().SignInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(s.family.operation, nil),
		}, s.privateHandle); err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("pkcs11: %s SignInit", s.algorithm), Err: err}
		}

		var err error
		signature, err = s.pool.Ctx().Sign(session, digest)
		if err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("pkcs11: %s Sign", s.algorithm), Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// pkcs11QuantumPublicKey wraps a PKCS#11 object handle for a quantum public key.
// Since Go's crypto library has no native ML-DSA/ML-KEM key types, this wrapper
// provides a type-safe representation that carries the algorithm metadata and
// the session pool needed to verify against the key on the token.
type pkcs11QuantumPublicKey struct {
	pool      *SessionPool
	handle    pkcs11.ObjectHandle
	algorithm string         // e.g., "ML-DSA-44", "ML-KEM-768"
	family    *quantumFamily // the family whose mechanisms drive the token
}

// Algorithm returns the quantum algorithm name for this public key.
func (k *pkcs11QuantumPublicKey) Algorithm() string {
	return k.algorithm
}

// Handle returns the PKCS#11 object handle for this public key.
func (k *pkcs11QuantumPublicKey) Handle() pkcs11.ObjectHandle {
	return k.handle
}

// Ensure interface is implemented at compile time
var _ types.KeyProvider = (*Backend)(nil)
var _ crypto.Signer = (*pkcs11Ed25519Signer)(nil)
var _ crypto.Signer = (*pkcs11MLDSASigner)(nil)
