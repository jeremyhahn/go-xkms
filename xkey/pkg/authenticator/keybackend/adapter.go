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

package keybackend

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// BackendAdapter wraps a go-xkms types.KeyProvider to implement FIDO2KeyBackend.
// It translates between FIDO2 credential IDs / COSE algorithms and go-xkms
// KeyAttributes, and handles COSE public key encoding. This eliminates the need
// for per-backend FIDO2 implementations — any go-xkms KeyProvider that supports
// EC key generation and signing works automatically.
type BackendAdapter struct {
	provider    types.KeyProvider
	backendType types.BackendType
	logger      *slog.Logger
	slotModel   pivcert.SlotModel // nil for non-slot backends (software, generic PKCS#11)
	closed      atomic.Bool
	slotCache   sync.Map // credentialID (hex) -> PIVSlot string
}

// NewBackendAdapter creates a FIDO2KeyBackend that delegates all cryptographic
// operations to a go-xkms KeyProvider. The backendType identifies this adapter
// in the CompositeBackend routing and is stored in credential BackendID fields.
func NewBackendAdapter(provider types.KeyProvider, backendType types.BackendType) *BackendAdapter {
	return &BackendAdapter{
		provider:    provider,
		backendType: backendType,
		logger:      slog.Default(),
	}
}

// SetLogger sets the logger for the adapter.
func (a *BackendAdapter) SetLogger(logger *slog.Logger) {
	a.logger = logger
}

// SetSlotModel attaches a PIV slot model for slot-constrained backends.
// When set, GenerateCredentialKey auto-allocates the next available slot.
func (a *BackendAdapter) SetSlotModel(sm pivcert.SlotModel) {
	a.slotModel = sm
}

// adapterKeyHandle implements KeyHandle for the BackendAdapter.
type adapterKeyHandle struct {
	credentialID []byte
	algorithm    int
	backendType  types.BackendType
}

func (h *adapterKeyHandle) CredentialID() []byte        { return h.credentialID }
func (h *adapterKeyHandle) Algorithm() int               { return h.algorithm }
func (h *adapterKeyHandle) BackendID() types.BackendType { return h.backendType }

// Type returns the backend type.
func (a *BackendAdapter) Type() types.BackendType {
	return a.backendType
}

// Capabilities maps the go-xkms provider capabilities to FIDO2KeyCapabilities.
func (a *BackendAdapter) Capabilities() FIDO2KeyCapabilities {
	caps := a.provider.Capabilities()

	// Determine supported COSE algorithms based on backend type.
	// TPM2 is limited to P-256 (ES256) for FIDO2.
	// PKCS#11 and software backends support all standard EC curves.
	algorithms := algorithmsForBackend(a.backendType)

	return FIDO2KeyCapabilities{
		SupportedAlgorithms: algorithms,
		SupportsExport:      caps.Export,
		SupportsImport:      caps.Import,
		SupportsAttestation: false,
		HardwareBacked:      caps.HardwareBacked,
	}
}

// algorithmsForBackend returns the COSE algorithms supported by a backend type.
// TPM2 only supports P-256 for FIDO2 credential keys. PKCS#11 and software
// backends support the full set of EC curves.
func algorithmsForBackend(bt types.BackendType) []int {
	if bt == types.BackendTypeTPM2 || strings.HasPrefix(string(bt), "tpm2") {
		return []int{COSEAlgES256}
	}
	return []int{COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgEdDSA}
}

// GenerateCredentialKey generates a new key pair via the KeyProvider and returns
// the COSE-encoded public key.
func (a *BackendAdapter) GenerateCredentialKey(algorithm int, credentialID []byte) (KeyHandle, []byte, error) {
	if a.closed.Load() {
		return nil, nil, ErrBackendClosed
	}
	if len(credentialID) == 0 {
		return nil, nil, ErrInvalidCredentialID
	}

	attrs, err := a.generateCredentialAttrs(credentialID, algorithm)
	if err != nil {
		return nil, nil, err
	}

	privKey, err := a.provider.GenerateKey(attrs)
	if err != nil {
		a.logger.Error("FIDO2 adapter: provider.GenerateKey failed",
			"backend", a.backendType,
			"store_type", attrs.StoreType,
			"cn", attrs.CN,
			"algorithm", algorithm,
			"error", err)
		return nil, nil, fmt.Errorf("%w: %v", ErrKeyGenerationFailed, err)
	}

	// Refresh slot model occupancy after successful key generation.
	if a.slotModel != nil {
		_ = a.slotModel.Refresh()
	}

	// Extract public key from the generated private key.
	var pubKey crypto.PublicKey
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		pubKey = k.Public()
	default:
		a.logger.Error("FIDO2 adapter: unsupported key type from provider",
			"backend", a.backendType,
			"type", fmt.Sprintf("%T", privKey))
		return nil, nil, fmt.Errorf("%w: unsupported key type %T", ErrKeyGenerationFailed, privKey)
	}

	publicKeyCOSE, err := EncodeCOSEPublicKey(pubKey, algorithm)
	if err != nil {
		a.logger.Error("FIDO2 adapter: COSE encoding failed",
			"backend", a.backendType,
			"pubkey_type", fmt.Sprintf("%T", pubKey),
			"algorithm", algorithm,
			"error", err)
		return nil, nil, err
	}

	handle := &adapterKeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
		backendType:  a.backendType,
	}

	return handle, publicKeyCOSE, nil
}

// Sign creates a signature using the KeyProvider's Signer.
func (a *BackendAdapter) Sign(handle KeyHandle, algorithm int, data []byte) ([]byte, error) {
	if a.closed.Load() {
		return nil, ErrBackendClosed
	}
	if handle == nil {
		return nil, ErrInvalidKeyHandle
	}

	attrs, err := a.lookupCredentialAttrs(handle.CredentialID(), algorithm)
	if err != nil {
		return nil, err
	}

	signer, err := a.provider.Signer(attrs)
	if err != nil {
		a.logger.Error("FIDO2 adapter: provider.Signer failed",
			"backend", a.backendType,
			"error", err)
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	// Sign the data. For ECDSA, Go's crypto.Signer hashes internally
	// when given a hash option. For FIDO2, the authenticator data + client
	// data hash is the raw data to be signed.
	var sig []byte
	switch algorithm {
	case COSEAlgES256:
		sig, err = signWithHash(signer, data, crypto.SHA256)
	case COSEAlgES384:
		sig, err = signWithHash(signer, data, crypto.SHA384)
	case COSEAlgES512:
		sig, err = signWithHash(signer, data, crypto.SHA512)
	case COSEAlgEdDSA:
		// Ed25519 hashes internally — pass data directly with zero hash.
		sig, err = signer.Sign(nil, data, crypto.Hash(0))
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	if err != nil {
		return nil, ErrSigningFailed
	}

	// Normalize ECDSA signatures to low-S form per WebAuthn requirements.
	if algorithm != COSEAlgEdDSA {
		curve := curveForAlgorithm(algorithm)
		if curve != nil {
			sig, err = NormalizeLowS(sig, curve)
			if err != nil {
				return nil, ErrSigningFailed
			}
		}
	}

	return sig, nil
}

// LoadKey verifies a key exists in the provider by attempting to get a Signer.
func (a *BackendAdapter) LoadKey(credentialID []byte, algorithm int) (KeyHandle, error) {
	if a.closed.Load() {
		return nil, ErrBackendClosed
	}
	if len(credentialID) == 0 {
		return nil, ErrInvalidCredentialID
	}

	attrs, err := a.lookupCredentialAttrs(credentialID, algorithm)
	if err != nil {
		return nil, err
	}

	// Verify the key exists by attempting to get a Signer.
	if _, err := a.provider.Signer(attrs); err != nil {
		return nil, ErrKeyNotFound
	}

	return &adapterKeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
		backendType:  a.backendType,
	}, nil
}

// DeleteKey removes a key from the provider.
func (a *BackendAdapter) DeleteKey(handle KeyHandle) error {
	if a.closed.Load() {
		return ErrBackendClosed
	}
	if handle == nil {
		return ErrInvalidKeyHandle
	}

	attrs, err := a.lookupCredentialAttrs(handle.CredentialID(), handle.Algorithm())
	if err != nil {
		return err
	}

	return a.provider.DeleteKey(attrs)
}

// ExportPrivateKey exports the private key in PKCS#8 format.
// Only supported for software backends where keys are extractable.
func (a *BackendAdapter) ExportPrivateKey(handle KeyHandle) ([]byte, error) {
	if a.closed.Load() {
		return nil, ErrBackendClosed
	}
	if handle == nil {
		return nil, ErrInvalidKeyHandle
	}

	attrs, err := a.lookupCredentialAttrs(handle.CredentialID(), handle.Algorithm())
	if err != nil {
		return nil, err
	}

	privKey, err := a.provider.GetKey(attrs)
	if err != nil {
		return nil, ErrKeyNotFound
	}

	// MarshalPKCS8PrivateKey succeeds for raw key material (software backends)
	// and fails for hardware-bound signers (TPM2, PKCS#11) where the private
	// key never leaves the device. This makes exportability a per-key property
	// rather than a per-backend blanket decision.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, ErrExportNotSupported
	}
	return pkcs8, nil
}

// ImportPrivateKey is not supported via the adapter. FIDO2 credential import
// is handled through the credential storage layer, not the key backend.
func (a *BackendAdapter) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (KeyHandle, error) {
	return nil, ErrImportNotSupported
}

// Close marks the adapter as closed.
func (a *BackendAdapter) Close() error {
	a.closed.Store(true)
	return nil
}

// lookupCredentialAttrs builds go-xkms KeyAttributes from a FIDO2 credential ID
// and COSE algorithm identifier. The CN is derived deterministically from the
// credential ID so that LoadKey, Sign, DeleteKey, and ExportPrivateKey can find
// previously generated keys. No slot allocation is performed.
func (a *BackendAdapter) lookupCredentialAttrs(credentialID []byte, algorithm int) (*types.KeyAttributes, error) {
	attrs := &types.KeyAttributes{
		CN:        "fido2-" + hex.EncodeToString(credentialID),
		KeyType:   types.KeyTypeSigning,
		StoreType: storeTypeForBackend(a.backendType),
	}

	switch algorithm {
	case COSEAlgES256:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.Hash = crypto.SHA256
		attrs.SignatureAlgorithm = x509.ECDSAWithSHA256
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P256()}
	case COSEAlgES384:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.Hash = crypto.SHA384
		attrs.SignatureAlgorithm = x509.ECDSAWithSHA384
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P384()}
	case COSEAlgES512:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.Hash = crypto.SHA512
		attrs.SignatureAlgorithm = x509.ECDSAWithSHA512
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P521()}
	case COSEAlgEdDSA:
		attrs.KeyAlgorithm = x509.Ed25519
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	// Restore PIV slot from cache if this credential was auto-allocated.
	if v, ok := a.slotCache.Load(hex.EncodeToString(credentialID)); ok {
		attrs.PIVSlot = v.(string)
	}

	return attrs, nil
}

// generateCredentialAttrs builds KeyAttributes for new credential key generation.
// If a SlotModel is present, it auto-allocates the next available PIV slot.
func (a *BackendAdapter) generateCredentialAttrs(credentialID []byte, algorithm int) (*types.KeyAttributes, error) {
	attrs, err := a.lookupCredentialAttrs(credentialID, algorithm)
	if err != nil {
		return nil, err
	}

	if a.slotModel != nil {
		slot, slotErr := a.slotModel.NextAvailable()
		if slotErr != nil {
			a.logger.Error("FIDO2 adapter: no available PIV slot",
				"backend", a.backendType,
				"error", slotErr)
			return nil, fmt.Errorf("%w: %v", ErrKeyGenerationFailed, slotErr)
		}
		attrs.PIVSlot = string(slot)
		a.slotCache.Store(hex.EncodeToString(credentialID), string(slot))
		a.logger.Info("FIDO2 adapter: auto-allocated PIV slot",
			"backend", a.backendType,
			"slot", slot)
	}

	return attrs, nil
}

// signWithHash hashes data and signs the digest.
func signWithHash(signer crypto.Signer, data []byte, hash crypto.Hash) ([]byte, error) {
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)
	return signer.Sign(nil, digest, hash)
}

// curveForAlgorithm returns the elliptic curve for a COSE ECDSA algorithm.
func curveForAlgorithm(algorithm int) elliptic.Curve {
	switch algorithm {
	case COSEAlgES256:
		return elliptic.P256()
	case COSEAlgES384:
		return elliptic.P384()
	case COSEAlgES512:
		return elliptic.P521()
	default:
		return nil
	}
}

// storeTypeForBackend maps a BackendType to the corresponding StoreType.
// Handles both exact matches (e.g., "pkcs11") and module-ID-style types
// (e.g., "pkcs11-libykcs11-slot-0") by checking prefixes.
func storeTypeForBackend(bt types.BackendType) types.StoreType {
	switch bt {
	case types.BackendTypeSoftware:
		return types.StoreSoftware
	case types.BackendTypeTPM2:
		return types.StoreTPM2
	case types.BackendTypePKCS11:
		return types.StorePKCS11
	case types.BackendTypeAWSKMS:
		return types.StoreAWSKMS
	case types.BackendTypeGCPKMS:
		return types.StoreGCPKMS
	case types.BackendTypeAzureKV:
		return types.StoreAzureKV
	case types.BackendTypeVault:
		return types.StoreVault
	case types.BackendTypePhone:
		return types.StorePhone
	default:
		// Handle module-ID-style backend types like "pkcs11-libykcs11"
		// by matching the prefix to known backend types.
		s := string(bt)
		for _, mapping := range []struct {
			prefix    string
			storeType types.StoreType
		}{
			{"pkcs11", types.StorePKCS11},
			{"tpm2", types.StoreTPM2},
			{"awskms", types.StoreAWSKMS},
			{"gcpkms", types.StoreGCPKMS},
			{"azurekv", types.StoreAzureKV},
			{"vault", types.StoreVault},
		} {
			if strings.HasPrefix(s, mapping.prefix) {
				return mapping.storeType
			}
		}
		return types.StoreType(bt)
	}
}

// Compile-time interface check.
var _ FIDO2KeyBackend = (*BackendAdapter)(nil)
