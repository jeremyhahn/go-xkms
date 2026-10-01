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

package xkms

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// pivAlgorithmAttrs maps PIV algorithm strings to KeyAttributes builders.
// Each entry returns a partially-filled KeyAttributes with the correct
// algorithm, key type, and algorithm-specific parameters.
type pivAlgorithmBuilder func(cn string) *types.KeyAttributes

// pivAlgorithmDispatch provides O(1) map-based dispatch for algorithm mapping.
var pivAlgorithmDispatch = map[string]pivAlgorithmBuilder{
	"rsa2048": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeSigning,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
	},
	"rsa4096": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeSigning,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 4096,
			},
		}
	},
	"ecdsap256": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}
	},
	"ecdsap384": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P384(),
			},
		}
	},
	"ed25519": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.Ed25519,
			KeyType:      types.KeyTypeSigning,
		}
	},
}

// backendPIVKeyGenerator generates PIV keys using an xkms Backend.
// It delegates key generation and signer retrieval to the configured backend,
// allowing TPM2, PKCS11, and other backends to handle actual cryptographic operations.
type backendPIVKeyGenerator struct {
	backend   Backend
	storeType types.StoreType
}

// newBackendPIVKeyGenerator creates a new backend-backed PIVKeyGenerator.
// The storeType identifies the backend storage type (e.g., "software", "tpm2", "pkcs11")
// and is set on generated KeyAttributes to satisfy validation requirements.
func newBackendPIVKeyGenerator(backend Backend, storeType types.StoreType) *backendPIVKeyGenerator {
	return &backendPIVKeyGenerator{backend: backend, storeType: storeType}
}

// GeneratePIVKey generates a new key for the given PIV slot using the configured backend.
// An empty algorithm defaults to "ecdsap256".
func (g *backendPIVKeyGenerator) GeneratePIVKey(slot pivcert.PIVSlot, algorithm string, cn string) (crypto.Signer, error) {
	if algorithm == "" {
		algorithm = "ecdsap256"
	}

	builder, ok := pivAlgorithmDispatch[algorithm]
	if !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	attrs := builder(cn)
	attrs.StoreType = g.storeType
	attrs.PIVSlot = string(slot)
	// Provenance is a consequence of this code path, not an input: this is the
	// generate path, so the key is generated. See types.KeyOrigin.
	attrs.KeyOrigin = types.KeyOriginGenerated
	// AttestLevel is KeyOrigin's sibling: it records where the key lives
	// (hardware or software) rather than how it arrived. g implements
	// PIVAttestLevelReporter itself, so this always resolves to the backend's
	// own classification.
	attrs.AttestLevel = pivAttestLevel(g, slot, cn)

	// If the backend implements PIVParentProvider, set the parent key attributes.
	// This is used by TPM2 to set PlatformSRK as the parent for PIV keys.
	if provider, ok := g.backend.(PIVParentProvider); ok {
		parentAttrs, err := provider.PIVParentAttributes()
		if err != nil {
			return nil, err
		}
		if parentAttrs != nil {
			attrs.Parent = parentAttrs
		}
	}

	// context.Background() is correct here: GeneratePIVKey implements the
	// PIVKeyGenerator interface, which carries no request context.
	ctx := context.Background()

	// Generating into a slot re-keys it, as on a PIV token: the slot's
	// previous key is replaced, not left to block the new one (a backend
	// that persists keys refuses a second key under the same name) or
	// orphaned beside it.
	if err := g.deleteSlotKeys(ctx, cn); err != nil {
		return nil, err
	}

	// Generate the key using the appropriate backend method
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if _, err := g.backend.GenerateRSA(ctx, attrs); err != nil {
			return nil, err
		}
	case x509.ECDSA:
		if _, err := g.backend.GenerateECDSA(ctx, attrs); err != nil {
			return nil, err
		}
	case x509.Ed25519:
		if _, err := g.backend.GenerateEd25519(ctx, attrs); err != nil {
			return nil, err
		}
	default:
		return nil, ErrPIVInvalidAlgorithm
	}

	// Retrieve the signer for the generated key
	return g.backend.Signer(ctx, attrs)
}

// deleteSlotKeys removes the keys a slot's CN names from the backend. A
// backend whose ListKeys does not enumerate slot keys (hardware tokens
// resolving by CKA_ID) lists none here, and its own generate replaces the
// slot's key.
func (g *backendPIVKeyGenerator) deleteSlotKeys(ctx context.Context, cn string) error {
	stored, err := g.backend.ListKeys(ctx)
	if err != nil {
		return &PIVRekeyError{CN: cn, Err: err}
	}
	for _, ka := range stored {
		if ka == nil || ka.CN != cn {
			continue
		}
		if err := g.backend.DeleteKey(ctx, ka); err != nil {
			return &PIVRekeyError{CN: cn, Err: err}
		}
	}
	return nil
}

// GetPIVSigner returns a signer for an existing key in the given PIV slot.
// PIVSlot is populated so slot-constrained backends (e.g., YubiKey PKCS#11)
// can locate the key by CKA_ID instead of relying on a CN convention that may
// not match the certificate subject users choose when generating the key.
func (g *backendPIVKeyGenerator) GetPIVSigner(slot pivcert.PIVSlot, cn string) (crypto.Signer, error) {
	// context.Background() is correct here: GetPIVSigner implements the
	// PIVKeyGenerator interface, which carries no request context.
	ctx := context.Background()

	// Resolve the stored key's full attributes by CN so the backend's
	// Signer receives the algorithm, store type, and key type it validates
	// against — a CN+slot shell fails attribute validation on backends
	// that persist keys (e.g. software/pkcs8).
	if stored, err := g.backend.ListKeys(ctx); err == nil {
		for _, ka := range stored {
			if ka != nil && ka.CN == cn {
				return g.backend.Signer(ctx, ka)
			}
		}
	}

	// Fall back to the CN+slot shell for backends whose ListKeys does not
	// enumerate slot keys (e.g. hardware tokens resolving by CKA_ID).
	attrs := &types.KeyAttributes{
		CN:        cn,
		PIVSlot:   string(slot),
		StoreType: g.storeType,
		KeyType:   types.KeyTypeSigning,
	}
	return g.backend.Signer(ctx, attrs)
}

// Verify interface compliance at compile time.
var _ PIVKeyGenerator = (*backendPIVKeyGenerator)(nil)

// ImportPIVKey installs an externally held private key in the slot by routing
// it through the backend's own import ceremony.
//
// The key material is not handed to the backend in the clear. xkms has exactly
// one import path — GetImportParameters, WrapKey, ImportKey — and this reuses
// it rather than adding a second, plaintext one: the key is marshalled to
// PKCS#8, wrapped to a wrapping key the backend issues for this single import
// token, and unwrapped inside the backend. The hybrid RSA+AES algorithm is
// chosen because a PKCS#8-encoded RSA-4096 key exceeds what plain RSA-OAEP can
// carry.
//
// A backend that does not implement backend.ImportBackend, or that refuses
// the operation, produces ErrPIVImportNotSupported so the refusal is
// reportable rather than mistaken for success.
func (g *backendPIVKeyGenerator) ImportPIVKey(ctx context.Context, slot pivcert.PIVSlot, algorithm string, cn string, key crypto.PrivateKey) (crypto.Signer, error) {
	builder, ok := pivAlgorithmDispatch[algorithm]
	if !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	// The import ceremony is resolved through importBackendFor, the same
	// capability lookup xkms.ImportKey makes (service.go), so PIV import and
	// generic key import reach a backend the one way rather than two — and a
	// tenant-scoped backend keeps its scoping rather than being unwrapped.
	// Only the import half is needed: PIV key installation never exports, so
	// a backend that can import but not export (AWS KMS's shape) must not be
	// blocked here by an unrelated export limitation.
	importer, ok := importBackendFor(g.backend)
	if !ok {
		return nil, ErrPIVImportNotSupported
	}

	attrs := builder(cn)
	attrs.StoreType = g.storeType
	attrs.PIVSlot = string(slot)
	// This is the import path, so the key is imported. The attributes are
	// built here from the algorithm and the slot rather than taken from a
	// caller, which is what makes the value unforgeable at this seam.
	attrs.KeyOrigin = types.KeyOriginImported
	// An imported key is not exempt from carrying an attestation level: it
	// answers a different question than KeyOrigin (where the key lives, not
	// how it arrived), and hardware + imported is the combination #207
	// singled out as the one that must stay distinguishable.
	attrs.AttestLevel = pivAttestLevel(g, slot, cn)

	if provider, ok := g.backend.(PIVParentProvider); ok {
		parentAttrs, err := provider.PIVParentAttributes()
		if err != nil {
			return nil, err
		}
		if parentAttrs != nil {
			attrs.Parent = parentAttrs
		}
	}

	// The PKCS#8 encoding is plaintext key material on the heap. Wipe it on
	// every exit path, success as much as failure, so its residency is
	// bounded by this call rather than by the garbage collector.
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrPIVKeyMaterialInvalid
	}
	defer secure.Wipe(der)

	params, err := importer.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		return nil, errors.Join(ErrPIVImportNotSupported, err)
	}

	wrapped, err := importer.WrapKey(ctx, der, params)
	if err != nil {
		return nil, errors.Join(ErrPIVImportNotSupported, err)
	}

	if err := importer.ImportKey(ctx, attrs, wrapped); err != nil {
		return nil, errors.Join(ErrPIVImportNotSupported, err)
	}

	// Confirm the backend actually recorded the provenance, by reading it back
	// the same way an attestation later will.
	//
	// This is what makes "an imported key is never unattributable" structural
	// rather than documentary. A backend that does not persist the origin — or
	// a write path that forgets to stamp it — fails HERE, at import, where an
	// operator is present and the key can be rolled back. The alternative is
	// discovering it at attestation time, where the only remaining options are
	// to refuse a key that may be perfectly legitimate or to attest one that
	// may not be.
	//
	// It also means a slot key whose origin reads back unknown provably did
	// not arrive by import, which is what lets attestation treat unknown as
	// safe instead of refusing every backend that has no provenance plumbing
	// (see refuseUnattestableKey).
	recorded, found, originErr := g.PIVKeyOrigin(slot, cn)
	if originErr != nil {
		return nil, errors.Join(ErrPIVImportProvenanceNotRecorded, originErr)
	}
	if !found || recorded != types.KeyOriginImported {
		// Roll the key back: a key whose provenance cannot be established must
		// not be left sitting in a slot looking like a generated one.
		if delErr := g.backend.DeleteKey(ctx, attrs); delErr != nil {
			return nil, errors.Join(ErrPIVImportProvenanceNotRecorded, delErr)
		}
		return nil, ErrPIVImportProvenanceNotRecorded
	}

	return g.backend.Signer(ctx, attrs)
}

// Verify import capability compliance at compile time.
var _ PIVKeyImporter = (*backendPIVKeyGenerator)(nil)

// PIVKeyOrigin reports how the slot's key arrived, by reading the origin the
// backend persisted on the key's own record.
//
// The record is the authority rather than anything the caller holds: the
// generate and import paths stamp it from the code path that ran, so a value
// read back here was written by the system. A key the backend does not
// enumerate reports KeyOriginUnknown with a nil error — the caller's question
// is whether the key was imported, and an absent key is not a yes.
func (g *backendPIVKeyGenerator) PIVKeyOrigin(_ pivcert.PIVSlot, cn string) (types.KeyOrigin, bool, error) {
	ctx := context.Background()

	stored, err := g.backend.ListKeys(ctx)
	if err != nil {
		return types.KeyOriginUnknown, false, err
	}
	for _, ka := range stored {
		if ka != nil && ka.CN == cn {
			// The origin the backend read back is authoritative: it is a
			// plain read of the persisted record (see
			// pkg/keyprovider/pkcs8.resolveKeyOrigin), with no inference
			// substituting a different value.
			return ka.KeyOrigin, true, nil
		}
	}
	return types.KeyOriginUnknown, false, nil
}

// Verify origin-reporting compliance at compile time.
var _ PIVKeyOriginReporter = (*backendPIVKeyGenerator)(nil)

// AttestLevel classifies the key this generator backs, from the underlying
// backend's own hardware-backed capability flag — the same signal the
// backend catalog and UI backend sorting already use to describe a
// backend's trust class (types.Capabilities.HardwareBacked), so PIV does
// not invent a second one. The answer does not vary by slot or CN: a
// backend's hardware backing is a property of the backend, not of any one
// key it holds.
func (g *backendPIVKeyGenerator) AttestLevel(_ pivcert.PIVSlot, _ string) (types.AttestLevel, error) {
	if g.backend.KeyProvider().Capabilities().IsHardwareBacked() {
		return types.AttestLevelHardware, nil
	}
	return types.AttestLevelSoftware, nil
}

// Verify attest-level-reporting compliance at compile time.
var _ PIVAttestLevelReporter = (*backendPIVKeyGenerator)(nil)
