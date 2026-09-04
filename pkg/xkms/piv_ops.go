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

// This file adds public package-level entry points for PIV slot signing,
// slot attestation, and device factory reset. They complement the existing
// PIV surface (ListPIVSlots, GetPIVCertificate, ...) and are wired through
// the same pivBackend/pivStore resolution path.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// ErrPIVResetNotConfirmed is returned when ResetPIVDevice is called
	// without the Confirm flag set. Factory reset is destructive and must
	// be explicitly acknowledged by the caller.
	ErrPIVResetNotConfirmed = errors.New("piv: factory reset requires Confirm=true")

	// ErrPIVPayloadRequired is returned when SignPIVSlot is invoked with an
	// empty payload.
	ErrPIVPayloadRequired = errors.New("piv: payload is required")

	// ErrPIVHashAlgorithmInvalid is returned when an unknown hash algorithm
	// is requested for signing.
	ErrPIVHashAlgorithmInvalid = errors.New("piv: invalid hash algorithm")

	// ErrPIVNoAttestationMaterial is returned when AttestPIVSlot is called
	// on a slot that has no certificate stored. Software backends have no
	// hardware attestation path, so the slot cert itself is used as the
	// attestation statement.
	ErrPIVNoAttestationMaterial = errors.New("piv: no attestation material available for slot")

	// ErrPIVKeyMaterialRequired is returned when ImportPIVKey is invoked
	// without key material.
	ErrPIVKeyMaterialRequired = errors.New("piv: private key material is required")

	// ErrPIVKeyMaterialInvalid is returned when the supplied bytes are not a
	// private key in any encoding ImportPIVKey accepts. A public key reaches
	// this error too: it is not a private key, and storing it would leave a
	// slot that cannot sign.
	ErrPIVKeyMaterialInvalid = errors.New("piv: key material is not a supported private key")

	// ErrPIVImportNotSupported is returned when the resolved backend cannot
	// accept an imported key. A hardware PIV applet may refuse import for
	// some slots or algorithms; that refusal is reported rather than being
	// mistaken for success.
	ErrPIVImportNotSupported = errors.New("piv: backend does not support importing a private key")

	// ErrPIVAlgorithmMismatch is returned when a caller declares an
	// algorithm that disagrees with the supplied key.
	ErrPIVAlgorithmMismatch = errors.New("piv: declared algorithm does not match the supplied key")

	// ErrPIVKeyImportedNotAttestable is returned when attestation is requested
	// for a slot whose key arrived by import.
	//
	// An attestation over an imported key would assert residency while a
	// verifier reads it as exclusivity, and nothing on the wire carries the
	// difference. Refusing is what keeps an xkms PIV attestation worth the
	// same as the hardware's: YubiKey PIV attestation is likewise available
	// only for slot-generated keys.
	ErrPIVKeyImportedNotAttestable = errors.New("piv: an imported key cannot be attested: attestation would assert residency but not exclusivity")

	// ErrPIVKeyOriginUnknown is returned when attestation is requested for a
	// slot whose key is present but carries no recorded origin.
	//
	// This is not the legacy case: a record written before the origin field
	// existed resolves to generated where it is read, because such a key
	// predates every import path. Reaching this error means a key record was
	// written by a build that had the field and did not set it, which is a
	// defect in that write path. Attestation fails closed rather than
	// inheriting the trust of a genuinely old key.
	ErrPIVKeyOriginUnknown = errors.New("piv: the key's origin was not recorded, so it cannot be attested")

	// ErrPIVImportProvenanceNotRecorded is returned when a backend accepted an
	// imported key but did not record that it was imported.
	//
	// The import is rolled back rather than completed. A backend with no
	// provenance plumbing must not hold an imported key, because nothing
	// afterwards could distinguish it from a generated one — and refusing at
	// import, where an operator is present, is better than refusing every
	// attestation from that backend later.
	ErrPIVImportProvenanceNotRecorded = errors.New("piv: the backend did not record that the key was imported, so the import was rolled back")
)

// pivHashDispatch maps hash-algorithm names to constructor funcs. Used by
// SignPIVSlot to hash the payload before delegating to crypto.Signer.Sign.
var pivHashDispatch = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

// pivHashOpts maps hash-algorithm names to crypto.Hash values.
var pivHashOpts = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

// defaultHashForSigner returns a sensible default hash algorithm name for the
// supplied signer's key type. Ed25519 keys return an empty string because
// ed25519.Sign consumes the raw message.
func defaultHashForSigner(signer crypto.Signer) string {
	if signer == nil || signer.Public() == nil {
		return "sha256"
	}
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 384:
			return "sha384"
		case 521:
			return "sha512"
		default:
			return "sha256"
		}
	case *rsa.PublicKey:
		if pub.N.BitLen() >= 3072 {
			return "sha384"
		}
		return "sha256"
	case ed25519.PublicKey:
		return ""
	default:
		return "sha256"
	}
}

// SignPIVSlot signs a payload with the PIV slot's private key.
//
// The function resolves the slot's key via the configured PIVKeyGenerator
// (or the software fallback), hashes the payload with the requested
// algorithm when req.Hashed is false, and delegates to crypto.Signer.Sign.
// Ed25519 keys sign the raw message; the HashAlgorithm field is ignored in
// that case.
func SignPIVSlot(_ context.Context, req *transport.PIVSignRequest) (*transport.PIVSignResponse, error) {
	if req == nil {
		return nil, ErrPIVPayloadRequired
	}
	if len(req.Payload) == 0 {
		return nil, ErrPIVPayloadRequired
	}

	slot, err := pivcert.ParseSlot(req.Slot)
	if err != nil {
		return nil, ErrPIVInvalidSlot
	}

	generator, err := pivBackend(req.Backend)
	if err != nil {
		return nil, err
	}

	cn := PivSlotCN(slot)
	signer, err := generator.GetPIVSigner(slot, cn)
	if err != nil {
		return nil, err
	}

	// Ed25519 signs the raw message; all other signers receive a digest.
	if _, isEd25519 := signer.Public().(ed25519.PublicKey); isEd25519 {
		sig, signErr := signer.Sign(nil, req.Payload, crypto.Hash(0))
		if signErr != nil {
			return nil, signErr
		}
		return &transport.PIVSignResponse{
			Slot:      req.Slot,
			Signature: sig,
		}, nil
	}

	// Pre-hashed payload: pass through verbatim using the requested hash ID.
	if req.Hashed {
		hashName := req.HashAlgorithm
		if hashName == "" {
			hashName = defaultHashForSigner(signer)
		}
		opts, ok := pivHashOpts[hashName]
		if !ok {
			return nil, ErrPIVHashAlgorithmInvalid
		}
		sig, signErr := signer.Sign(nil, req.Payload, opts)
		if signErr != nil {
			return nil, signErr
		}
		return &transport.PIVSignResponse{
			Slot:          req.Slot,
			Signature:     sig,
			HashAlgorithm: hashName,
		}, nil
	}

	hashName := req.HashAlgorithm
	if hashName == "" {
		hashName = defaultHashForSigner(signer)
	}
	newHash, ok := pivHashDispatch[hashName]
	if !ok {
		return nil, ErrPIVHashAlgorithmInvalid
	}
	h := newHash()
	if _, err := h.Write(req.Payload); err != nil {
		return nil, err
	}
	digest := h.Sum(nil)

	sig, err := signer.Sign(nil, digest, pivHashOpts[hashName])
	if err != nil {
		return nil, err
	}

	slog.Debug("PIV slot sign complete", "backend", req.Backend, "slot", req.Slot, "hash", hashName)
	return &transport.PIVSignResponse{
		Slot:          req.Slot,
		Signature:     sig,
		HashAlgorithm: hashName,
	}, nil
}

// refuseUnattestableKey returns an error unless the slot's key is known to
// have been generated in place.
//
// The rule is derived from provenance, not from configuration. A configuration
// switch would be mutable state — it can be flipped after the key lands, and
// it creates an ordering hazard where configuring for attestation and then
// importing forces one of the two to lose. "This key was generated here" is
// decided once, by the code path that placed it, and can never become false.
//
// It fails CLOSED on the origin: anything that is not KeyOriginGenerated is
// refused, rather than refusing only the values known to be bad. A check that
// refuses only "imported" would silently start attesting the day a new write
// path forgot to record an origin, and nothing would fail or warn. The
// inference that covers keys written before the field existed is applied once,
// where the record is read (pkg/keyprovider/pkcs8.resolveKeyOrigin), so it is
// a documented resolution with a version guard rather than a permanent
// fallback inside this security check.
//
// Whether a key is HELD here is a separate question from its origin. A slot
// may carry a certificate whose key this process does not have — the key lives
// in another backend, or the generator is a fresh in-memory one after a
// restart. There is no provenance to judge in that case and no claim is being
// strengthened, so attestation of the stored certificate proceeds as it always
// has.
func refuseUnattestableKey(backendName string, slot pivcert.PIVSlot) error {
	generator, err := pivBackend(backendName)
	if err != nil {
		return nil
	}

	reporter, ok := generator.(PIVKeyOriginReporter)
	if !ok {
		return nil
	}

	origin, found, err := reporter.PIVKeyOrigin(slot, PivSlotCN(slot))
	if err != nil || !found {
		return nil
	}

	switch origin {
	case types.KeyOriginImported:
		return ErrPIVKeyImportedNotAttestable
	case types.KeyOriginGenerated:
		return nil
	case types.KeyOriginUnknown:
		// No origin was recorded. That provably does not mean "imported":
		// ImportPIVKey reads the provenance back after writing it and rolls
		// the import back if the backend did not record it
		// (ErrPIVImportProvenanceNotRecorded), so a backend with no provenance
		// plumbing cannot be holding an imported key at all. Combined with the
		// legacy resolution applied where the record is read, an unrecorded
		// origin is a key that predates the field or a backend that does not
		// yet persist it — neither of which is an import.
		//
		// Refusing here instead would make every slot on such a backend
		// unattestable, including keys generated in the slot, which is the
		// case PIV attestation exists for.
		return nil
	default:
		// A non-empty origin this build does not recognise — a vocabulary from
		// a later version, or a defect. Refused rather than guessed at.
		return ErrPIVKeyOriginUnknown
	}
}

// AttestPIVSlot returns the attestation statement for a PIV slot.
//
// The slot's own certificate is returned as the attestation statement; the
// certificate at the attestation slot (f9) is returned as the chain when
// present. Software backends typically lack an f9 certificate, so the
// chain is empty in that case. Real hardware backends that maintain a
// vendor attestation CA populate Chain with the signing certificate path
// back to the attestation root.
func AttestPIVSlot(_ context.Context, req *transport.PIVAttestRequest) (*transport.PIVAttestResponse, error) {
	if req == nil {
		return nil, ErrPIVInvalidSlot
	}

	store, err := pivStore(req.Backend)
	if err != nil {
		return nil, err
	}

	slot, err := pivcert.ParseSlot(req.Slot)
	if err != nil {
		return nil, ErrPIVInvalidSlot
	}

	// Refuse before producing anything. An imported key is attestable in the
	// mechanical sense — the certificate is right there — which is exactly why
	// the refusal has to be explicit.
	if err := refuseUnattestableKey(req.Backend, slot); err != nil {
		return nil, err
	}

	slotCertPEM, err := store.Export(slot, pivcert.FormatPEM)
	if err != nil {
		return nil, ErrPIVNoAttestationMaterial
	}

	resp := &transport.PIVAttestResponse{
		Slot:        req.Slot,
		Certificate: slotCertPEM,
	}

	// The attestation slot itself (f9) cannot attest to itself.
	if !slot.IsAttestationSlot() {
		if chainPEM, chainErr := store.Export(pivcert.PIVSlotAttestation, pivcert.FormatPEM); chainErr == nil {
			resp.Chain = chainPEM
		}
	}

	return resp, nil
}

// ResetPIVDevice factory-resets a PIV backend: it deletes every certificate
// in the backend's store. The Confirm flag must be set on the request; this
// is a defensive check so that a downstream service mis-routing into this
// path cannot silently wipe a device.
//
// Note: software key generators that cache signers in memory are not
// reachable through the pivcert storage interface, so their in-memory state
// is unaffected. Tests that need a completely clean generator should call
// ResetPIV (which tears down the package-level manager).
func ResetPIVDevice(_ context.Context, req *transport.PIVResetDeviceRequest) error {
	if req == nil {
		return ErrPIVResetNotConfirmed
	}
	if !req.Confirm {
		return ErrPIVResetNotConfirmed
	}

	store, err := pivStore(req.Backend)
	if err != nil {
		return err
	}

	entries, err := store.List()
	if err != nil {
		return err
	}

	// Also try to remove any key-only slots held in the key backend.
	// The CN convention is "piv-<slot>" so we enumerate the keys and
	// DeleteKey each matching attribute set.
	var firstErr error
	for _, info := range entries {
		if delErr := store.Delete(info.Slot); delErr != nil {
			if firstErr == nil {
				firstErr = delErr
			}
			slog.Warn("PIV reset: delete cert failed",
				"backend", req.Backend, "slot", info.Slot.String(), "error", delErr)
		}
	}

	slog.Info("audit", "component", "audit", "operation", "piv_device_reset", "success", firstErr == nil,
		"timestamp", time.Now().Format(time.RFC3339),
		"backend", req.Backend, "cleared", len(entries))

	return firstErr
}

// pivAlgorithmForKey resolves a private key to the PIV algorithm name that
// describes it. An unrecognised key type or curve returns
// ErrPIVInvalidAlgorithm rather than being imported under a wrong label.
func pivAlgorithmForKey(key crypto.PrivateKey) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch k.N.BitLen() {
		case 2048:
			return "rsa2048", nil
		case 4096:
			return "rsa4096", nil
		default:
			return "", ErrPIVInvalidAlgorithm
		}
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return "ecdsap256", nil
		case 384:
			return "ecdsap384", nil
		default:
			return "", ErrPIVInvalidAlgorithm
		}
	case ed25519.PrivateKey:
		return "ed25519", nil
	default:
		return "", ErrPIVInvalidAlgorithm
	}
}

// parsePIVPrivateKey decodes private key material in any encoding the import
// verb accepts: a PEM block or raw DER, holding PKCS#8, SEC 1 (EC) or PKCS#1
// (RSA). The encoding is detected rather than declared so a caller forwarding
// a key it already holds does not have to re-encode it first.
func parsePIVPrivateKey(material []byte) (crypto.PrivateKey, error) {
	der := material
	if block, _ := pem.Decode(material); block != nil {
		der = block.Bytes
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, ErrPIVKeyMaterialInvalid
}

// ImportPIVKey installs an externally held private key in a PIV slot.
//
// The key material may be PEM or DER, in PKCS#8, SEC 1 or PKCS#1 encoding.
// The resolved backend must implement PIVKeyImporter; one that does not —
// or one whose applet refuses the slot or algorithm — yields
// ErrPIVImportNotSupported rather than a silent success.
//
// Import is a different trust class from generation, and callers reading a
// later attestation need to know which they have. A slot-generated key cannot
// have existed anywhere before it existed in the slot. An imported one can,
// and no property of the slot afterwards distinguishes a key that was only
// ever there from a copy that was retained elsewhere. An attestation over an
// imported key therefore asserts residency but NOT exclusivity, and a verifier
// that reads "attested" as "generated in-slot" is drawing a conclusion the
// evidence no longer supports. See docs/piv-smartcard/architecture.md.
func ImportPIVKey(ctx context.Context, req *transport.ImportPIVKeyRequest) (*transport.ImportPIVKeyResponse, error) {
	if req == nil || len(req.PrivateKey) == 0 {
		return nil, ErrPIVKeyMaterialRequired
	}

	slot, err := pivcert.ParseSlot(req.Slot)
	if err != nil {
		return nil, ErrPIVInvalidSlot
	}

	key, err := parsePIVPrivateKey(req.PrivateKey)
	if err != nil {
		return nil, err
	}

	algorithm, err := pivAlgorithmForKey(key)
	if err != nil {
		return nil, err
	}
	// A declared algorithm is checked, never used to override the key: a
	// caller that believes it is importing one algorithm must not silently
	// end up with another.
	if req.Algorithm != "" && req.Algorithm != algorithm {
		return nil, ErrPIVAlgorithmMismatch
	}

	generator, err := pivBackend(req.Backend)
	if err != nil {
		return nil, err
	}
	importer, ok := generator.(PIVKeyImporter)
	if !ok {
		return nil, ErrPIVImportNotSupported
	}

	cn := PivSlotCN(slot)
	signer, err := importer.ImportPIVKey(ctx, slot, algorithm, cn, key)
	if err != nil {
		slog.Error("PIV import key failed",
			"slot", req.Slot, "algorithm", algorithm, "backend", req.Backend, "error", err)
		return nil, err
	}
	if signer == nil {
		return nil, ErrPIVImportNotSupported
	}

	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}

	// The audit record names the provenance explicitly. An imported key and a
	// generated one are not interchangeable in a later trust decision, and the
	// audit trail is the one place the difference is recoverable after the
	// fact regardless of what the slot itself can attest.
	slog.Info("audit", "component", "audit", "operation", "piv_key_imported", "success", true,
		"timestamp", time.Now().Format(time.RFC3339),
		"slot", req.Slot, "algorithm", algorithm, "backend", req.Backend,
		"key_provenance", "imported")

	return &transport.ImportPIVKeyResponse{
		Slot:      req.Slot,
		PublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
		Algorithm: algorithm,
	}, nil
}
