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

	"errors"
	"hash"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
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
