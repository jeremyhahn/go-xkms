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
	"crypto/ecdsa"
	"crypto/elliptic"
	"regexp"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// OTAImageAlgorithmES256 is the one algorithm an OTA image-signing key uses:
// ECDSA on P-256 with SHA-256 (RFC 7518 section 3.4), on every
// trusted-firmware board (SPEC ota-image-keys).
const OTAImageAlgorithmES256 = "ES256"

// otaImageKeyPrefix prefixes a board id to form its key ID.
const otaImageKeyPrefix = "ota-image-"

// maxBoardIDLength bounds a board id to a DNS label's length.
const maxBoardIDLength = 63

// boardIDPattern is a board id: lowercase alphanumeric words joined by single
// hyphens. A doubled hyphen is refused so a board key ID can never take the
// shape of a key version's backend name ("K--v2").
var boardIDPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// OTAImageKeyID returns the key ID of boardID's OTA image-signing key. A
// board has exactly one, so the key ID is a function of the board id alone.
func OTAImageKeyID(boardID string) (string, error) {
	if len(boardID) > maxBoardIDLength || !boardIDPattern.MatchString(boardID) {
		return "", &ErrValidation{Sentinel: ErrInvalidBoardID, Detail: "a board id is 1-63 of a-z, 0-9 and single inner hyphens"}
	}
	return otaImageKeyPrefix + boardID, nil
}

// otaImageKeyID validates req and returns its board's key ID.
func otaImageKeyID(req *transport.OTAImageKeyRequest) (string, error) {
	if req == nil {
		return "", ErrNilConfig
	}
	if req.Algorithm != "" && req.Algorithm != OTAImageAlgorithmES256 {
		return "", &ErrValidation{Sentinel: ErrOTAImageAlgorithm, Detail: req.Algorithm}
	}
	return OTAImageKeyID(req.BoardID)
}

// CreateOTAImageKey creates the ES256 OTA image-signing key of req's board.
// A board that already has one is refused with ErrKeyAlreadyExists.
func (s *XKMSService) CreateOTAImageKey(ctx context.Context, req *transport.OTAImageKeyRequest) (*transport.GenerateKeyResponse, error) {
	keyID, err := otaImageKeyID(req)
	if err != nil {
		return nil, err
	}
	return s.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID:     keyID,
		Backend:   req.Backend,
		KeyType:   "signing",
		Algorithm: "ecdsa",
		Curve:     "P-256",
		TenantID:  req.TenantID,
	})
}

// RotateOTAImageKey creates the next version of req's board key and makes it
// current. Earlier versions keep verifying the images they signed.
func (s *XKMSService) RotateOTAImageKey(ctx context.Context, req *transport.OTAImageKeyRequest) (*transport.RotateKeyResponse, error) {
	keyID, err := otaImageKeyID(req)
	if err != nil {
		return nil, err
	}
	if err := s.requireES256Key(ctx, req.Backend, req.TenantID, keyID); err != nil {
		return nil, err
	}
	return s.RotateKey(ctx, &transport.RotateKeyRequest{
		Backend:  req.Backend,
		KeyID:    keyID,
		TenantID: req.TenantID,
	})
}

// SignOTAImage signs req's image with the current version of its board key,
// which the response's KeyVersion names.
func (s *XKMSService) SignOTAImage(ctx context.Context, req *transport.OTAImageSignRequest) (*transport.SignResponse, error) {
	if req == nil {
		return nil, ErrNilConfig
	}
	keyID, err := OTAImageKeyID(req.BoardID)
	if err != nil {
		return nil, err
	}
	if err := s.requireES256Key(ctx, req.Backend, req.TenantID, keyID); err != nil {
		return nil, err
	}
	return s.Sign(ctx, &transport.SignRequest{
		Backend:      req.Backend,
		KeyID:        keyID,
		Data:         req.Data,
		Hash:         crypto.SHA256.String(),
		DataIsDigest: req.DataIsDigest,
		TenantID:     req.TenantID,
	})
}

// requireES256Key refuses a board key whose current version is not an ECDSA
// P-256 key, so a key created under the board's key ID by another path never
// signs an image or is rotated as one.
func (s *XKMSService) requireES256Key(ctx context.Context, backendName, tenantID, keyID string) error {
	k, err := s.resolveKeyIn(ctx, backendName, tenantID, keyID)
	if err != nil {
		return err
	}
	cur, err := k.current()
	if err != nil {
		return err
	}
	// The public key comes from the backend's signer: the cloud KMS backends
	// return no private key from GetKey for a non-extractable key.
	signer, err := k.backend.Signer(ctx, cur.attrs)
	if err != nil {
		return &ErrKeyOperation{Operation: "read OTA image key", KeyID: keyID, Err: err}
	}
	if pub, ok := signer.Public().(*ecdsa.PublicKey); ok && pub.Curve == elliptic.P256() {
		return nil
	}
	return &ErrValidation{Sentinel: ErrOTAImageAlgorithm, Detail: "the board key is not an ECDSA P-256 key"}
}
