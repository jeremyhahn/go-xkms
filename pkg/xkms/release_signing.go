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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// SignReleaseCoRIMRequest names the repository whose signing key signs an
// unsigned CoRIM.
type SignReleaseCoRIMRequest struct {
	// Repository is the repository the reference values belong to; its key
	// is the tenant's release key unless a binding names another.
	Repository string

	// CoRIM is the CBOR encoding of the unsigned CoRIM.
	CoRIM []byte

	// SignerName is the corim-meta signer name. Empty means Repository.
	SignerName string
}

// SignReleaseCoRIMResponse carries the signed CoRIM and the key that signed it.
type SignReleaseCoRIMResponse struct {
	// SignedCoRIM is the COSE_Sign1 encoding of the signed CoRIM.
	SignedCoRIM []byte

	// KeyID and Backend name the repository key that signed it.
	KeyID   string
	Backend string
}

// SignReleaseCoRIM signs an unsigned CoRIM with the signing key of one of
// the caller's tenant's repositories: the release key
// (appraisal.ReleaseSigningKeyID) unless a binding names another. The key is
// looked up in the caller's tenant only and signs through its backend's
// crypto.Signer, so the private key never leaves the backend. The caller
// needs attestation_signing_keys:sign.
func (s *XKMSService) SignReleaseCoRIM(ctx context.Context, req *SignReleaseCoRIMRequest) (*SignReleaseCoRIMResponse, error) {
	if req == nil {
		return nil, appraisal.ErrNilRequest
	}
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionSign); err != nil {
		return nil, err
	}
	resolution, err := appraiser.ResolveSigningKey(ctx, tenant, &appraisal.ResolveSigningKeyRequest{Repository: req.Repository})
	if err != nil {
		return nil, err
	}
	signer, err := s.repositorySigner(ctx, tenant, resolution)
	if err != nil {
		return nil, err
	}
	alg, err := coseAlgorithm(signer.Public())
	if err != nil {
		return nil, err
	}
	name := req.SignerName
	if name == "" {
		name = req.Repository
	}
	signed, err := refvalue.Sign(ctx, req.CoRIM, signer, alg, name)
	if err != nil {
		return nil, err
	}
	return &SignReleaseCoRIMResponse{SignedCoRIM: signed, KeyID: resolution.KeyID, Backend: resolution.Backend}, nil
}

// repositorySigner returns the backend signer of a resolved repository key,
// restricted to the tenant's own keys like SigningPublicKey.
func (s *XKMSService) repositorySigner(ctx context.Context, tenant string, key *appraisal.SigningKeyResolution) (crypto.Signer, error) {
	b, backendName, err := s.resolveTenantBackendWithName(key.Backend, tenant)
	if err != nil {
		return nil, err
	}
	owner := recordTenant(tenant)
	k, err := s.resolveKeyOf(ctx, b, backendName, key.KeyID, &owner)
	if err != nil {
		return nil, err
	}
	cur, err := k.current()
	if err != nil {
		return nil, err
	}
	signer, err := k.backend.Signer(ctx, cur.attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "sign with repository signing key", KeyID: key.KeyID, Err: err}
	}
	return signer, nil
}

// coseAlgorithm picks the COSE algorithm a public key signs a CoRIM with.
func coseAlgorithm(pub crypto.PublicKey) (cose.Algorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return cose.AlgorithmES256, nil
		case elliptic.P384():
			return cose.AlgorithmES384, nil
		case elliptic.P521():
			return cose.AlgorithmES512, nil
		}
	case ed25519.PublicKey:
		return cose.AlgorithmEdDSA, nil
	case *rsa.PublicKey:
		return cose.AlgorithmPS256, nil
	}
	return 0, refvalue.ErrUnsupportedKey
}
