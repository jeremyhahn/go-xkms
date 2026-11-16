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
	"io"

	"github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
)

// SignReleaseCoRIMRequest and SignReleaseCoRIMResponse are the appraisal
// types, which carry the JSON tags every transport shares.
type (
	SignReleaseCoRIMRequest  = appraisal.SignReleaseCoRIMRequest
	SignReleaseCoRIMResponse = appraisal.SignReleaseCoRIMResponse
)

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
	signer, resolution, err := s.resolveRepositorySigner(ctx, req.Repository)
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

// RepositorySigner returns the signer of the caller tenant's key for a
// repository: the tenant's release key unless the tenant named another key
// for the repository (owner ruling 134). It is the default signer of the
// tenant's images (image.NewRepositorySigner) and CoRIMs
// (SignReleaseCoRIM). The caller needs the signing-key sign permission; the
// private key stays in its backend, the signer only signs through it.
func (s *XKMSService) RepositorySigner(ctx context.Context, repository string) (crypto.Signer, error) {
	signer, _, err := s.resolveRepositorySigner(ctx, repository)
	return signer, err
}

// resolveRepositorySigner authorizes a sign, resolves the caller tenant's
// key for repository and returns its signer with the resolution.
func (s *XKMSService) resolveRepositorySigner(ctx context.Context, repository string) (crypto.Signer, *appraisal.SigningKeyResolution, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionSign); err != nil {
		return nil, nil, err
	}
	resolution, err := appraiser.ResolveSigningKey(ctx, tenant, &appraisal.ResolveSigningKeyRequest{Repository: repository})
	if err != nil {
		return nil, nil, err
	}
	signer, err := s.resolutionSigner(ctx, tenant, resolution)
	if err != nil {
		return nil, nil, err
	}
	return signer, resolution, nil
}

// resolutionSigner returns the backend signer of a resolved repository key,
// restricted to the tenant's own keys like SigningPublicKey.
func (s *XKMSService) resolutionSigner(ctx context.Context, tenant string, key *appraisal.SigningKeyResolution) (crypto.Signer, error) {
	b, backendName, err := s.resolveTenantBackendWithName(key.Backend, tenant)
	if err != nil {
		return nil, err
	}
	owner := recordTenant(tenant)
	k, err := s.resolveKeyOf(ctx, b, backendName, key.KeyID, &owner)
	if err != nil {
		return nil, err
	}
	// Admitted like XKMSService.Sign: a disabled, revoked or policy-denied
	// key never signs a release.
	if err := s.admitKey(ctx, k, keypolicy.OpSign); err != nil {
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
	return opaqueSigner{signer: signer}, nil
}

// opaqueSigner exposes only Public and Sign of a backend signer. A software
// backend's signer is the private key itself (*ecdsa.PrivateKey and the
// like), which a caller of RepositorySigner could otherwise type-assert to
// and read.
type opaqueSigner struct {
	signer crypto.Signer
}

// Public returns the backend key's public half.
func (o opaqueSigner) Public() crypto.PublicKey { return o.signer.Public() }

// Sign signs digest through the backend.
func (o opaqueSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.signer.Sign(rand, digest, opts)
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
