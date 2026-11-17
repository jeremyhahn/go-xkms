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
	"crypto/x509"
	"io"
	"time"

	"github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
	alg, err := releaseAlgorithm(signer)
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
	// A disabled, revoked or policy-denied key yields no signer.
	if err := s.checkKeyPolicy(ctx, k, keypolicy.OpSign); err != nil {
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
	// Each Sign is admitted like XKMSService.Sign, under the tenant, key and
	// caller captured here: a retained signer stops when the key is disabled,
	// revoked or its policy expires, and every use is charged to the key.
	// The signer stays paired with the version resolved here, the one Public
	// returns: when admission follows the usage counters to a newer version,
	// the Sign is refused rather than made under a key the caller never saw.
	//
	// The key is resolved again on every Sign, so a version disabled or
	// retired, or a key deleted, since the signer was obtained is refused
	// even without a key policy store (admitKey alone reloads nothing then),
	// and the signature comes from the backend key the version holds now,
	// checked to be the key Public returns.
	signCtx := context.WithoutCancel(ctx)
	version := k.record.Current
	sign := func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
		use, err := s.resolveKeyOf(signCtx, b, backendName, k.keyID, &owner)
		if err != nil {
			return nil, err
		}
		if use.record.Current != version {
			return nil, &KeyVersionMissingError{KeyID: k.keyID, Version: version}
		}
		v, err := use.use(version)
		if err != nil {
			return nil, err
		}
		if err := s.admitKey(signCtx, use, keypolicy.OpSign); err != nil {
			return nil, err
		}
		if use.record.Current != version {
			return nil, &KeyVersionMissingError{KeyID: k.keyID, Version: version}
		}
		backendSigner, err := use.backend.Signer(signCtx, v.attrs)
		if err != nil {
			return nil, &ErrKeyOperation{Operation: "sign with repository signing key", KeyID: key.KeyID, Err: err}
		}
		pub, ok := backendSigner.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !pub.Equal(signer.Public()) {
			return nil, &KeyVersionMissingError{KeyID: k.keyID, Version: version}
		}
		return backendSigner.Sign(rand, digest, opts)
	}
	return opaqueSigner{signer: signer, sigAlg: cur.attrs.SignatureAlgorithm, sign: sign}, nil
}

// opaqueSigner exposes only Public and Sign of a backend signer. A software
// backend's signer is the private key itself (*ecdsa.PrivateKey and the
// like), which a caller of RepositorySigner could otherwise type-assert to
// and read. When sign is set, every Sign goes through it: the repository
// signer admits the key under key policy on each use (resolutionSigner).
type opaqueSigner struct {
	signer crypto.Signer
	sigAlg x509.SignatureAlgorithm
	sign   func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Public returns the backend key's public half.
func (o opaqueSigner) Public() crypto.PublicKey { return o.signer.Public() }

// Sign signs digest through the backend.
func (o opaqueSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if o.sign != nil {
		return o.sign(rand, digest, opts)
	}
	return o.signer.Sign(rand, digest, opts)
}

// checkKeyPolicy refuses a key its policy does not admit for op, without
// charging a use: a signer is obtained once and charged per Sign.
func (s *XKMSService) checkKeyPolicy(ctx context.Context, k *versionedKey, op keypolicy.Operation) error {
	store := s.keyPolicies.load()
	if store == nil {
		return nil
	}
	rec, _, err := store.Load(ctx, k.tenant, k.backendName, k.keyID)
	if err != nil {
		return err
	}
	return rec.Check(callerSubject(ctx), op, 0, time.Now())
}

// coseAlgorithm picks the COSE algorithm a public key signs a CoRIM with.
func coseAlgorithm(pub crypto.PublicKey, sigAlg x509.SignatureAlgorithm) (cose.Algorithm, error) {
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
		// The padding is the backend's, not ours: a PKCS#1 v1.5 key (GCP KMS
		// RSA_SIGN_PKCS1_*) signs v1.5 whatever options it is given, so only
		// a key recorded as RSASSA-PSS may carry a PS* label.
		switch sigAlg {
		case x509.SHA256WithRSAPSS:
			return cose.AlgorithmPS256, nil
		case x509.SHA384WithRSAPSS:
			return cose.AlgorithmPS384, nil
		case x509.SHA512WithRSAPSS:
			return cose.AlgorithmPS512, nil
		}
		return 0, &errs.Detail{Err: refvalue.ErrUnsupportedKey,
			Detail: "RSA release signing needs an RSASSA-PSS key, got signature algorithm " + sigAlg.String()}
	}
	return 0, refvalue.ErrUnsupportedKey
}

// releaseAlgorithm picks the COSE algorithm for a repository signer from its
// public key and, for a wrapped signer, the key's recorded signature
// algorithm.
func releaseAlgorithm(signer crypto.Signer) (cose.Algorithm, error) {
	sigAlg := x509.UnknownSignatureAlgorithm
	if o, ok := signer.(opaqueSigner); ok {
		sigAlg = o.sigAlg
	}
	return coseAlgorithm(signer.Public(), sigAlg)
}
