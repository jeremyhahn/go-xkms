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
	"crypto/x509"
	"errors"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/image"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// The per-repository signing-key binding service layer (SPEC
// release-signing-key, go-xkms#1697). A tenant's images and CoRIM are signed
// by its release key (appraisal.ReleaseSigningKeyID) unless a binding names
// another key for the repository. Like the other Verifier methods, each acts
// on the caller's tenant and returns ErrNotConfigured when no Appraiser is
// wired.
//
// Changing a binding redirects every verification of the repository to
// another key, and reading one reveals which key signs it, so every method
// checks its attestation_signing_keys:* permission here as well as at the
// wire gate: an in-process caller composing the service through sdk/go meets
// the same refusal as a remote one.

// ErrSigningKeyForbidden is a signing-key call by a caller that does not
// hold the attestation_signing_keys:* permission it requires.
var ErrSigningKeyForbidden = errors.New("attestation: caller may not use the signing-key binding")

// SigningKeyPermissionError refuses a signing-key call by a caller without
// the permission it requires. It matches ErrSigningKeyForbidden and the
// authorizer's own refusal under errors.Is.
type SigningKeyPermissionError struct {
	// Permission is the resource:action the call requires.
	Permission string
	// Err is the authorizer's refusal.
	Err error
}

// Error reports the permission and the refusal.
func (e *SigningKeyPermissionError) Error() string {
	return "attestation: the signing-key call requires " + e.Permission + ": " + e.Err.Error()
}

// Unwrap returns ErrSigningKeyForbidden and the authorizer's refusal.
func (e *SigningKeyPermissionError) Unwrap() []error {
	return []error{ErrSigningKeyForbidden, e.Err}
}

// CoRIMSignError reports a CoRIM that could not be signed for a repository.
// Err is the refvalue sentinel chain (ErrMalformed, ErrMeta, ErrSignerKey,
// ErrSign), so callers match the cause with errors.Is.
type CoRIMSignError struct {
	// Repository is the repository the CoRIM was to be signed for.
	Repository string
	// KeyID is the signing key ResolveSigningKey named.
	KeyID string
	// Err is the signer's failure.
	Err error
}

// Error reports the repository, key and failure.
func (e *CoRIMSignError) Error() string {
	return "attestation: signing the CoRIM of repository " + e.Repository + " with key " + e.KeyID + ": " + e.Err.Error()
}

// Unwrap returns the signer's failure.
func (e *CoRIMSignError) Unwrap() error {
	return e.Err
}

// ErrSystemTenantImageSigning is returned by SignImage for the system tenant.
// Ruling 134 makes the tenant release signing key the image signer; the
// system tenant has none and never signs images (owner ruling 165).
var ErrSystemTenantImageSigning = errors.New("attestation: the system tenant has no release signing key to sign images with")

// ImageSignError reports that SignImage resolved a signing key but could not
// sign the image with it: the certificate request, the registry or the
// signer failed. It never carries the registry credentials.
type ImageSignError struct {
	// Reference is the image reference that was to be signed.
	Reference string
	// KeyID is the signing key ResolveSigningKey named.
	KeyID string
	// Err is the failure.
	Err error
}

// Error returns the reference, the key and the failure.
func (e *ImageSignError) Error() string {
	return "attestation: signing image " + e.Reference + " with key " + e.KeyID + ": " + e.Err.Error()
}

// Unwrap returns the failure.
func (e *ImageSignError) Unwrap() error {
	return e.Err
}

// ReleaseKeyProvisionError reports that a tenant's release key could not be
// generated on its first use. Err is the backend's failure.
// ErrReleaseKeyBackendUnsupported reports that the default backend cannot
// hold a release key for one tenant, so none is generated on first use. A
// tenant on such a backend binds a key it already holds.
var ErrReleaseKeyBackendUnsupported = errors.New("attestation: the backend cannot hold a tenant's release signing key")

type ReleaseKeyProvisionError struct {
	// TenantID is the tenant whose release key was to be generated.
	TenantID string
	// Err is the generate failure.
	Err error
}

// Error reports the tenant and the failure.
func (e *ReleaseKeyProvisionError) Error() string {
	return "attestation: provisioning the release signing key of tenant " + e.TenantID + ": " + e.Err.Error()
}

// Unwrap returns the generate failure.
func (e *ReleaseKeyProvisionError) Unwrap() error {
	return e.Err
}

// The algorithm of a provisioned release key. Neither the release-signing-key
// row nor the image-signing docs name one, so it is the ECDSA P-256 the
// service already generates its other use-named signing key with
// (CreateOTAImageKey): COSE signs with it as ES256 (refvalue.Sign) and DSSE
// over SHA-256 (pkg/image).
const (
	releaseKeyAlgorithm = "ecdsa"
	releaseKeyCurve     = "P-256"
)

// releaseKeyResolveTimeout bounds how long the loser of a release-key
// generation race waits for the winner's key to become resolvable: a
// software backend publishes the key material before the tenant record, so
// the collision can be seen before the tenant-filtered listing finds the key.
const releaseKeyResolveTimeout = 3 * time.Second

// releaseKeyResolveBackoff is the pause between those lookups; a test sets
// it to zero.
var releaseKeyResolveBackoff = 50 * time.Millisecond

// authorizeSigningKeys refuses a caller that does not hold
// attestation_signing_keys:action.
func (s *XKMSService) authorizeSigningKeys(ctx context.Context, action string) error {
	if err := s.AuthorizeCaller(ctx, auth.ResourceAttestationSigningKeys, action); err != nil {
		return &SigningKeyPermissionError{Permission: auth.ResourceAttestationSigningKeys + ":" + action, Err: err}
	}
	return nil
}

// SetSigningKeyBinding names the key that signs one of the caller's tenant's
// repositories, in place of the release key.
//
// Permission: attestation_signing_keys:bind.
func (s *XKMSService) SetSigningKeyBinding(ctx context.Context, req *appraisal.SetSigningKeyBindingRequest) (*appraisal.SigningKeyBinding, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionBind); err != nil {
		return nil, err
	}
	return appraiser.SetSigningKeyBinding(ctx, tenant, req)
}

// GetSigningKeyBinding returns the binding of one of the caller's tenant's
// repositories.
//
// Permission: attestation_signing_keys:get.
func (s *XKMSService) GetSigningKeyBinding(ctx context.Context, req *appraisal.GetSigningKeyBindingRequest) (*appraisal.SigningKeyBinding, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionGet); err != nil {
		return nil, err
	}
	return appraiser.GetSigningKeyBinding(ctx, tenant, req)
}

// ListSigningKeyBindings lists the caller's tenant's bindings, ordered by
// repository.
//
// Permission: attestation_signing_keys:list.
func (s *XKMSService) ListSigningKeyBindings(ctx context.Context) (*appraisal.ListSigningKeyBindingsResponse, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionList); err != nil {
		return nil, err
	}
	return appraiser.ListSigningKeyBindings(ctx, tenant)
}

// DeleteSigningKeyBinding removes the binding of one of the caller's
// tenant's repositories, returning it to the release key.
//
// Permission: attestation_signing_keys:bind.
func (s *XKMSService) DeleteSigningKeyBinding(ctx context.Context, req *appraisal.DeleteSigningKeyBindingRequest) error {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionBind); err != nil {
		return err
	}
	return appraiser.DeleteSigningKeyBinding(ctx, tenant, req)
}

// SigningPublicKey returns the public half of the tenant key a resolution
// names, so an Appraiser composed with appraisal.WithSigningKeySource(service)
// verifies a repository's signatures under the tenant's own key. The public
// key comes from the backend's signer: the cloud KMS backends return no
// private key from GetKey for a non-extractable key.
func (s *XKMSService) SigningPublicKey(ctx context.Context, tenant string, key *appraisal.SigningKeyResolution) (crypto.PublicKey, error) {
	signer, err := s.repositorySigner(ctx, tenant, key)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// repositoryKey resolves the tenant's key a repository signing key
// resolution names, without admitting it for any operation.
func (s *XKMSService) repositoryKey(ctx context.Context, tenant string, key *appraisal.SigningKeyResolution) (*versionedKey, error) {
	if key == nil {
		return nil, appraisal.ErrNilRequest
	}
	b, backendName, err := s.resolveTenantBackendWithName(key.Backend, tenant)
	if err != nil {
		return nil, err
	}
	// Every tenant names its release key release-signing, and the system
	// tenant's backend is unscoped, so the lookup is restricted to the
	// requested tenant: a key of another tenant is never trusted.
	owner := recordTenant(tenant)
	return s.resolveKeyOf(ctx, b, backendName, key.KeyID, &owner)
}

// repositorySigner returns the tenant-scoped backend signer of a resolved
// repository signing key. It admits nothing: the public-key lookup reads the
// key through it, and releaseKeySigner admits the key before signing.
func (s *XKMSService) repositorySigner(ctx context.Context, tenant string, key *appraisal.SigningKeyResolution) (crypto.Signer, error) {
	k, err := s.repositoryKey(ctx, tenant, key)
	if err != nil {
		return nil, err
	}
	return s.keySigner(ctx, k, key.KeyID)
}

// keySigner returns the backend signer of k's current version.
func (s *XKMSService) keySigner(ctx context.Context, k *versionedKey, keyID string) (crypto.Signer, error) {
	cur, err := k.current()
	if err != nil {
		return nil, err
	}
	signer, err := k.backend.Signer(ctx, cur.attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "read repository signing key", KeyID: keyID, Err: err}
	}
	return signer, nil
}

// releaseKeySigner returns the signer of the repository's resolved key, as
// repositorySigner does, and provisions a tenant's release key on its first
// use (SPEC release-signing-key): an unbound repository of a tenant that
// holds no release-signing key generates it in the tenant's scope of the
// resolved backend. Only the default resolution provisions; a binding to a
// key the tenant does not hold still fails with ErrKeyNotFound. The system
// tenant is never provisioned: it never signs images (owner ruling 165).
// The key, existing or just provisioned, is admitted for signing as Sign
// admits it: a revoked or disabled key, or a caller its policy refuses,
// never signs.
func (s *XKMSService) releaseKeySigner(ctx context.Context, tenant string, key *appraisal.SigningKeyResolution) (crypto.Signer, error) {
	k, err := s.repositoryKey(ctx, tenant, key)
	if errors.Is(err, ErrKeyNotFound) && key.Default && !qrdbsdk.IsSystemTenant(tenant) {
		if err := s.provisionReleaseKey(ctx, tenant, key.Backend); err != nil {
			return nil, err
		}
		k, err = s.repositoryKey(ctx, tenant, key)
	}
	if err != nil {
		return nil, err
	}
	if err := s.admitKey(ctx, k, keypolicy.OpSign); err != nil {
		return nil, err
	}
	return s.keySigner(ctx, k, key.KeyID)
}

// provisionReleaseKey generates tenant's release key in backendName, the
// default backend when empty. An existing key is kept: a backend refuses to
// generate over one, with ErrKeyAlreadyExists or, on a tenant-scoped TPM
// backend, a blob write wrapping store.ErrBlobExists, so of two concurrent
// first uses one generates the key and the other signs with it.
func (s *XKMSService) provisionReleaseKey(ctx context.Context, tenant, backendName string) error {
	b, err := s.resolveBackend(backendName)
	if err != nil {
		return &ReleaseKeyProvisionError{TenantID: tenant, Err: err}
	}
	if !keepsTenantScope(b) {
		return &ReleaseKeyProvisionError{TenantID: tenant, Err: ErrReleaseKeyBackendUnsupported}
	}
	_, err = s.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID:     appraisal.ReleaseSigningKeyID,
		Backend:   backendName,
		KeyType:   "signing",
		Algorithm: releaseKeyAlgorithm,
		Curve:     releaseKeyCurve,
		TenantID:  tenant,
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrKeyAlreadyExists) || errors.Is(err, store.ErrBlobExists) {
		return s.awaitReleaseKey(ctx, tenant, backendName)
	}
	return &ReleaseKeyProvisionError{TenantID: tenant, Err: err}
}

// awaitReleaseKey waits until the release key another instance generated
// resolves for tenant. A software backend publishes the key material before
// the tenant record, so the loser of a generation race can collide with a
// key that the tenant-filtered lookup does not yet find. The wait is bounded
// by releaseKeyResolveTimeout and ctx; a key that never resolves is reported
// as ErrKeyNotFound.
func (s *XKMSService) awaitReleaseKey(ctx context.Context, tenant, backendName string) error {
	key := &appraisal.SigningKeyResolution{KeyID: appraisal.ReleaseSigningKeyID, Backend: backendName}
	ctx, cancel := context.WithTimeout(ctx, releaseKeyResolveTimeout)
	defer cancel()
	for {
		_, err := s.repositoryKey(ctx, tenant, key)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrKeyNotFound) {
			return &ReleaseKeyProvisionError{TenantID: tenant, Err: err}
		}
		timer := time.NewTimer(releaseKeyResolveBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return &ReleaseKeyProvisionError{TenantID: tenant, Err: errors.Join(err, ctx.Err())}
		case <-timer.C:
		}
	}
}

// ResolveSigningKey returns the key that signs one of the caller's tenant's
// repositories: its bound key, or else the release key.
//
// Permission: attestation_signing_keys:get.
func (s *XKMSService) ResolveSigningKey(ctx context.Context, req *appraisal.ResolveSigningKeyRequest) (*appraisal.SigningKeyResolution, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionGet); err != nil {
		return nil, err
	}
	return appraiser.ResolveSigningKey(ctx, tenant, req)
}

// SignCoRIM signs CoRIM reference values of one of the caller's tenant's
// repositories as a draft-ietf-rats-corim-11 §4.2 signed CoRIM, with the key
// ResolveSigningKey names: the repository's bound key, or else the tenant's
// release key (owner ruling 134). The key is the tenant-scoped backend's
// signer, restricted to the caller's tenant as SigningPublicKey restricts
// it, so the output verifies under the key the Verifier trusts for the
// repository.
//
// Permission: attestation_signing_keys:sign.
func (s *XKMSService) SignCoRIM(ctx context.Context, req *appraisal.SignCoRIMRequest) (*appraisal.SignedCoRIM, error) {
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
	if err := appraisal.ValidateRepository(req.Repository); err != nil {
		return nil, err
	}
	key, err := appraiser.ResolveSigningKey(ctx, tenant, &appraisal.ResolveSigningKeyRequest{Repository: req.Repository})
	if err != nil {
		return nil, err
	}
	signer, err := s.releaseKeySigner(ctx, tenant, key)
	if err != nil {
		return nil, err
	}
	meta := refvalue.Meta{
		SignerName: req.SignerName,
		SignerURI:  req.SignerURI,
		NotBefore:  req.NotBefore,
		NotAfter:   req.NotAfter,
	}
	signed, err := refvalue.Sign(req.CoRIM, meta, signer)
	if err != nil {
		return nil, &CoRIMSignError{Repository: req.Repository, KeyID: key.KeyID, Err: err}
	}
	return &appraisal.SignedCoRIM{Key: *key, CoRIM: signed}, nil
}

// SignImage signs the image req.Reference names with the key
// ResolveSigningKey resolves for the reference's repository in the caller's
// tenant: the repository's bound key, or the tenant's release signing key
// (ruling 134). The key signs through its tenant-scoped backend Signer and
// never leaves it. Each call has the service CA issue the key a code-signing
// certificate, then drives the pkg/image Signer, which pushes the DSSE
// attestation as an OCI 1.1 referrer and to the image's cosign ".att" tag.
//
// The registry credentials in req are used for this call only. The password
// is wiped on every path, and neither it nor the username appears in an
// error. The system tenant has no release key and is refused with
// ErrSystemTenantImageSigning.
func (s *XKMSService) SignImage(ctx context.Context, req *transport.SignImageRequest) (*transport.SignedImage, error) {
	if req == nil {
		return nil, appraisal.ErrNilRequest
	}
	if req.Registry != nil {
		defer req.Registry.Password.Wipe()
	}
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSigningKeys(ctx, auth.ActionSign); err != nil {
		return nil, err
	}
	if qrdbsdk.IsSystemTenant(tenant) {
		return nil, ErrSystemTenantImageSigning
	}
	ref, err := image.ParseReference(req.Reference)
	if err != nil {
		return nil, err
	}
	if err := appraisal.ValidateRepository(ref.Repository); err != nil {
		return nil, err
	}
	// The credentials are checked before the CA certifies anything, so a
	// malformed request costs no certificate.
	credentials, err := registryAuth(ctx, req.Registry)
	if err != nil {
		return nil, err
	}
	if credentials != nil && credentials.Password != nil {
		defer credentials.Password.Destroy()
	}
	issuer := s.ca.load()
	if issuer == nil {
		return nil, ErrNotConfigured
	}
	key, err := appraiser.ResolveSigningKey(ctx, tenant, &appraisal.ResolveSigningKeyRequest{Repository: ref.Repository})
	if err != nil {
		return nil, err
	}
	signer, err := s.releaseKeySigner(ctx, tenant, key)
	if err != nil {
		return nil, err
	}
	signImageErr := func(err error) error {
		return &ImageSignError{Reference: ref.String(), KeyID: key.KeyID, Err: err}
	}

	// The certificate is issued unstored: it is named after the caller's
	// repository and returned with the signature, so the CA's store, keyed
	// by common name alone, never holds it. A CA that cannot issue unstored
	// yields a nil issuer, which RequestCodeSigningCertificate refuses.
	codeSigningIssuer, _ := issuer.(image.CertificateIssuer)
	certificate, err := image.RequestCodeSigningCertificate(ctx, codeSigningIssuer, signer, tenant, ref.Repository)
	if err != nil {
		return nil, signImageErr(err)
	}
	chain, err := caChain(issuer)
	if err != nil {
		return nil, signImageErr(err)
	}
	registry, err := s.newImageRegistry(credentials)
	if err != nil {
		return nil, signImageErr(err)
	}
	result, err := signImage(ctx, registry, &image.SignerConfig{
		Signer:      signer,
		Certificate: certificate,
		Chain:       chain,
		Registry:    registry,
	}, req)
	if err != nil {
		return nil, signImageErr(err)
	}
	certificatePEM, err := encoding.EncodeCertificatePEM(certificate)
	if err != nil {
		return nil, signImageErr(err)
	}
	return &transport.SignedImage{
		Key:             *key,
		Digest:          result.Digest,
		Envelope:        result.Envelope,
		Certificate:     certificatePEM,
		Referrer:        result.Push.Referrer.Digest,
		ReferrerIndexed: result.Push.ReferrerIndexed,
		AttestationTag:  result.Push.AttestationTag,
	}, nil
}

// signImage signs req's image with a pkg/image Signer built from cfg and
// closes registry afterwards; a failure to close is reported with any
// signing failure.
func signImage(ctx context.Context, registry image.RegistryClient, cfg *image.SignerConfig, req *transport.SignImageRequest) (*image.SignResult, error) {
	signer, err := image.NewSigner(cfg)
	if err != nil {
		return nil, errors.Join(err, registry.Close())
	}
	result, err := signer.SignImage(ctx, req.Reference, &image.SignOptions{
		PredicateType: req.PredicateType,
		Predicate:     req.Predicate,
	})
	if err := errors.Join(err, registry.Close()); err != nil {
		return nil, err
	}
	return result, nil
}

// caChain returns the service CA's certificate chain, the intermediates and
// root an image verifier chains the code-signing certificate through.
func caChain(issuer provider.CA) ([]*x509.Certificate, error) {
	bundle, err := issuer.CABundle()
	if err != nil {
		return nil, err
	}
	return encoding.DecodeCertificateChainPEM(bundle)
}

// registryAuth seals the caller's registry credentials for one SignImage
// call; nil credentials send none. The password is sealed into a
// secure.Secret, which wipes the request's copy, and is opened only to build
// each request's Authorization header. A password needs a username: the
// registry client sends none without one.
func registryAuth(ctx context.Context, credentials *transport.ImageRegistryCredentials) (*image.RegistryAuth, error) {
	if credentials == nil || (credentials.Username == "" && len(credentials.Password) == 0) {
		return nil, nil
	}
	if credentials.Username == "" {
		return nil, &errs.Detail{Err: image.ErrRegistryCredentials, Detail: "password without a username"}
	}
	auth := &image.RegistryAuth{Username: credentials.Username}
	if len(credentials.Password) > 0 {
		password, err := secure.NewSecret(ctx, credentials.Password)
		if err != nil {
			return nil, &errs.Joined{Lead: image.ErrRegistryCredentials, Cause: err}
		}
		auth.Password = password
	}
	return auth, nil
}

// newImageRegistry builds the registry client for one SignImage call.
func (s *XKMSService) newImageRegistry(auth *image.RegistryAuth) (image.RegistryClient, error) {
	newRegistry := s.imageRegistry
	if newRegistry == nil {
		newRegistry = image.NewRegistryClient
	}
	return newRegistry(&image.RegistryOptions{Auth: auth})
}
