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

package appraisal

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
)

// KeyOriginGenerated is the KeyOrigin of an Android attested key generated
// inside secure hardware, the only origin an appraisal affirms.
const KeyOriginGenerated = "generated"

// AppraiseAndroidKeyAttestationRequest carries an Android key attestation
// certificate chain, as a handset's Keystore returns it.
type AppraiseAndroidKeyAttestationRequest struct {
	// ChainDER is the DER certificate chain, leaf (the attested key) first.
	ChainDER [][]byte `json:"chain_der"`
}

// AppraiseEKCertificateRequest carries a TPM endorsement key certificate
// and the intermediates it chains through to its manufacturer's root.
type AppraiseEKCertificateRequest struct {
	// CertificateDER is the DER EK certificate, as read from the TPM's NV
	// EK certificate index.
	CertificateDER []byte `json:"certificate_der"`

	// IntermediatesDER are DER intermediate CA certificates, in any order.
	IntermediatesDER [][]byte `json:"intermediates_der,omitempty"`
}

// AndroidApplicationSource supplies the tenant-controlled allow-list an
// Android key attestation's application must be on (docs/SPEC.md:43).
type AndroidApplicationSource interface {
	// AndroidApplications returns the tenant's application matcher, or nil
	// when the tenant has none configured.
	AndroidApplications(ctx context.Context, tenant string) (android.ApplicationMatcher, error)
}

// WithAndroidApplications sets the source of each tenant's Android
// application allow-list. Without one every Android appraisal is refused.
func WithAndroidApplications(source AndroidApplicationSource) Option {
	return func(a *Appraiser) { a.androidApps = source }
}

// AndroidApplicationAllowList maps an Android package name to the hex
// SHA-256 digests of the signing certificates accepted for it. A package is
// only an identity together with its signing digest, so an entry without
// digests admits nothing.
type AndroidApplicationAllowList map[string][]string

// Match admits appID when one of its packages is listed with one of its
// signing digests.
func (l AndroidApplicationAllowList) Match(appID *android.AttestationApplicationID) (string, string, error) {
	if appID == nil || len(appID.Packages) == 0 {
		return "", "", ErrNoAttestedApplication
	}
	for _, pkg := range appID.Packages {
		for _, want := range l[pkg.Name] {
			for _, digest := range appID.SignatureDigests {
				if got := hex.EncodeToString(digest); strings.EqualFold(strings.TrimSpace(want), got) {
					return pkg.Name, got, nil
				}
			}
		}
	}
	return "", "", ErrApplicationNotAllowed
}

// AndroidApplicationPolicies is a static AndroidApplicationSource: each
// tenant's allow-list by tenant name. A tenant absent from it, or with an
// empty allow-list, has none.
type AndroidApplicationPolicies map[string]AndroidApplicationAllowList

// AndroidApplications returns tenant's allow-list, or nil when it has none.
func (p AndroidApplicationPolicies) AndroidApplications(_ context.Context, tenant string) (android.ApplicationMatcher, error) {
	if list := p[tenant]; len(list) > 0 {
		return list, nil
	}
	return nil, nil
}

// attestedApplication refuses an attestation naming no application before
// the tenant's matcher sees it, whatever matcher the tenant supplied.
type attestedApplication struct {
	allowed android.ApplicationMatcher
}

// Match refuses a missing application identity, then defers to the
// tenant's matcher.
func (m attestedApplication) Match(appID *android.AttestationApplicationID) (string, string, error) {
	if appID == nil || len(appID.Packages) == 0 {
		return "", "", ErrNoAttestedApplication
	}
	return m.allowed.Match(appID)
}

// androidApplications resolves tenant's application matcher, failing
// closed when the Appraiser or the tenant has no allow-list.
func (a *Appraiser) androidApplications(ctx context.Context, tenant string) (android.ApplicationMatcher, error) {
	if a.androidApps == nil {
		return nil, ErrNoApplicationAllowList
	}
	allowed, err := a.androidApps.AndroidApplications(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if allowed == nil {
		return nil, ErrNoApplicationAllowList
	}
	return attestedApplication{allowed: allowed}, nil
}

// AppraiseAndroidKeyAttestation verifies an Android key attestation chain
// under the tenant's android-root endorsements: the chain anchors in one,
// the key was generated in TEE or StrongBox hardware for signing, and the
// device reports a locked bootloader and a verified boot chain, and the
// attested application is on the tenant's allow-list (refused when the
// tenant has none or the chain names no application). Evidence
// that fails is refused with an *EvidenceRefusedError.
func (a *Appraiser) AppraiseAndroidKeyAttestation(ctx context.Context, tenant string, req *AppraiseAndroidKeyAttestationRequest) (*AttestationResult, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	refuse := func(cause error) error { return &EvidenceRefusedError{Check: AppraisalCheckAndroidKey, Cause: cause} }
	if len(req.ChainDER) == 0 {
		return nil, refuse(attestation.ErrEmptyCertificateChain)
	}
	roots, pool, err := a.endorsementPool(ctx, tenant, EndorsementAndroidRoot)
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, refuse(attestation.ErrNoTrustAnchors)
	}
	apps, err := a.androidApplications(ctx, tenant)
	if errors.Is(err, ErrNoApplicationAllowList) {
		return nil, refuse(err)
	}
	if err != nil {
		return nil, err
	}
	key, err := attestation.VerifyAndroidDeviceKey(req.ChainDER, &attestation.AndroidDeviceTrust{Roots: pool, Applications: apps})
	if err != nil {
		return nil, refuse(err)
	}
	return &AttestationResult{
		Verified:    true,
		Checks:      []AppraisalCheck{{Name: AppraisalCheckAndroidKey, Outcome: AppraisalPass}},
		TrustAnchor: endorsementFor(roots, key.TrustAnchor),
		BootState:   key.RootOfTrust.VerifiedBootState.String(),
		KeyOrigin:   KeyOriginGenerated,
		AppraisedAt: a.now().UTC(),
	}, nil
}

// AppraiseEKCertificate verifies a TPM endorsement key certificate under the
// tenant's ek-root endorsements: it chains to one through the given
// intermediates and carries the tcg-kp-EKCertificate extended key usage.
// Evidence that fails is refused with an *EvidenceRefusedError.
func (a *Appraiser) AppraiseEKCertificate(ctx context.Context, tenant string, req *AppraiseEKCertificateRequest) (*AttestationResult, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	refuse := func(cause error) error {
		return &EvidenceRefusedError{Check: AppraisalCheckEKCertificate, Cause: cause}
	}
	leaf, _, err := evidence.ParseEKCertificateChain(req.CertificateDER)
	if err != nil {
		return nil, refuse(err)
	}
	intermediates := make([]*x509.Certificate, 0, len(req.IntermediatesDER))
	for _, der := range req.IntermediatesDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, refuse(err)
		}
		intermediates = append(intermediates, cert)
	}
	roots, pool, err := a.endorsementPool(ctx, tenant, EndorsementEKRoot)
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, refuse(attestation.ErrNoTrustAnchors)
	}
	now := a.now()
	if err := evidence.VerifyEKCertificate(leaf, intermediates, evidence.EKCertificateOptions{Roots: pool, Now: now}); err != nil {
		return nil, refuse(err)
	}
	// The chain verified under the pool; name the endorsement it anchored
	// in by re-verifying under each root alone.
	anchor := ""
	for _, root := range roots {
		single := x509.NewCertPool()
		single.AddCert(root.cert)
		if evidence.VerifyEKCertificate(leaf, intermediates, evidence.EKCertificateOptions{Roots: single, Now: now}) == nil {
			anchor = root.name
			break
		}
	}
	return &AttestationResult{
		Verified:    true,
		Checks:      []AppraisalCheck{{Name: AppraisalCheckEKCertificate, Outcome: AppraisalPass}},
		TrustAnchor: anchor,
		AppraisedAt: now.UTC(),
	}, nil
}

// endorsedRoot is a stored CA endorsement with its parsed certificate.
type endorsedRoot struct {
	name string
	cert *x509.Certificate
}

// endorsementPool loads the tenant's CA endorsements of kind, the same
// store AppraiseQuote anchors AK certificates in, as parsed roots and a pool.
func (a *Appraiser) endorsementPool(ctx context.Context, tenant string, kind EndorsementKind) ([]endorsedRoot, *x509.CertPool, error) {
	stored, err := a.loadEndorsements(ctx, tenant, kind)
	if err != nil {
		return nil, nil, err
	}
	roots := make([]endorsedRoot, 0, len(stored))
	pool := x509.NewCertPool()
	for _, e := range stored {
		// PutEndorsement only stores a parseable CA certificate; a record
		// that no longer parses anchors nothing and is passed over.
		cert, err := parseCertificatePEM(e.CertificatePEM)
		if err != nil {
			continue
		}
		roots = append(roots, endorsedRoot{name: e.Name, cert: cert})
		pool.AddCert(cert)
	}
	return roots, pool, nil
}

// endorsementFor names the endorsement whose certificate is anchor.
func endorsementFor(roots []endorsedRoot, anchor *x509.Certificate) string {
	if anchor == nil {
		return ""
	}
	for _, root := range roots {
		if bytes.Equal(root.cert.Raw, anchor.Raw) {
			return root.name
		}
	}
	return attestation.FormatTrustAnchor(anchor)
}
