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

package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// signContext carries the decisions signCSR made before choosing how the
// certificate's names are sourced.
type signContext struct {
	signer       crypto.Signer
	issuingCert  *x509.Certificate
	serial       *big.Int
	notBefore    time.Time
	notAfter     time.Time
	validityDays int
	keyUsage     x509.KeyUsage
	extKeyUsage  []x509.ExtKeyUsage
	profile      ProfileProvider
}

// signCallerNamedCSR signs a CSR under a CallerSANProfile. The CSR proves
// possession of its key and contributes nothing else: its subject and names
// are ignored, the subject comes from opts.Subject and the names from
// opts.SANS (on the keypair path the subject comes from the originating
// CertificateRequest when opts names none), and the tenant SPIFFE synthesis is refused because it would add
// a name the caller did not supply.
//
// IssueCertificateWithProfile reaches this path too. It builds its own CSR
// from the request's names and passes the same names on SignOptions.SANS, so
// the names it certifies are still exactly the caller's.
func (ca *CA) signCallerNamedCSR(ctx context.Context, csr *x509.CertificateRequest, opts *SignOptions, request *CertificateRequest, sc *signContext) (*x509.Certificate, error) {
	if opts == nil {
		return nil, &errs.Detail{Err: ErrCallerSANsRequired, Detail: "profile " + sc.profile.Name()}
	}
	if opts.SPIFFETrustDomain != "" || opts.SPIFFEKind != "" || opts.SPIFFEName != "" {
		return nil, &errs.Detail{Err: ErrTenantSPIFFEWithCallerSANs, Detail: "profile " + sc.profile.Name()}
	}
	names, err := parseCallerSANs(opts.SANS)
	if err != nil {
		return nil, err
	}
	if names.empty() {
		return nil, &errs.Detail{Err: ErrCallerSANsRequired, Detail: "profile " + sc.profile.Name()}
	}

	var subject pkix.Name
	switch {
	case opts.Subject != nil:
		subject = opts.Subject.ToPkixName()
	case request != nil:
		subject = request.Subject.ToPkixName()
	}

	spec := &CertificateSpec{
		Serial:             sc.serial,
		Subject:            subject,
		NotBefore:          sc.notBefore,
		NotAfter:           sc.notAfter,
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: determineSignatureAlgorithm(sc.signer.Public()),
		Profile:            sc.profile,
		DNSNames:           names.dns,
		EmailAddresses:     names.emails,
		IPAddresses:        names.ips,
		URIs:               names.uris,
	}
	return ca.issueSignedSpec(ctx, spec, csr, opts, request, sc)
}

// SubordinateIssuer is implemented by a CA that can certify a caller-held key
// as a name-constrained subordinate CA. *CA implements it. It is a separate
// interface rather than part of TrustedCA so that every existing TrustedCA
// implementation keeps compiling.
type SubordinateIssuer interface {
	// IssueSubordinateCA certifies req.PublicKey as a CA confined by
	// req.NameConstraints.
	IssueSubordinateCA(ctx context.Context, req *SubordinateCARequest) (*x509.Certificate, error)
}

var _ SubordinateIssuer = (*CA)(nil)

// DefaultSubordinateLifetime is the lifetime of a subordinate CA certificate
// whose request names none.
const DefaultSubordinateLifetime = 365 * 24 * time.Hour

// SubordinateCARequest describes a name-constrained subordinate CA, such as
// the tunnel intermediate that issues ipsec-vtep certificates or the SPIFFE
// intermediate that issues x509-svid certificates.
type SubordinateCARequest struct {
	// Subject is the subordinate's distinguished name. Its CommonName is
	// required.
	Subject pkix.Name

	// PublicKey is the subordinate's key, held by the caller (in its own
	// keystore, TPM or HSM). Required.
	PublicKey crypto.PublicKey

	// NameConstraints confine every certificate the subordinate issues.
	// Required, with at least one permitted subtree: an unconstrained
	// subordinate is what the CA's configured intermediates are for.
	NameConstraints *NameConstraints

	// Validity is the subordinate's lifetime. Zero selects
	// DefaultSubordinateLifetime. It must not extend past the issuing
	// certificate (ErrValidityExceedsIssuer).
	Validity time.Duration

	// AllowSubordinates permits the subordinate to certify further CAs. By
	// default it may not: the certificate carries pathLenConstraint 0.
	AllowSubordinates bool
}

// validate checks the request before any key or serial is touched.
func (r *SubordinateCARequest) validate() error {
	if r == nil {
		return &errs.Detail{Err: ErrInvalidCertificate, Detail: "subordinate CA request required"}
	}
	if r.Subject.CommonName == "" {
		return &errs.Detail{Err: ErrInvalidCertificate, Detail: "subordinate CA common name required"}
	}
	if r.PublicKey == nil {
		return &errs.Detail{Err: ErrInvalidCertificate, Detail: "subordinate CA public key required"}
	}
	if r.Validity < 0 {
		return &errs.Detail{Err: ErrInvalidValidity, Detail: "validity must not be negative"}
	}
	if err := r.NameConstraints.Validate(); err != nil {
		return err
	}
	if !r.NameConstraints.hasPermittedSubtree() {
		return &errs.Detail{Err: ErrInvalidNameConstraints, Detail: "a subordinate CA needs at least one permitted subtree"}
	}
	return nil
}

// IssueSubordinateCA certifies a caller-held key as a name-constrained
// subordinate CA, signed by this CA's issuing key with the CA profile and
// stamped with this CA's revocation endpoints. The certificate is stored and
// recorded like any other this CA issues, so it can be revoked.
//
// The CA keeps no handle on the subordinate's key. To issue under it, the
// caller signs with SignOptions.Signer (its key) and SignOptions.IssuerCert
// (the returned certificate).
func (ca *CA) IssueSubordinateCA(ctx context.Context, req *SubordinateCARequest) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	if err := req.validate(); err != nil {
		return nil, err
	}

	ca.mu.RLock()
	issuingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()
	if issuingCert == nil {
		return nil, ErrCertificateNotFound
	}

	lifetime := req.Validity
	if lifetime == 0 {
		lifetime = DefaultSubordinateLifetime
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(lifetime)
	if notAfter.After(issuingCert.NotAfter) {
		return nil, &errs.Detail{
			Err:    ErrValidityExceedsIssuer,
			Detail: fmt.Sprintf("subordinate would expire %s, issuer expires %s", notAfter.UTC().Format(time.RFC3339), issuingCert.NotAfter.UTC().Format(time.RFC3339)),
		}
	}

	signer, err := ca.getSigner(ctx)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
	}
	caProfile, err := ca.Profiles().Get(ProfileNameCA)
	if err != nil {
		return nil, err
	}
	serial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSerialGenerationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	issuer := &Issuer{Signer: signer, Certificate: issuingCert, Identity: ca.config.IssuingIdentity()}
	cert, err := issuer.Issue(rand.Reader, &CertificateSpec{
		Serial:             serial,
		Subject:            req.Subject,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		PublicKey:          req.PublicKey,
		SignatureAlgorithm: determineSignatureAlgorithm(signer.Public()),
		Profile:            caProfile,
		Request: &CertificateRequest{
			Subject:        subjectFromPkixName(req.Subject),
			IsCA:           true,
			MaxPathLen:     0,
			MaxPathLenZero: !req.AllowSubordinates,
		},
		NameConstraints: req.NameConstraints,
	})
	if err != nil {
		return nil, err
	}

	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to store certificate", Err: err}
	}
	if err := ca.recordCertTenant(ctx, cert.SerialNumber, ""); err != nil {
		return nil, err
	}
	return cert, nil
}
