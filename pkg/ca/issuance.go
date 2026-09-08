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

// Package ca defines the issuance helpers shared by the root, intermediate and
// end-entity certificate paths: certificate-profile application and the
// revocation / Authority Information Access endpoints stamped onto every
// certificate this CA signs.
package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// =============================================================================
// Canonical Certificate Issuance
// =============================================================================

// Issuer is the signing identity for one issuance: the key that signs, the
// certificate that will appear as the issuer, and the configured identity
// whose revocation and Authority Information Access endpoints are stamped onto
// what it issues.
//
// The issuer is carried explicitly rather than resolved from a process-wide
// CA so that a multi-tenant caller can issue from a tenant's own key under a
// tenant's own trust chain. The ACME admin service and the cluster
// provisioner both rely on this.
type Issuer struct {
	// Signer signs the certificate. Required.
	Signer crypto.Signer

	// Certificate is the issuing CA certificate. A nil Certificate requests a
	// self-signed certificate: the template becomes its own parent, which is
	// how root CAs — including per-tenant roots — are created.
	Certificate *x509.Certificate

	// Identity supplies the CRL distribution points, OCSP responders and
	// issuing-certificate URLs that this issuer can speak for. A nil Identity
	// issues certificates without revocation or Authority Information Access
	// endpoints.
	Identity *Identity
}

// SelfSigned reports whether this issuer signs with its own key under its own
// subject, which is the case for a root CA.
func (iss *Issuer) SelfSigned() bool {
	return iss != nil && iss.Certificate == nil
}

// CertificateSpec describes the certificate a caller wants issued.
//
// A caller states what it wants — a subject, a validity window, the names the
// certificate must cover, and the profile that classifies the certificate —
// and pkg/ca decides how that becomes an x509.Certificate. Key usage,
// extended key usage, basic constraints, certificate policies and the
// issuer's revocation endpoints are deliberately absent: those are policy and
// belong to the profile and the issuer, not to the call site.
type CertificateSpec struct {
	// Serial is the certificate serial number. Required.
	Serial *big.Int

	// Subject is the distinguished name of the certified entity. Required.
	Subject pkix.Name

	// NotBefore and NotAfter bound the validity period. Required.
	NotBefore time.Time
	NotAfter  time.Time

	// PublicKey is the key being certified. A nil PublicKey certifies the
	// issuer's own public key, which is what a self-signed root requires.
	PublicKey crypto.PublicKey

	// SignatureAlgorithm pins the algorithm used to sign. The zero value lets
	// crypto/x509 derive it from the signing key.
	SignatureAlgorithm x509.SignatureAlgorithm

	// Profile classifies the certificate. Required: requiring it
	// unconditionally is what guarantees no issuance path can bypass
	// Profile.Apply.
	Profile ProfileProvider

	// Request is the issuance context handed to Profile.Apply so profiles can
	// make context-sensitive decisions — a CA profile reads MaxPathLen, a
	// tenant-aware profile reads TenantID.
	Request *CertificateRequest

	// DNSNames, EmailAddresses, IPAddresses and URIs are the subject
	// alternative names taken from a CSR or supplied directly by the caller.
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	// SANS carries additional subject alternative names in the CA's
	// configuration representation. They are appended to the fields above.
	SANS *SubjectAlternativeNames

	// OtherNames are subjectAltName entries of GeneralName CHOICE otherName,
	// which crypto/x509 cannot express. Supplying any of them makes this
	// package encode the whole subjectAltName extension, standard names
	// included, because crypto/x509 skips its own once the extension is
	// present. The TCG DevID hardwareModuleName and permanentIdentifier are
	// carried this way.
	OtherNames []OtherName

	// ExtraExtensions are caller-owned extensions — TCG device attributes, a
	// Certificate Transparency poison or SCT list, a network-zone extension —
	// appended after the CA and the profile have added their own.
	ExtraExtensions []pkix.Extension
}

// Template builds the finished, policy-applied certificate template for spec.
//
// This is the single implementer of CA certificate template construction in
// go-xkms. It is exported for the one caller that cannot use Issue: the
// hybrid ML-DSA signer, which signs the same template twice.
//
// The order of operations is load-bearing:
//
//  1. the caller's subject, validity and names populate the template;
//  2. the issuer certificate supplies the issuer name and authority key
//     identifier;
//  3. the profile sets key usage, extended key usage, basic constraints,
//     certificate policies and any extensions it owns;
//  4. the issuer's identity stamps the revocation and Authority Information
//     Access endpoints the profile did not already claim;
//  5. the caller's extra extensions are appended last.
//
// Returns ErrInvalidIssuer when the issuer has no signer, and an error
// wrapping ErrInvalidProfile when no profile was supplied or the profile
// rejects the template.
func (iss *Issuer) Template(spec *CertificateSpec) (*x509.Certificate, error) {
	if iss == nil || iss.Signer == nil {
		return nil, ErrInvalidIssuer
	}
	if spec == nil {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: "certificate spec required"}
	}
	if spec.Serial == nil {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: "serial number required"}
	}
	if spec.Profile == nil {
		return nil, &errs.Detail{Err: ErrInvalidProfile, Detail: "certificate profile required"}
	}

	template := &x509.Certificate{
		SerialNumber:       spec.Serial,
		Subject:            spec.Subject,
		NotBefore:          spec.NotBefore,
		NotAfter:           spec.NotAfter,
		SignatureAlgorithm: spec.SignatureAlgorithm,
		DNSNames:           spec.DNSNames,
		EmailAddresses:     spec.EmailAddresses,
		IPAddresses:        spec.IPAddresses,
		URIs:               spec.URIs,

		// Certificates assert basic constraints by default — RFC 5280 section
		// 4.2.1.9 — and a profile whose certificates must omit the extension
		// clears this in Apply. The TCG credential profiles and the ACME leaf
		// profile do exactly that.
		BasicConstraintsValid: true,
	}

	if spec.SANS != nil {
		template.DNSNames = append(template.DNSNames, spec.SANS.DNS...)
		template.EmailAddresses = append(template.EmailAddresses, spec.SANS.Email...)
		template.IPAddresses = append(template.IPAddresses, spec.SANS.ParseIPs()...)
		template.URIs = append(template.URIs, spec.SANS.ParseURIs()...)
	}

	// Bind the certificate to its issuer. crypto/x509 derives both from the
	// parent certificate when it signs, but populating them here means a
	// caller inspecting the template before signing sees the real chain.
	if iss.Certificate != nil {
		template.Issuer = iss.Certificate.Subject
		template.AuthorityKeyId = iss.Certificate.SubjectKeyId
	}

	if err := applyProfile(template, spec.Profile, spec.Request); err != nil {
		return nil, err
	}

	applyRevocationEndpoints(template, iss.Identity)

	// An otherName can only reach the certificate through an extension this
	// package encodes, and that extension carries every other name too.
	if len(spec.OtherNames) > 0 {
		for _, ext := range spec.ExtraExtensions {
			if ext.Id.Equal(oidSubjectAltNameExt) {
				return nil, &errs.Detail{
					Err:    ErrInvalidCertificate,
					Detail: "subject alternative names were supplied both as otherNames and as a pre-encoded extension",
				}
			}
		}
		ext, err := BuildSubjectAltName(
			template.Subject,
			template.DNSNames,
			template.EmailAddresses,
			template.IPAddresses,
			template.URIs,
			spec.OtherNames,
		)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ext)
	}

	template.ExtraExtensions = append(template.ExtraExtensions, spec.ExtraExtensions...)

	return template, nil
}

// Issue builds the certificate described by spec and signs it.
//
// Every CA-issued certificate in go-xkms — root, intermediate, end entity,
// TCG endorsement / attestation / device identity, ACME subscriber and
// per-tenant CA — is created here. Callers that need the DER encoding read it
// from the returned certificate's Raw field.
//
// randReader supplies randomness to the signature; pass crypto/rand.Reader
// unless a test needs determinism.
//
// Returns an error wrapping ErrSigningFailed when the signature cannot be
// produced, and ErrInvalidCertificate when the result cannot be parsed back.
func (iss *Issuer) Issue(randReader io.Reader, spec *CertificateSpec) (*x509.Certificate, error) {
	template, err := iss.Template(spec)
	if err != nil {
		return nil, err
	}

	der, err := iss.Sign(randReader, template, spec.PublicKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: fmt.Sprintf("parse issued certificate: %v", err)}
	}
	return cert, nil
}

// Sign signs a certificate template and returns its DER encoding.
//
// This is the only place go-xkms calls x509.CreateCertificate for a CA-issued
// certificate. Issue uses it, and so do the two callers that must sign the
// same template more than once and therefore cannot go through Issue: the
// Certificate Transparency pipeline, which signs a precertificate carrying a
// poison extension and then a final certificate carrying the SCT list, and the
// hybrid ML-DSA signer, which signs once to obtain a TBS to countersign and
// again to embed the countersignature.
//
// A nil publicKey certifies the issuer's own key, which is what a self-signed
// root requires.
//
// Returns ErrInvalidIssuer when the issuer has no signer, ErrInvalidCertificate
// when template is nil, and an error wrapping ErrSigningFailed when the
// signature cannot be produced.
func (iss *Issuer) Sign(randReader io.Reader, template *x509.Certificate, publicKey crypto.PublicKey) ([]byte, error) {
	if iss == nil || iss.Signer == nil {
		return nil, ErrInvalidIssuer
	}
	if template == nil {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: "certificate template required"}
	}

	// A self-signed certificate is its own parent and certifies its own key.
	parent := iss.Certificate
	if parent == nil {
		parent = template
	}
	if publicKey == nil {
		publicKey = iss.Signer.Public()
	}

	der, err := x509.CreateCertificate(randReader, template, parent, publicKey, iss.Signer)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return der, nil
}

// =============================================================================
// Profile Application
// =============================================================================

// applyProfile applies a certificate profile to a finished template.
//
// The profile is the authority on key usage, extended key usage, basic
// constraints and any profile-specific extensions (for example the PIV
// UnknownExtKeyUsage OIDs from NIST SP 800-73-4, or a CA profile's
// CRL/OCSP/AIA endpoints). It runs after the template has been populated from
// the CSR and the sign options so profile semantics are the last word on the
// fields it owns.
//
// A nil profile is a no-op: issuance without a profile is valid and leaves the
// template untouched.
//
// Returns an error wrapping ErrInvalidProfile when the profile rejects the
// template.
func applyProfile(template *x509.Certificate, profile ProfileProvider, request *CertificateRequest) error {
	if profile == nil {
		return nil
	}
	if err := profile.Apply(template, request); err != nil {
		return &errs.Joined{
			Lead:   ErrInvalidProfile,
			Detail: fmt.Sprintf("profile %q", profile.Name()),
			Cause:  err,
		}
	}
	return nil
}

// =============================================================================
// Revocation & Authority Information Access Endpoints
// =============================================================================

// applyRevocationEndpoints fills a certificate template's revocation and
// Authority Information Access endpoints from an issuing identity.
//
// Precedence, highest first:
//
//  1. Values already present on the template. A certificate profile's Apply
//     (or a value the caller pre-populated) is an explicit choice and is never
//     overwritten.
//  2. The identity's configured CRLDistributionPoints, OCSPServers and
//     IssuingCertificateURLs.
//
// Each URL list is considered independently, so a profile that sets only OCSP
// responders still inherits the identity's CRL distribution points.
//
// When neither source supplies a list the field is left empty so that no
// degenerate (empty) CRL Distribution Points or Authority Information Access
// extension is encoded into the issued certificate — a CA configured without
// revocation endpoints must keep issuing exactly the certificates it did
// before.
//
// The identity's slices are copied so that later mutation of the running
// configuration cannot alias into an issued certificate template.
func applyRevocationEndpoints(template *x509.Certificate, identity *Identity) {
	if template == nil || identity == nil {
		return
	}

	if len(template.CRLDistributionPoints) == 0 && len(identity.CRLDistributionPoints) > 0 {
		template.CRLDistributionPoints = cloneStrings(identity.CRLDistributionPoints)
	}
	if len(template.OCSPServer) == 0 && len(identity.OCSPServers) > 0 {
		template.OCSPServer = cloneStrings(identity.OCSPServers)
	}
	if len(template.IssuingCertificateURL) == 0 && len(identity.IssuingCertificateURLs) > 0 {
		template.IssuingCertificateURL = cloneStrings(identity.IssuingCertificateURLs)
	}
}

// cloneStrings returns a copy of s, or nil when s is empty.
func cloneStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// =============================================================================
// Issuance Context Reconstruction
// =============================================================================

// certificateRequestFromTemplate reconstructs the issuance context for profiles
// on the direct CSR-signing path, where the caller supplies a CSR and
// SignOptions rather than a CertificateRequest.
//
// Profiles receive the request so they can make context-sensitive decisions
// (a CA profile reads MaxPathLen, a tenant-aware profile reads TenantID). The
// template is the authoritative merge of the CSR and the sign options at this
// point, so the subject and SANs are read back from it rather than re-derived.
//
// validityDays is passed separately because the template carries absolute
// NotBefore/NotAfter timestamps rather than a day count.
func certificateRequestFromTemplate(template *x509.Certificate, opts *SignOptions, validityDays int) *CertificateRequest {
	request := &CertificateRequest{
		Subject:        subjectFromPkixName(template.Subject),
		SANS:           subjectAltNamesFromTemplate(template),
		Valid:          validityDays,
		KeyUsage:       template.KeyUsage,
		ExtKeyUsage:    template.ExtKeyUsage,
		IsCA:           template.IsCA,
		MaxPathLen:     template.MaxPathLen,
		MaxPathLenZero: template.MaxPathLenZero,
	}

	if opts != nil {
		request.Signer = opts.Signer
		request.IssuerCert = opts.IssuerCert
		request.SPIFFETrustDomain = opts.SPIFFETrustDomain
		request.TenantID = opts.TenantID
		request.SPIFFEKind = opts.SPIFFEKind
		request.SPIFFEName = opts.SPIFFEName
		request.ExtraExtensions = opts.ExtraExtensions
	}

	return request
}

// certificateRequestFromSpec reconstructs the issuance context for profiles on
// the CSR-signing path, where the caller supplies a CSR and SignOptions rather
// than a CertificateRequest.
//
// It describes the certificate as it stands immediately before Profile.Apply
// runs: the subject and subject alternative names already merged from the CSR
// and the sign options, the key usage and extended key usage the profile is
// about to overwrite, and the end-entity basic constraints a CSR starts from.
// A profile that reads the request therefore sees the same values whichever
// path invoked it.
//
// validityDays is passed separately because the spec carries absolute
// NotBefore/NotAfter timestamps rather than a day count.
func certificateRequestFromSpec(
	spec *CertificateSpec,
	opts *SignOptions,
	validityDays int,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
) *CertificateRequest {
	if spec == nil {
		return nil
	}

	request := &CertificateRequest{
		Subject:     subjectFromPkixName(spec.Subject),
		SANS:        subjectAltNamesFromSpec(spec),
		Valid:       validityDays,
		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,
	}

	if opts != nil {
		request.Signer = opts.Signer
		request.IssuerCert = opts.IssuerCert
		request.SPIFFETrustDomain = opts.SPIFFETrustDomain
		request.TenantID = opts.TenantID
		request.SPIFFEKind = opts.SPIFFEKind
		request.SPIFFEName = opts.SPIFFEName
		request.ExtraExtensions = opts.ExtraExtensions
	}

	return request
}

// subjectAltNamesFromSpec converts a spec's subject alternative names into the
// CA's SubjectAlternativeNames representation. Returns nil when the spec
// carries no names so profiles can distinguish "no SANs" from "empty SANs".
func subjectAltNamesFromSpec(spec *CertificateSpec) *SubjectAlternativeNames {
	if len(spec.DNSNames) == 0 && len(spec.EmailAddresses) == 0 &&
		len(spec.IPAddresses) == 0 && len(spec.URIs) == 0 {
		return nil
	}
	return &SubjectAlternativeNames{
		DNS:   cloneStrings(spec.DNSNames),
		Email: cloneStrings(spec.EmailAddresses),
		IPs:   ipStrings(spec.IPAddresses),
		URIs:  uriStrings(spec.URIs),
	}
}

// subjectFromPkixName converts an X.509 distinguished name into the CA's
// Subject representation. Multi-valued attributes keep their first value,
// which is the only value Subject.ToPkixName can produce.
func subjectFromPkixName(name pkix.Name) Subject {
	return Subject{
		CommonName:         name.CommonName,
		Organization:       firstOrEmpty(name.Organization),
		OrganizationalUnit: firstOrEmpty(name.OrganizationalUnit),
		Country:            firstOrEmpty(name.Country),
		Province:           firstOrEmpty(name.Province),
		Locality:           firstOrEmpty(name.Locality),
		Address:            firstOrEmpty(name.StreetAddress),
		PostalCode:         firstOrEmpty(name.PostalCode),
	}
}

// subjectAltNamesFromTemplate converts the template's SAN fields into the CA's
// SubjectAlternativeNames representation. Returns nil when the template carries
// no SANs so profiles can distinguish "no SANs" from "empty SANs".
func subjectAltNamesFromTemplate(template *x509.Certificate) *SubjectAlternativeNames {
	if len(template.DNSNames) == 0 && len(template.EmailAddresses) == 0 &&
		len(template.IPAddresses) == 0 && len(template.URIs) == 0 {
		return nil
	}
	return &SubjectAlternativeNames{
		DNS:   cloneStrings(template.DNSNames),
		Email: cloneStrings(template.EmailAddresses),
		IPs:   ipStrings(template.IPAddresses),
		URIs:  uriStrings(template.URIs),
	}
}

// firstOrEmpty returns the first element of s, or the empty string.
func firstOrEmpty(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// ipStrings renders IP addresses in their textual form.
func ipStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// uriStrings renders URIs in their textual form.
func uriStrings(uris []*url.URL) []string {
	if len(uris) == 0 {
		return nil
	}
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		if u == nil {
			continue
		}
		out = append(out, u.String())
	}
	return out
}
