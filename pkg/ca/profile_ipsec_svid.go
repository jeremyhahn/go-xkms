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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

// Registry names of the overlay-identity profiles.
const (
	// ProfileNameIPsecVTEP is the profile of an IKEv2 tunnel endpoint
	// certificate (RFC 4945, RFC 7296).
	ProfileNameIPsecVTEP = "ipsec-vtep"

	// ProfileNameX509SVID is the profile of a SPIFFE X.509-SVID leaf.
	ProfileNameX509SVID = "x509-svid"
)

// OIDIPsecIKE is id-kp-ipsecIKE (1.3.6.1.5.5.7.3.17, RFC 4945 §5.1.3.12),
// the extended key usage of an IKE peer certificate. crypto/x509 has no
// ExtKeyUsage constant for it, so it travels in UnknownExtKeyUsage.
var OIDIPsecIKE = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 17}

// Lifetimes of the overlay-identity profiles.
const (
	ipsecVTEPDefaultLifetime = 30 * 24 * time.Hour
	ipsecVTEPMaxLifetime     = 90 * 24 * time.Hour
	x509SVIDDefaultLifetime  = time.Hour
	x509SVIDMaxLifetime      = 24 * time.Hour
)

// keyPolicy describes the public keys a profile certifies.
type keyPolicy struct {
	curves     map[elliptic.Curve]bool
	minRSABits int
	ed25519    bool
}

// check refuses a key outside the policy.
func (k keyPolicy) check(profile string, pub crypto.PublicKey) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if k.curves[key.Curve] {
			return nil
		}
		return &errs.Detail{Err: ErrUnsupportedProfileKey, Detail: profile + ": ECDSA curve " + key.Curve.Params().Name}
	case *rsa.PublicKey:
		if k.minRSABits > 0 && key.N.BitLen() >= k.minRSABits {
			return nil
		}
		return &errs.Detail{Err: ErrUnsupportedProfileKey, Detail: profile + ": RSA-" + strconv.Itoa(key.N.BitLen()) + " is below RSA-" + strconv.Itoa(k.minRSABits)}
	case ed25519.PublicKey:
		if k.ed25519 {
			return nil
		}
		return &errs.Detail{Err: ErrUnsupportedProfileKey, Detail: profile + ": Ed25519"}
	case nil:
		return &errs.Detail{Err: ErrUnsupportedProfileKey, Detail: profile + ": no public key"}
	default:
		return &errs.Detail{Err: ErrUnsupportedProfileKey, Detail: profile + ": unsupported key type"}
	}
}

// =============================================================================
// ipsec-vtep
// =============================================================================

// ipsecVTEPProfile issues IKEv2 peer certificates for overlay tunnel
// endpoints.
type ipsecVTEPProfile struct {
	baseProfile
	keys keyPolicy
}

// NewIPsecVTEPProfile creates the profile of an IKEv2 tunnel-endpoint
// certificate.
//
//   - Not a CA: basic constraints asserted with cA false.
//   - Key usage: digitalSignature (RFC 4945 §5.1.3.2).
//   - Extended key usage: id-kp-ipsecIKE only (RFC 4945 §5.1.3.12). A relying
//     party verifying it with crypto/x509 must pass ExtKeyUsageAny, because
//     Go's default extended-key-usage check requires serverAuth.
//   - Names: taken only from the issuing caller, never from the CSR. At least
//     one IP address is required (the endpoint's IKE identity); DNS names are
//     allowed; URI and email names are refused.
//   - Keys: ECDSA P-256 or P-384, or RSA of at least 3072 bits (RFC 8247 §3).
//     Ed25519 is refused: strongSwan reaches the key through PKCS#11, whose
//     EdDSA support the tunnel deployment does not rely on.
//   - Lifetime: 30 days by default, 90 days at most.
//   - An optional tp-attestationEvidence extension (OIDAttestationEvidence),
//     supplied by the caller through SignOptions.ExtraExtensions, must decode
//     and must appear at most once.
//
// The profile is meant to be issued under a subordinate CA whose name
// constraints confine it to the fabric's address ranges (IssueSubordinateCA).
func NewIPsecVTEPProfile() ProfileProvider {
	return &ipsecVTEPProfile{
		baseProfile: baseProfile{
			name:                  ProfileNameIPsecVTEP,
			keyUsage:              x509.KeyUsageDigitalSignature,
			defaultValidity:       int(ipsecVTEPDefaultLifetime / (24 * time.Hour)),
			basicConstraintsValid: true,
			unknownExtKeyUsage:    []asn1.ObjectIdentifier{OIDIPsecIKE},
		},
		keys: keyPolicy{
			curves:     map[elliptic.Curve]bool{elliptic.P256(): true, elliptic.P384(): true},
			minRSABits: 3072,
		},
	}
}

// CallerSuppliedSANs implements CallerSANProfile.
func (p *ipsecVTEPProfile) CallerSuppliedSANs() bool { return true }

// DefaultLifetime implements LifetimeBoundedProfile.
func (p *ipsecVTEPProfile) DefaultLifetime() time.Duration { return ipsecVTEPDefaultLifetime }

// MaxLifetime implements LifetimeBoundedProfile.
func (p *ipsecVTEPProfile) MaxLifetime() time.Duration { return ipsecVTEPMaxLifetime }

// Apply implements ProfileProvider.
func (p *ipsecVTEPProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if err := p.baseProfile.Apply(template, request); err != nil {
		return err
	}
	template.IsCA = false
	return nil
}

// ValidateTemplate implements TemplateValidator.
func (p *ipsecVTEPProfile) ValidateTemplate(template *x509.Certificate) error {
	if len(template.IPAddresses) == 0 {
		return &errs.Detail{Err: ErrInvalidSAN, Detail: p.name + ": at least one IP address is required"}
	}
	if len(template.URIs) > 0 || len(template.EmailAddresses) > 0 {
		return &errs.Detail{Err: ErrInvalidSAN, Detail: p.name + ": URI and email names are not permitted"}
	}
	if err := p.keys.check(p.name, template.PublicKey); err != nil {
		return err
	}
	if _, _, err := parseAttestationEvidence(template.ExtraExtensions); err != nil {
		return err
	}
	return nil
}

// =============================================================================
// x509-svid
// =============================================================================

// x509SVIDProfile issues SPIFFE X.509-SVID leaf certificates.
type x509SVIDProfile struct {
	baseProfile
	keys keyPolicy
}

// NewX509SVIDProfile creates the profile of a SPIFFE X.509-SVID leaf
// (SPIFFE X.509-SVID specification §4 and §5).
//
//   - Not a CA: basic constraints asserted with cA false (§4.1).
//   - Key usage: digitalSignature, plus keyEncipherment for an RSA key; never
//     keyCertSign or cRLSign (§4.3).
//   - Extended key usage: serverAuth and clientAuth (§4.4).
//   - Names: taken only from the issuing caller, never from the CSR. Exactly
//     one URI SAN, which must be a valid SPIFFE ID (§2) whose trust domain
//     is the tenant, the subject's OU[0] (spiffe://<tenant>/...); DNS names
//     are allowed; IP and email names are refused.
//   - Keys: ECDSA P-256/P-384/P-521, RSA of at least 2048 bits, or Ed25519.
//   - Lifetime: 1 hour by default, 24 hours at most.
//
// Issue it under a subordinate CA whose PermittedURIDomains names the
// tenant's trust domain, so each tenant's bundle is its own CA. That
// constraint binds only the trust domain; scoping an issuer to a path such as
// /svc/ is the issuing caller's policy.
func NewX509SVIDProfile() ProfileProvider {
	return &x509SVIDProfile{
		baseProfile: baseProfile{
			name:                  ProfileNameX509SVID,
			keyUsage:              x509.KeyUsageDigitalSignature,
			extKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			defaultValidity:       1,
			basicConstraintsValid: true,
		},
		keys: keyPolicy{
			curves:     map[elliptic.Curve]bool{elliptic.P256(): true, elliptic.P384(): true, elliptic.P521(): true},
			minRSABits: 2048,
			ed25519:    true,
		},
	}
}

// CallerSuppliedSANs implements CallerSANProfile.
func (p *x509SVIDProfile) CallerSuppliedSANs() bool { return true }

// DefaultLifetime implements LifetimeBoundedProfile.
func (p *x509SVIDProfile) DefaultLifetime() time.Duration { return x509SVIDDefaultLifetime }

// MaxLifetime implements LifetimeBoundedProfile.
func (p *x509SVIDProfile) MaxLifetime() time.Duration { return x509SVIDMaxLifetime }

// Apply implements ProfileProvider.
func (p *x509SVIDProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if err := p.baseProfile.Apply(template, request); err != nil {
		return err
	}
	template.IsCA = false
	if _, isRSA := template.PublicKey.(*rsa.PublicKey); isRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	return nil
}

// ValidateTemplate implements TemplateValidator.
func (p *x509SVIDProfile) ValidateTemplate(template *x509.Certificate) error {
	if len(template.URIs) != 1 {
		return &errs.Detail{Err: ErrInvalidSAN, Detail: p.name + ": exactly one URI SAN is required, got " + strconv.Itoa(len(template.URIs))}
	}
	id, err := spiffe.WorkloadIDFromURL(template.URIs[0])
	if err != nil {
		return &errs.Joined{Lead: ErrInvalidSAN, Detail: p.name + ": URI SAN is not a SPIFFE ID", Cause: err}
	}
	if id.TrustDomain().Name() != firstOrEmpty(template.Subject.OrganizationalUnit) {
		return &errs.Detail{Err: ErrInvalidSAN, Detail: p.name + ": the SPIFFE trust domain must be the tenant (subject OU[0])"}
	}
	if len(template.IPAddresses) > 0 || len(template.EmailAddresses) > 0 {
		return &errs.Detail{Err: ErrInvalidSAN, Detail: p.name + ": IP and email names are not permitted"}
	}
	return p.keys.check(p.name, template.PublicKey)
}
