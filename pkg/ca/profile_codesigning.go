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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// ProfileNameCodeSigning is the registry name of the code-signing profile.
const ProfileNameCodeSigning = "code-signing"

const (
	// codeSigningDefaultLifetime is the lifetime of a code-signing
	// certificate whose request names none.
	codeSigningDefaultLifetime = 365 * 24 * time.Hour

	// codeSigningMaxLifetime is the longest lifetime the profile issues: the
	// 460-day maximum of the CA/Browser Forum Code Signing Baseline
	// Requirements §6.3.2.
	codeSigningMaxLifetime = 460 * 24 * time.Hour
)

// Extension identifiers a code-signing CSR is checked for, RFC 5280 section
// 4.2.1, and id-kp-codeSigning, RFC 5280 section 4.2.1.12.
var (
	oidKeyUsageExt         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstraintsExt = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsageExt      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPCodeSigning       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
)

// codeSigningExtensionCheck refuses a requested extension value the
// code-signing profile does not permit.
type codeSigningExtensionCheck func(profile string, value []byte) error

// codeSigningExtensionChecks maps each extension a code-signing CSR may not
// request freely to its check. Extensions absent from the map are not copied
// from a CSR onto a certificate, so they need no check.
var codeSigningExtensionChecks = map[string]codeSigningExtensionCheck{
	oidSubjectAltNameExt.String():   refuseRequestedSubjectAltName,
	oidBasicConstraintsExt.String(): checkRequestedBasicConstraints,
	oidKeyUsageExt.String():         checkRequestedKeyUsage,
	oidExtKeyUsageExt.String():      checkRequestedExtKeyUsage,
}

// codeSigningProfile issues code-signing certificates under a constrained
// request policy.
type codeSigningProfile struct {
	baseProfile
}

// NewCodeSigningProfile creates the profile for code-signing certificates.
//
//   - Key usage: digitalSignature. Extended key usage: codeSigning.
//   - Not a CA: basic constraints asserted with cA false.
//   - Subject: exactly one common name, and no subject alternative names.
//   - Lifetime: 365 days by default, 460 days at most.
//
// A CSR is validated, never reshaped: one whose subject carries any other
// attribute, which requests subject alternative names or a CA certificate, or
// which requests a key usage or extended key usage beyond the profile's, is
// refused with its own error, as is a lifetime above the maximum.
func NewCodeSigningProfile() ProfileProvider {
	return &codeSigningProfile{
		baseProfile: baseProfile{
			name:                  ProfileNameCodeSigning,
			keyUsage:              x509.KeyUsageDigitalSignature,
			extKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			defaultValidity:       int(codeSigningDefaultLifetime / (24 * time.Hour)),
			basicConstraintsValid: true,
		},
	}
}

// DefaultLifetime implements LifetimeBoundedProfile.
func (p *codeSigningProfile) DefaultLifetime() time.Duration { return codeSigningDefaultLifetime }

// MaxLifetime implements LifetimeBoundedProfile.
func (p *codeSigningProfile) MaxLifetime() time.Duration { return codeSigningMaxLifetime }

// ValidateCSR implements CSRValidator.
func (p *codeSigningProfile) ValidateCSR(csr *x509.CertificateRequest) error {
	if err := checkCommonNameOnly(p.name, csr.RawSubject, csr.Subject); err != nil {
		return err
	}
	for _, ext := range csr.Extensions {
		if check, ok := codeSigningExtensionChecks[ext.Id.String()]; ok {
			if err := check(p.name, ext.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateTemplate implements TemplateValidator. It holds the issued
// certificate to the same subject and name rules as the request, so names the
// issuing caller adds through SignOptions are refused too.
func (p *codeSigningProfile) ValidateTemplate(template *x509.Certificate) error {
	if err := checkCommonNameOnly(p.name, template.RawSubject, template.Subject); err != nil {
		return err
	}
	names := len(template.DNSNames) + len(template.EmailAddresses) + len(template.IPAddresses) + len(template.URIs)
	if names > 0 {
		return &errs.Detail{Err: ErrSubjectAltNameNotPermitted, Detail: p.name + ": the certificate carries subject alternative names"}
	}
	for _, ext := range template.ExtraExtensions {
		if ext.Id.Equal(oidSubjectAltNameExt) {
			return &errs.Detail{Err: ErrSubjectAltNameNotPermitted, Detail: p.name + ": the certificate carries a subjectAltName extension"}
		}
	}
	return nil
}

// checkCommonNameOnly refuses a subject other than one RDN holding one
// non-empty commonName. raw, when present, is the encoded subject and wins
// over name, which is only consulted for a subject not yet encoded.
func checkCommonNameOnly(profile string, raw []byte, name pkix.Name) error {
	rdns := name.ToRDNSequence()
	if len(raw) > 0 {
		rdns = nil
		if rest, err := asn1.Unmarshal(raw, &rdns); err != nil || len(rest) > 0 {
			return &errs.Detail{Err: ErrSubjectNotCommonNameOnly, Detail: profile + ": the subject does not decode"}
		}
	}
	if len(rdns) != 1 || len(rdns[0]) != 1 || !rdns[0][0].Type.Equal(oidAttributeCommonName) {
		return &errs.Detail{Err: ErrSubjectNotCommonNameOnly, Detail: profile + ": the subject must be a single common name"}
	}
	if cn, ok := rdns[0][0].Value.(string); !ok || cn == "" {
		return &errs.Detail{Err: ErrSubjectNotCommonNameOnly, Detail: profile + ": the common name is empty"}
	}
	return nil
}

// refuseRequestedSubjectAltName refuses any requested subjectAltName.
func refuseRequestedSubjectAltName(profile string, _ []byte) error {
	return &errs.Detail{Err: ErrSubjectAltNameNotPermitted, Detail: profile + ": the CSR requests subject alternative names"}
}

// checkRequestedBasicConstraints refuses requested basic constraints that
// assert cA, or that do not decode.
func checkRequestedBasicConstraints(profile string, value []byte) error {
	var constraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	if rest, err := asn1.Unmarshal(value, &constraints); err != nil || len(rest) > 0 {
		return &errs.Detail{Err: ErrCARequestNotPermitted, Detail: profile + ": the requested basic constraints do not decode"}
	}
	if constraints.IsCA {
		return &errs.Detail{Err: ErrCARequestNotPermitted, Detail: profile + ": the CSR requests a CA certificate"}
	}
	return nil
}

// checkRequestedKeyUsage refuses a requested key usage other than
// digitalSignature alone.
func checkRequestedKeyUsage(profile string, value []byte) error {
	var bits asn1.BitString
	if rest, err := asn1.Unmarshal(value, &bits); err != nil || len(rest) > 0 {
		return &errs.Detail{Err: ErrKeyUsageNotPermitted, Detail: profile + ": the requested key usage does not decode"}
	}
	var usage x509.KeyUsage
	for i := 0; i < bits.BitLength; i++ {
		if bits.At(i) != 0 {
			usage |= 1 << uint(i)
		}
	}
	if usage != x509.KeyUsageDigitalSignature {
		return &errs.Detail{Err: ErrKeyUsageNotPermitted, Detail: profile + ": only digitalSignature may be requested"}
	}
	return nil
}

// checkRequestedExtKeyUsage refuses a requested extended key usage other
// than codeSigning alone.
func checkRequestedExtKeyUsage(profile string, value []byte) error {
	var purposes []asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(value, &purposes); err != nil || len(rest) > 0 {
		return &errs.Detail{Err: ErrExtKeyUsageNotPermitted, Detail: profile + ": the requested extended key usage does not decode"}
	}
	if len(purposes) != 1 || !purposes[0].Equal(oidKPCodeSigning) {
		return &errs.Detail{Err: ErrExtKeyUsageNotPermitted, Detail: profile + ": only codeSigning may be requested"}
	}
	return nil
}
