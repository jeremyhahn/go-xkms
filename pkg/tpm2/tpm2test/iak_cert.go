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

package tpm2test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// ProvisionIAKCertificate installs a throwaway IAK certificate on tpm, in the
// WebAuthn Level 2 section 8.3.1 shape a "tpm" attestation statement's x5c[0]
// must have: an empty subject, a subjectAltName naming the TPM's
// manufacturer, model and version and carrying the RFC 4043
// permanentIdentifier (the SHA-256 of the IAK's public key) that is the
// device identity a device-attest-01 order names, tcg-kp-AIKCertificate, and not a CA. It is
// signed by an unrelated one-off key, as a manufacturer-issued EK certificate
// is, and stands in for the certificate an attestation CA issues a real
// device.
//
// This is development and testing tooling only: a device-attest-01 statement
// (pkg/acme/challenges/device-attest-01.Setup) requires tpm.IAKCertificate()
// to resolve, and neither the in-process TPM simulator nor swtpm ever have a
// CA-issued one. It is idempotent in the sense that it always installs a
// fresh certificate; callers that already provisioned one and want to keep it
// should not call this again.
func ProvisionIAKCertificate(tpm pkgtpm2.TrustedPlatformModule) error {
	iak, err := tpm.IAK()
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to read IAK public key", Err: err}
	}
	props, err := tpm.FixedProperties()
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to read TPM fixed properties", Err: err}
	}
	spki, err := x509.MarshalPKIXPublicKey(iak)
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to encode IAK public key", Err: err}
	}
	digest := sha256.Sum256(spki)
	permanentID, err := ca.MarshalPermanentIdentifier(hex.EncodeToString(digest[:]), nil)
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to encode IAK permanent identifier", Err: err}
	}
	san, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil, []ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: permanentID}}, []pkix.Name{{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: ca.OIDTCGAttributeTPMManufacturer, Value: props.ManufacturerCode},
			{Type: ca.OIDTCGAttributeTPMModel, Value: "xkms-simulator"},
			{Type: ca.OIDTCGAttributeTPMVersion, Value: fmt.Sprintf("id:%04X%04X", props.FwMajor, props.FwMinor)},
		},
	}})
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to build IAK certificate subject alt name", Err: err}
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to generate IAK certificate issuer key", Err: err}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to generate IAK certificate serial", Err: err}
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ca.OIDTCGKpAIKCertificate},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{san},
	}
	issuer := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "xkms-simulator-aik-ca"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, iak, signer)
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to create IAK certificate", Err: err}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to parse IAK certificate", Err: err}
	}
	if err := tpm.ProvisionIAKCert(cert); err != nil {
		return &errs.Wrapped{Msg: "tpm2test: failed to provision IAK certificate", Err: err}
	}
	return nil
}
