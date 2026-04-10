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

package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// Compile-time assertions: *CA satisfies both provider.CA and provider.TCGCA.
var (
	_ provider.CA    = (*CA)(nil)
	_ provider.TCGCA = (*CA)(nil)
)

// SignCSRRaw signs a CSR using only primitive parameter types. This method
// satisfies the provider.CA interface, enabling pkg/xkms/servicer_ca.go to
// call CA methods via the typed provider.CA interface without importing
// ca types (breaking the import cycle between pkg/xkms and pkg/ca).
//
// If profile and validityDays are both zero-values, CA defaults are used.
//
// Thread-safe: Yes
func (ca *CA) SignCSRRaw(csrPEM []byte, profile string, validityDays int) (*x509.Certificate, error) {
	var opts *SignOptions
	if profile != "" || validityDays > 0 {
		opts = &SignOptions{
			Profile:      profile,
			ValidityDays: validityDays,
		}
	}
	return ca.SignCSR(csrPEM, opts)
}

// IssueCertificateRaw issues a certificate using only primitive parameter types,
// enabling cross-package duck typing without importing ca types.
//
// sans entries use prefix notation: "DNS:example.com", "IP:1.2.3.4",
// "Email:user@example.com", "URI:https://example.com". Entries without
// a recognized prefix are treated as DNS names.
//
// Returns the issued certificate PEM, chain PEM, private key PEM (if generated),
// and the hex-encoded serial number.
//
// Thread-safe: Yes
func (ca *CA) IssueCertificateRaw(
	commonName, organization string,
	sans []string,
	validityDays int,
	profile, algorithm string,
) (certPEM, chainPEM, keyPEM []byte, serialHex string, err error) {

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
		Valid: validityDays,
	}

	// Parse SANs from prefix notation into structured form.
	if len(sans) > 0 {
		sanStruct := parseSANStrings(sans)
		request.SANS = sanStruct
	}

	issued, err := ca.IssueCertificateWithProfile(request, profile)
	if err != nil {
		return nil, nil, nil, "", err
	}

	// Build chain PEM from CA certificate PEM (the CA bundle).
	chain := issued.CACertificatePEM
	if len(chain) == 0 {
		chain = issued.ChainPEM
	}

	serial := ""
	if issued.SerialNumber != nil {
		serial = issued.SerialNumber.Text(16)
	}

	return issued.CertificatePEM, chain, issued.PrivateKeyPEM, serial, nil
}

// parseSANStrings parses SAN entries from prefix notation into a
// SubjectAlternativeNames struct. Supported prefixes: DNS:, IP:, Email:, URI:.
// Entries without a prefix are classified as DNS names if they don't parse
// as IP addresses.
func parseSANStrings(sans []string) *SubjectAlternativeNames {
	s := &SubjectAlternativeNames{}

	for _, san := range sans {
		switch {
		case strings.HasPrefix(san, "DNS:"):
			s.DNS = append(s.DNS, strings.TrimPrefix(san, "DNS:"))
		case strings.HasPrefix(san, "IP:"):
			s.IPs = append(s.IPs, strings.TrimPrefix(san, "IP:"))
		case strings.HasPrefix(san, "Email:"):
			s.Email = append(s.Email, strings.TrimPrefix(san, "Email:"))
		case strings.HasPrefix(san, "URI:"):
			s.URIs = append(s.URIs, strings.TrimPrefix(san, "URI:"))
		default:
			// No prefix: if it parses as IP, use as IP; otherwise DNS.
			if ip := net.ParseIP(san); ip != nil {
				s.IPs = append(s.IPs, san)
			} else {
				s.DNS = append(s.DNS, san)
			}
		}
	}

	return s
}

// GetCACertificatePEM returns the CA certificate in PEM-encoded format.
// This is a convenience method for service layer callers that need PEM
// without importing ca types.
//
// Thread-safe: Yes
func (ca *CA) GetCACertificatePEM() ([]byte, error) {
	cert, err := ca.CACertificate()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}), nil
}

// IssueEKCertificateRaw issues an EK certificate using primitive types.
// ekPubDER is DER-encoded public key bytes.
// Thread-safe: Yes
func (ca *CA) IssueEKCertificateRaw(commonName, organization string, ekPubDER []byte) (certDER []byte, err error) {
	pubKey, err := x509.ParsePKIXPublicKey(ekPubDER)
	if err != nil {
		return nil, fmt.Errorf("parse EK public key: %w", err)
	}

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
	}

	cert, err := ca.IssueEKCertificate(request, pubKey)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}

// IssueAKCertificateRaw issues an AK certificate using primitive types.
// pubDER is DER-encoded public key bytes.
// Thread-safe: Yes
func (ca *CA) IssueAKCertificateRaw(commonName, organization string, pubDER []byte) (certDER []byte, err error) {
	pubKey, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, fmt.Errorf("parse AK public key: %w", err)
	}

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
	}

	cert, err := ca.IssueAKCertificate(request, pubKey)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}

// SignTCGCSRIDevIDRaw signs a packed TCG-CSR-IDEVID using primitive types.
// packedCSR is the binary-marshalled TCG_CSR_IDEVID bytes.
// Returns IAK cert DER and IDevID cert DER.
// Thread-safe: Yes
func (ca *CA) SignTCGCSRIDevIDRaw(commonName, organization string, packedCSR []byte) (iakDER, idevidDER []byte, err error) {
	// Unmarshal the packed bytes into a TCG_CSR_IDEVID structure.
	tcgCSR, err := tpm2.UnmarshalIDevIDCSR(packedCSR)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal TCG CSR: %w", err)
	}

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
	}

	return ca.SignTCGCSRIDevID(tcgCSR, request)
}

// EnrollDeviceRaw performs TCG device enrollment using primitive types.
// packedCSR is the binary-packed TCG_CSR_IDEVID bytes.
// Thread-safe: Yes
func (ca *CA) EnrollDeviceRaw(commonName, organization string, packedCSR []byte) (
	iakDER, idevidDER, credBlob, encSecret, plainSecret []byte, err error,
) {
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
	}

	result, err := ca.EnrollDevice(packedCSR, request)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return result.IAKCertDER, result.IDevIDCertDER, result.CredentialBlob, result.EncryptedSecret, result.PlainSecret, nil
}
