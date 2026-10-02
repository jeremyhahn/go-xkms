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
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

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
func (ca *CA) SignCSRRaw(ctx context.Context, csrPEM []byte, profile string, validityDays int) (*x509.Certificate, error) {
	var opts *SignOptions
	if profile != "" || validityDays > 0 {
		opts = &SignOptions{
			Profile:      profile,
			ValidityDays: validityDays,
		}
	}
	return ca.SignCSR(ctx, csrPEM, opts)
}

// SignCSRWithSPIFFE signs a CSR and optionally stamps a tenant-scoped SPIFFE
// URI SAN onto the issued certificate. When trustDomain and tenantID are both
// non-empty, the SAN spiffe://<trustDomain>/tenant/<tenantID>/<kind>/<name> is
// appended (kind defaults to "user", name defaults to the subject CN). When
// either is empty, this is identical to SignCSRRaw.
//
// This satisfies the provider.CA interface so pkg/xkms can request SPIFFE-bound
// certificates without importing ca types.
//
// Thread-safe: Yes
func (ca *CA) SignCSRWithSPIFFE(ctx context.Context, csrPEM []byte, profile string, validityDays int, trustDomain, tenantID, kind, name string) (*x509.Certificate, error) {
	opts := &SignOptions{
		Profile:           profile,
		ValidityDays:      validityDays,
		SPIFFETrustDomain: trustDomain,
		TenantID:          tenantID,
		SPIFFEKind:        kind,
		SPIFFEName:        name,
	}
	return ca.SignCSR(ctx, csrPEM, opts)
}

// IssueCertificateRaw issues a certificate using only primitive parameter types,
// enabling cross-package duck typing without importing ca types.
//
// sans entries use prefix notation: "DNS:example.com", "IP:1.2.3.4",
// "Email:user@example.com", "URI:https://example.com". Entries without
// a recognized prefix are treated as DNS names.
//
// tenantID ("" for the system/platform scope) is recorded as the issued
// certificate's owning tenant, exactly as SignCSRWithSPIFFE's tenantID is
// for a CSR-signed certificate (both route through signCSR, the single
// recording site); CertificateTenant reads it back for RevokeCertificate's
// ownership check (go-xkms#1229).
//
// Returns the issued certificate PEM, chain PEM, private key PEM (if generated),
// and the hex-encoded serial number.
//
// Thread-safe: Yes
func (ca *CA) IssueCertificateRaw(
	ctx context.Context,
	commonName, organization string,
	sans []string,
	validityDays int,
	profile, algorithm, tenantID string,
) (certPEM, chainPEM, keyPEM []byte, serialHex string, err error) {

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
		Valid:    validityDays,
		TenantID: tenantID,
	}

	// Parse SANs from prefix notation into structured form.
	if len(sans) > 0 {
		sanStruct := parseSANStrings(sans)
		request.SANS = sanStruct
	}

	issued, err := ca.IssueCertificateWithProfile(ctx, request, profile)
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
func (ca *CA) IssueEKCertificateRaw(ctx context.Context, commonName, organization string, ekPubDER []byte) (certDER []byte, err error) {
	pubKey, err := x509.ParsePKIXPublicKey(ekPubDER)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "parse EK public key", Err: err}
	}

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
	}

	cert, err := ca.IssueEKCertificate(ctx, request, pubKey)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}

// IssueAKCertificateRaw issues an AK certificate using primitive types.
// pubDER is DER-encoded public key bytes.
// Thread-safe: Yes
func (ca *CA) IssueAKCertificateRaw(ctx context.Context, commonName, organization string, pubDER []byte) (certDER []byte, err error) {
	pubKey, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "parse AK public key", Err: err}
	}

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
	}

	cert, err := ca.IssueAKCertificate(ctx, request, pubKey)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}

// SignTCGCSRIDevIDRaw signs a packed TCG-CSR-IDEVID using primitive types.
// packedCSR is the binary-marshalled TCG_CSR_IDEVID bytes.
// Returns IAK cert DER and IDevID cert DER.
// Thread-safe: Yes
func (ca *CA) SignTCGCSRIDevIDRaw(ctx context.Context, commonName, organization string, packedCSR []byte) (iakDER, idevidDER []byte, err error) {
	// Unmarshal the packed bytes into a TCG_CSR_IDEVID structure.
	tcgCSR, err := tpm2.UnmarshalIDevIDCSR(packedCSR)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "unmarshal TCG CSR", Err: err}
	}

	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
	}

	return ca.SignTCGCSRIDevID(ctx, tcgCSR, request)
}

// EnrollDeviceRaw performs TCG device enrollment using primitive types.
// packedCSR is the binary-packed TCG_CSR_IDEVID bytes.
// Thread-safe: Yes
func (ca *CA) EnrollDeviceRaw(ctx context.Context, commonName, organization string, packedCSR []byte) (
	iakDER, idevidDER, credBlob, encSecret, plainSecret []byte, err error,
) {
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   commonName,
			Organization: organization,
		},
	}

	result, err := ca.EnrollDevice(ctx, packedCSR, request)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return result.IAKCertDER, result.IDevIDCertDER, result.CredentialBlob, result.EncryptedSecret, result.PlainSecret, nil
}

// IssueLAKCertificateRaw issues a Local Attestation Key certificate using
// primitive types (go-xkms#715). See provider.TCGCA.IssueLAKCertificateRaw.
// Thread-safe: Yes
func (ca *CA) IssueLAKCertificateRaw(
	ctx context.Context,
	tpmManufacturer, tpmModel, tpmFirmwareVersion string,
	iakCertDER []byte,
	certifyInfo, signature []byte,
	signatureAlgorithm x509.SignatureAlgorithm,
	lakPublicArea, nonce []byte,
) (certDER []byte, err error) {
	iakCert, err := x509.ParseCertificate(iakCertDER)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "parse IAK certificate", Err: err}
	}

	request := &CertificateRequest{
		TPMManufacturer:    tpmManufacturer,
		TPMModel:           tpmModel,
		TPMFirmwareVersion: tpmFirmwareVersion,
	}

	evidence := &LAKCertificationEvidence{
		CertifyInfo:        certifyInfo,
		Signature:          signature,
		SignatureAlgorithm: signatureAlgorithm,
		IAKCertificate:     iakCert,
		LAKPublicArea:      lakPublicArea,
		Nonce:              nonce,
	}

	cert, err := ca.IssueLAKCertificate(ctx, request, evidence)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}
