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

package xkms

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
)

// CA attestation errors.
var (
	// ErrAttestationRequired is returned when the server requires attestation
	// but the client did not provide it.
	ErrAttestationRequired = errors.New("ca: attestation required for CSR signing")

	// ErrAttestationVerificationFailed is returned when the attestation proof
	// fails verification.
	ErrAttestationVerificationFailed = errors.New("ca: attestation verification failed")

	// ErrCSRSigningDenied is returned when the caller does not have permission
	// to sign CSRs.
	ErrCSRSigningDenied = errors.New("ca: CSR signing denied (insufficient permissions)")

	// ErrAttestationNotConfigured is returned when a CSR carries an attestation
	// but the server has no attestation trust anchors wired at all. The request
	// is refused rather than admitted: without an anchor the caller-supplied
	// chain proves nothing, so accepting it would silently downgrade the
	// hardware-attestation gate to a no-op.
	ErrAttestationNotConfigured = errors.New("ca: attestation trust anchors not configured")

	// ErrAttestationFormatNotConfigured is returned when a CSR requests an
	// attestation format for which no trust anchors are configured. It prevents
	// a caller from selecting an unanchored format to bypass the gate.
	ErrAttestationFormatNotConfigured = errors.New("ca: no attestation trust anchors configured for format")

	// ErrAttestationVerifierInvalid is returned when a verifier offered to
	// SetAttestationVerifiers cannot enforce anchoring.
	ErrAttestationVerifierInvalid = errors.New("ca: invalid attestation verifier")
)

// getCA returns the typed CA provider. Returns ErrNotConfigured if no CA is wired.
func (s *XKMSService) getCA() (provider.CA, error) {
	if s.ca == nil {
		return nil, ErrNotConfigured
	}
	return s.ca, nil
}

// GetCABundle retrieves the CA certificate bundle.
func (s *XKMSService) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	bundlePEM, err := ca.CABundle()
	if err != nil {
		return nil, &ErrCAOperation{Operation: "get bundle", Err: err}
	}

	// Parse individual DER certificates from PEM bundle.
	var certs [][]byte
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}

	return &transport.GetCABundleResponse{
		BundlePEM:    bundlePEM,
		Certificates: certs,
		ContentType:  "application/x-pem-file",
	}, nil
}

// GetCACertificate retrieves the CA certificate.
func (s *XKMSService) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	cert, err := ca.CACertificate()
	if err != nil {
		return nil, &ErrCAOperation{Operation: "get certificate", Err: err}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return &transport.GetCACertificateResponse{
		CertificatePEM: certPEM,
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.Text(16),
		NotBefore:      cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:       cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		IsCA:           cert.IsCA,
	}, nil
}

// SignCSR signs a certificate signing request using the CA.
func (s *XKMSService) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if len(req.CSRPEM) == 0 {
		return nil, ErrNilData
	}

	// RBAC: check that the caller has permission to sign CSRs.
	// Local calls (no identity in context) are allowed — they come from
	// the GUI or CLI running on the same machine.
	if identity := auth.GetIdentity(ctx); identity != nil {
		if !identity.HasRole("admin") && !identity.HasRole("user") && !identity.HasRole("operator") {
			slog.Warn("CSR signing denied", "subject", identity.Subject)
			return nil, ErrCSRSigningDenied
		}
	}

	// Verify attestation if provided. When the server requires attestation
	// (future config flag), missing attestation will be rejected.
	if req.AttestationFormat != "" {
		if err := s.verifyCSRAttestation(req); err != nil {
			return nil, err
		}
	}

	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	// When a trust domain is configured and the request carries a tenant, the
	// issued client certificate is stamped with a tenant-scoped SPIFFE SAN so
	// login can derive the tenant from the verified peer certificate. The
	// SPIFFE kind defaults to "user" and the name defaults to the CSR subject
	// CommonName (resolved inside the CA).
	cert, err := ca.SignCSRWithSPIFFE(ctx, req.CSRPEM, req.Profile, req.ValidityDays, s.SPIFFETrustDomain(), req.TenantID, "", "")
	if err != nil {
		return nil, &ErrCAOperation{Operation: "sign csr", Err: err}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Get CA certificate for chain.
	var chainPEM []byte
	if caCert, caErr := ca.CACertificate(); caErr == nil {
		chainPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})
	}

	return &transport.SignCSRResponse{
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
		SerialNumber:   cert.SerialNumber.Text(16),
	}, nil
}

// SetAttestationVerifiers wires the per-format hardware-attestation verifiers
// used to verify attestation chains presented with a CSR. Keys are attestation
// format identifiers as they appear on the wire ("tpm2", "yubikey-piv"); they
// are normalized to lower case.
//
// Each verifier must carry at least one trust anchor. A verifier with no
// anchors cannot establish hardware provenance, so it is rejected here rather
// than stored — a misconfiguration must never downgrade the attestation gate to
// accepting a caller-minted chain. Formats with no configured verifier are
// refused at the gate; passing a nil or empty map leaves attestation-gated CSR
// signing failing closed.
func (s *XKMSService) SetAttestationVerifiers(verifiers map[string]*attestation.Verifier) error {
	normalized := make(map[string]*attestation.Verifier, len(verifiers))
	for format, verifier := range verifiers {
		key := normalizeAttestationFormat(format)
		if key == "" {
			return &errs.Detail{Err: ErrAttestationVerifierInvalid, Detail: "empty attestation format"}
		}
		if verifier == nil {
			return &errs.Detail{Err: ErrAttestationVerifierInvalid, Detail: "nil verifier for format " + key}
		}
		if verifier.TrustAnchorCount() == 0 {
			return &errs.Detail{Err: ErrAttestationVerifierInvalid, Detail: "no trust anchors for format " + key}
		}
		normalized[key] = verifier
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestationVerifiers = normalized
	return nil
}

// AttestationFormats returns the attestation formats that have trust anchors
// configured, in no particular order.
func (s *XKMSService) AttestationFormats() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	formats := make([]string, 0, len(s.attestationVerifiers))
	for format := range s.attestationVerifiers {
		formats = append(formats, format)
	}
	return formats
}

// attestationVerifierFor resolves the verifier registered for an attestation
// format. The boolean result is false when no verifier is configured for the
// format, in which case the caller must fail closed.
func (s *XKMSService) attestationVerifierFor(format string) (*attestation.Verifier, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	verifier, ok := s.attestationVerifiers[normalizeAttestationFormat(format)]
	return verifier, ok
}

// normalizeAttestationFormat canonicalizes a wire-supplied attestation format
// identifier so lookups are case- and whitespace-insensitive.
func normalizeAttestationFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

// verifyCSRAttestation verifies the attestation proof included in a CSR
// signing request. This proves the CSR's private key is stored in hardware.
//
// The attestation chain is caller-supplied and is therefore trusted only to the
// extent that it terminates at a trust anchor the operator configured for the
// requested format. The chain is ordered leaf-first and its shape is
// format-specific:
//
//	YubiKey PIV ("yubikey-piv"):
//	  certs[0] = slot attestation cert (signed by the f9 attestation cert)
//	  certs[1] = f9 attestation cert (signed by the Yubico PIV Root CA)
//	  anchor   = Yubico PIV Root CA
//
//	TPM 2.0 ("tpm2"):
//	  certs[0] = AK/IAK cert
//	  certs[1] = EK cert (signed by the TPM manufacturer CA)
//	  anchor   = TPM manufacturer root
//
// Anchors are registered per format, so a Yubico anchor can never validate a
// TPM chain and vice versa. Verification fails closed: a request whose format
// has no configured anchors is refused, never admitted.
func (s *XKMSService) verifyCSRAttestation(req *transport.SignCSRRequest) error {
	verifier, ok := s.attestationVerifierFor(req.AttestationFormat)
	if !ok {
		format := normalizeAttestationFormat(req.AttestationFormat)
		if len(s.AttestationFormats()) == 0 {
			slog.Warn("CSR attestation refused: no attestation trust anchors configured",
				"format", format)
			return &errs.Detail{Err: ErrAttestationNotConfigured, Detail: "format " + format}
		}
		slog.Warn("CSR attestation refused: unconfigured attestation format",
			"format", format)
		return &errs.Detail{Err: ErrAttestationFormatNotConfigured, Detail: format}
	}

	if len(req.AttestationChain) == 0 {
		return &errs.Detail{Err: ErrAttestationVerificationFailed, Detail: "empty attestation chain"}
	}

	// Parse the caller-supplied attestation certificate chain.
	certs := make([]*x509.Certificate, 0, len(req.AttestationChain))
	for i, der := range req.AttestationChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return &errs.Detail{Err: ErrAttestationVerificationFailed, Detail: fmt.Sprintf("invalid certificate at index %d: %v", i, err)}
		}
		certs = append(certs, cert)
	}

	stmt := &attestation.AttestationStatement{
		Format:           normalizeAttestationFormat(req.AttestationFormat),
		CertificateChain: certs,
	}

	// VerifyChainAnchored performs structural validation (each certificate
	// signed by the next, none expired) and X.509 path validation terminating
	// at a configured anchor. It returns ErrNoTrustAnchors rather than passing
	// when the verifier holds no anchors.
	if err := verifier.VerifyChainAnchored(stmt, &attestation.VerifyOptions{}); err != nil {
		slog.Warn("attestation chain verification failed",
			"format", stmt.Format,
			"chain_length", len(certs),
			"leaf_subject", certs[0].Subject,
			"error", err)
		return &errs.Detail{Err: ErrAttestationVerificationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	// Chain anchoring establishes provenance and nothing more: that some
	// hardware exists somewhere, not that it holds the key being certified,
	// nor that the evidence was produced for this request. Those are the
	// invariants, applied through each format's own mechanism.
	if err := s.enforceAttestationInvariants(stmt.Format, req, certs[0]); err != nil {
		return err
	}

	// Deployment policy on top of the invariants. Android evidence carries
	// claims no other format expresses -- verified boot state, bootloader
	// lock, the calling application -- so it has its own gate.
	if stmt.Format == AttestationFormatAndroidKey {
		if err := s.verifyAndroidCSRAttestation(req); err != nil {
			return err
		}
	}

	slog.Info("attestation verified",
		"format", stmt.Format,
		"chain_length", len(certs),
		"leaf_subject", certs[0].Subject)

	return nil
}

// IssueCertificate issues a new certificate from the CA.
func (s *XKMSService) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.CommonName == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "common name required"}
	}

	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	certPEM, chainPEM, keyPEM, serialHex, err := ca.IssueCertificateRaw(
		ctx,
		req.CommonName,
		req.Organization,
		req.SANs,
		req.ValidityDays,
		req.Profile,
		req.Algorithm,
	)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "issue certificate", Err: err}
	}

	return &transport.IssueCertificateResponse{
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
		PrivateKeyPEM:  keyPEM,
		SerialNumber:   serialHex,
	}, nil
}

// RevokeCertificate revokes a certificate by serial number.
func (s *XKMSService) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.SerialNumber == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "serial number required"}
	}

	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	serial, err := parseSerialHex(req.SerialNumber)
	if err != nil {
		return nil, err
	}

	if err := ca.Revoke(ctx, serial, req.Reason); err != nil {
		return nil, &ErrCAOperation{Operation: "revoke", Err: err}
	}

	return &transport.RevokeCertificateResponse{
		Success: true,
		Message: fmt.Sprintf("certificate %s revoked", req.SerialNumber),
	}, nil
}

// GenerateCRL generates a certificate revocation list.
func (s *XKMSService) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	crlDER, err := ca.GenerateCRL(ctx)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "generate crl", Err: err}
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	return &transport.GenerateCRLResponse{
		CRLPEM: crlPEM,
	}, nil
}

// IsRevoked checks whether a certificate has been revoked.
func (s *XKMSService) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.SerialNumber == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "serial number required"}
	}

	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	serial, err := parseSerialHex(req.SerialNumber)
	if err != nil {
		return nil, err
	}

	revoked, err := ca.IsRevoked(serial)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "is revoked", Err: err}
	}

	resp := &transport.IsRevokedResponse{
		Revoked: revoked,
	}
	if revoked {
		resp.Message = "certificate is revoked"
	} else {
		resp.Message = "certificate is not revoked"
	}

	return resp, nil
}

// parseSerialHex parses a hex serial number string, stripping optional 0x/0X prefix.
func parseSerialHex(s string) (*big.Int, error) {
	serialStr := strings.TrimPrefix(s, "0x")
	serialStr = strings.TrimPrefix(serialStr, "0X")
	serial := new(big.Int)
	if _, ok := serial.SetString(serialStr, 16); !ok {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "invalid serial number format"}
	}
	return serial, nil
}
