// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package issuance

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// Config contains configuration for the issuer.
type Config struct {
	// Signer provides certificate signing operations.
	Signer CertificateSigner

	// IssuerChain is the certificate chain from the issuing CA up to (but not
	// including) the root CA. This chain is used for CT log submission and may
	// be included in certificate responses per RFC 8555 Section 7.4.2.
	// If nil or empty, only the immediate issuer certificate is used.
	// The certificates should be ordered from issuer to root (issuer first).
	IssuerChain []*x509.Certificate

	// KeyValidator validates public keys.
	KeyValidator KeyValidator

	// Linter validates certificates.
	Linter CertificateLinter

	// CTSubmitter submits precerts to CT logs.
	CTSubmitter CTSubmitter

	// SerialStorage stores serial numbers.
	SerialStorage SerialStorage

	// CertStorage stores certificates.
	CertStorage CertificateStorage

	// AuditLogger logs audit events.
	AuditLogger AuditLogger

	// Profiles maps profile names to profiles.
	Profiles map[string]Profile

	// DefaultProfile is the default profile name.
	DefaultProfile string

	// Enabled controls whether issuance is enabled.
	Enabled bool
}

// issuer implements the Issuer interface.
type issuer struct {
	config Config
	mu     sync.RWMutex
}

// NewIssuer creates a new certificate issuer.
func NewIssuer(config Config) (Issuer, error) {
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.Profiles == nil {
		config.Profiles = map[string]Profile{
			"default":  DefaultProfile(),
			"tls":      TLSProfile(),
			"internal": InternalProfile(),
		}
	}

	if config.DefaultProfile == "" {
		config.DefaultProfile = "default"
	}

	return &issuer{
		config: config,
	}, nil
}

// validateConfig validates the issuer configuration.
func validateConfig(config *Config) error {
	if config.Signer == nil {
		return NewIssuanceError(PhaseCSRValidation, "signer is required", ErrInvalidConfig)
	}
	return nil
}

// Issue performs two-phase certificate issuance.
func (i *issuer) Issue(ctx context.Context, req *Request) (*Result, error) {
	if !i.config.Enabled {
		return nil, ErrIssuanceDisabled
	}

	if req == nil || req.CSR == nil {
		return nil, ErrNilInput
	}

	// Generate issuance ID
	issuanceID := generateIssuanceID()

	// Get profile
	profile, err := i.getProfile(req.Profile)
	if err != nil {
		return nil, err
	}

	// Step 1: Validate CSR
	if err := i.validateCSR(ctx, req, profile); err != nil {
		i.logFailure(ctx, req, PhaseCSRValidation, err)
		return nil, err
	}

	// Step 2: Validate key
	if err := i.validateKey(ctx, req.CSR.PublicKey); err != nil {
		i.logFailure(ctx, req, PhaseKeyValidation, err)
		return nil, err
	}

	// Step 3: Generate serial
	serial, err := i.generateSerial()
	if err != nil {
		i.logFailure(ctx, req, PhaseSerialGeneration, err)
		return nil, err
	}

	// Step 4: Persist serial (BEFORE signing!)
	if err := i.persistSerial(ctx, serial, req, issuanceID); err != nil {
		i.logFailure(ctx, req, PhaseSerialPersistence, err)
		return nil, err
	}

	// Cleanup serial on failure
	defer func() {
		if err != nil && i.config.SerialStorage != nil {
			_ = i.config.SerialStorage.RevokeReservation(ctx, serial)
		}
	}()

	// Log issuance intent (best effort - don't fail on audit log errors)
	if i.config.AuditLogger != nil {
		_ = i.config.AuditLogger.LogIssuanceIntent(ctx, req, serial)
	}

	// Step 5: Build template and add precert poison extension
	template, err := i.buildTemplate(req, serial)
	if err != nil {
		i.logFailure(ctx, req, PhaseLinting, err)
		return nil, err
	}

	// Add poison extension for precertificate
	precertTemplate := i.addPrecertPoison(template)

	// Step 6: Create lint precertificate (with poison extension for linting)
	lintCertDER, err := i.createLintDER(precertTemplate)
	if err != nil {
		i.logFailure(ctx, req, PhaseLinting, err)
		return nil, NewIssuanceError(PhaseLinting, "failed to create lint certificate", err)
	}

	// Step 7: Run linting on precert
	if !req.SkipLint && i.config.Linter != nil {
		if err := i.lintCertificate(lintCertDER); err != nil {
			i.logFailure(ctx, req, PhaseLinting, err)
			return nil, err
		}
	}

	// Step 8: Sign precertificate
	precertDER, err := i.signCertificate(precertTemplate)
	if err != nil {
		i.logFailure(ctx, req, PhasePrecertSigning, err)
		return nil, NewIssuanceError(PhasePrecertSigning, "failed to sign precert", err)
	}

	// Parse precert
	precert, err := x509.ParseCertificate(precertDER)
	if err != nil {
		i.logFailure(ctx, req, PhasePrecertSigning, err)
		return nil, NewIssuanceError(PhasePrecertSigning, "failed to parse precert", err)
	}

	// Step 9: Verify TBS determinism (lint cert vs precert)
	// Both have the same template (with poison), so TBS should match
	if err := ca.VerifyTBSDeterminism(lintCertDER, precertDER); err != nil {
		i.logFailure(ctx, req, PhaseTBSVerification, err)
		return nil, NewIssuanceError(PhaseTBSVerification, "precert TBS mismatch", err)
	}

	// Log precert creation
	if i.config.AuditLogger != nil {
		_ = i.config.AuditLogger.LogPrecertCreated(ctx, precert)
	}

	// Store precert for audit
	if i.config.CertStorage != nil {
		_ = i.config.CertStorage.StorePrecert(ctx, precert)
	}

	// Step 10: Submit to CT logs (unless skipped)
	var scts []ct.SignedCertificateTimestamp
	if !req.SkipCT && profile.RequireCT && i.config.CTSubmitter != nil {
		chain, err := i.getIssuerChain()
		if err != nil {
			i.logFailure(ctx, req, PhaseCTSubmission, err)
			return nil, NewIssuanceError(PhaseCTSubmission, "failed to get issuer chain", err)
		}

		scts, err = i.config.CTSubmitter.GetSCTs(ctx, precertDER, chain, req.NotAfter)
		if err != nil {
			i.logFailure(ctx, req, PhaseCTSubmission, err)
			return nil, NewIssuanceError(PhaseCTSubmission, "CT submission failed", err)
		}

		// Log CT submission
		if i.config.AuditLogger != nil {
			_ = i.config.AuditLogger.LogCTSubmission(ctx, scts, nil)
		}
	}

	// Step 11: Create final certificate template with SCTs (replacing poison)
	finalTemplate := i.replacePoisonWithSCTs(template, scts)

	// Step 12: Create lint certificate for final cert (for TBS verification)
	finalLintDER, err := i.createLintDER(finalTemplate)
	if err != nil {
		i.logFailure(ctx, req, PhaseFinalSigning, err)
		return nil, NewIssuanceError(PhaseFinalSigning, "failed to create final lint cert", err)
	}

	// Step 13: Sign final certificate
	finalCertDER, err := i.signCertificate(finalTemplate)
	if err != nil {
		i.logFailure(ctx, req, PhaseFinalSigning, err)
		return nil, NewIssuanceError(PhaseFinalSigning, "failed to sign final cert", err)
	}

	// Parse final cert
	finalCert, err := x509.ParseCertificate(finalCertDER)
	if err != nil {
		i.logFailure(ctx, req, PhaseFinalSigning, err)
		return nil, NewIssuanceError(PhaseFinalSigning, "failed to parse final cert", err)
	}

	// Step 14: Verify TBS determinism for final cert
	if err := ca.VerifyTBSDeterminism(finalLintDER, finalCertDER); err != nil {
		i.logFailure(ctx, req, PhaseTBSVerification, err)
		return nil, NewIssuanceError(PhaseTBSVerification, "final cert TBS mismatch", err)
	}

	// Step 15: Persist final certificate
	if i.config.CertStorage != nil {
		if err := i.config.CertStorage.StoreCertificate(ctx, finalCert); err != nil {
			i.logFailure(ctx, req, PhasePersistence, err)
			return nil, NewIssuanceError(PhasePersistence, "failed to store certificate", err)
		}
	}

	// Confirm serial usage (best effort - certificate is already issued)
	if i.config.SerialStorage != nil {
		_ = i.config.SerialStorage.ConfirmSerial(ctx, serial)
	}

	result := &Result{
		Precert:      precert,
		FinalCert:    finalCert,
		Serial:       serial,
		SCTs:         scts,
		IssuanceTime: time.Now(),
		IssuanceID:   issuanceID,
	}

	// Log issuance complete
	if i.config.AuditLogger != nil {
		_ = i.config.AuditLogger.LogIssuanceComplete(ctx, result)
	}

	return result, nil
}

// getProfile retrieves a profile by name.
func (i *issuer) getProfile(name string) (Profile, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if name == "" {
		name = i.config.DefaultProfile
	}

	profile, ok := i.config.Profiles[name]
	if !ok {
		return Profile{}, NewIssuanceError(PhaseCSRValidation,
			fmt.Sprintf("profile %q not found", name), ErrProfileNotFound)
	}

	return profile, nil
}

// validateCSR validates the certificate signing request.
func (i *issuer) validateCSR(ctx context.Context, req *Request, profile Profile) error {
	csr := req.CSR

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		return NewCSRValidationError("signature", "invalid CSR signature")
	}

	// Check key algorithm
	if !isAllowedAlgorithm(csr.PublicKeyAlgorithm, profile.AllowedKeyAlgorithms) {
		return NewCSRValidationError("publicKeyAlgorithm",
			fmt.Sprintf("algorithm %v not allowed", csr.PublicKeyAlgorithm))
	}

	// Validate validity period
	if err := i.validateValidityPeriod(req, profile); err != nil {
		return err
	}

	return nil
}

// validateValidityPeriod validates the certificate validity period.
func (i *issuer) validateValidityPeriod(req *Request, profile Profile) error {
	if req.NotBefore.IsZero() {
		return NewCSRValidationError("notBefore", "notBefore is required")
	}

	if req.NotAfter.IsZero() {
		return NewCSRValidationError("notAfter", "notAfter is required")
	}

	if !req.NotAfter.After(req.NotBefore) {
		return NewCSRValidationError("validity", "notAfter must be after notBefore")
	}

	maxDuration := time.Duration(profile.MaxValidityDays) * 24 * time.Hour
	if req.NotAfter.Sub(req.NotBefore) > maxDuration {
		return NewCSRValidationError("validity",
			fmt.Sprintf("validity period exceeds maximum of %d days", profile.MaxValidityDays))
	}

	return nil
}

// isAllowedAlgorithm checks if an algorithm is in the allowed list.
func isAllowedAlgorithm(alg x509.PublicKeyAlgorithm, allowed []x509.PublicKeyAlgorithm) bool {
	for _, a := range allowed {
		if a == alg {
			return true
		}
	}
	return false
}

// validateKey validates the public key.
func (i *issuer) validateKey(ctx context.Context, key interface{}) error {
	if i.config.KeyValidator == nil {
		return nil
	}

	if err := i.config.KeyValidator.CheckKey(ctx, key); err != nil {
		return NewIssuanceError(PhaseKeyValidation, "key validation failed", err)
	}

	return nil
}

// generateSerial generates a random serial number.
func (i *issuer) generateSerial() (*big.Int, error) {
	// Generate 128-bit random serial (minus sign bit = 127 bits of entropy)
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, NewIssuanceError(PhaseSerialGeneration, "failed to generate random bytes", err)
	}

	// Ensure positive serial (clear high bit)
	serialBytes[0] &= 0x7f

	serial := new(big.Int).SetBytes(serialBytes)
	return serial, nil
}

// persistSerial persists the serial number before signing.
func (i *issuer) persistSerial(ctx context.Context, serial *big.Int, req *Request, issuanceID string) error {
	if i.config.SerialStorage == nil {
		return nil
	}

	metadata := SerialMetadata{
		ReservedAt: time.Now(),
		RequestID:  issuanceID,
		Subject:    req.CSR.Subject.String(),
		Profile:    req.Profile,
	}

	if err := i.config.SerialStorage.ReserveSerial(ctx, serial, metadata); err != nil {
		return NewIssuanceError(PhaseSerialPersistence, "failed to reserve serial", err)
	}

	return nil
}

// buildTemplate builds the certificate template from the request.
func (i *issuer) buildTemplate(req *Request, serial *big.Int) (*x509.Certificate, error) {
	if req.Template != nil {
		template := *req.Template
		template.SerialNumber = serial
		template.NotBefore = req.NotBefore
		template.NotAfter = req.NotAfter
		return &template, nil
	}

	// Build from CSR
	csr := req.CSR
	template := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            csr.Subject,
		NotBefore:          req.NotBefore,
		NotAfter:           req.NotAfter,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,
		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	return template, nil
}

// createLintDER creates a DER-encoded certificate for linting.
func (i *issuer) createLintDER(template *x509.Certificate) ([]byte, error) {
	issuerCert, err := i.config.Signer.Certificate()
	if err != nil {
		return nil, err
	}

	signer, err := i.config.Signer.Signer()
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, template, issuerCert, template.PublicKey, signer)
}

// lintCertificate lints a DER-encoded certificate.
func (i *issuer) lintCertificate(der []byte) error {
	result, err := i.config.Linter.LintDER(der)
	if err != nil {
		return NewIssuanceError(PhaseLinting, "linting failed", err)
	}

	if !result.Passed() {
		return NewLintError(result.Summary(), result.Errors(), result.Warnings())
	}

	return nil
}

// addPrecertPoison adds the CT precert poison extension.
func (i *issuer) addPrecertPoison(template *x509.Certificate) *x509.Certificate {
	precertTemplate := *template

	// Add poison extension
	poison := ct.MakePrecertPoisonExtension()
	precertTemplate.ExtraExtensions = append(precertTemplate.ExtraExtensions, poison)

	return &precertTemplate
}

// signCertificate signs a certificate template.
func (i *issuer) signCertificate(template *x509.Certificate) ([]byte, error) {
	issuerCert, err := i.config.Signer.Certificate()
	if err != nil {
		return nil, err
	}

	signer, err := i.config.Signer.Signer()
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, template, issuerCert, template.PublicKey, signer)
}

// getIssuerChain returns the issuer certificate chain in DER format.
// If IssuerChain is configured, returns the full chain (intermediate CA to root).
// Otherwise, returns only the immediate issuer certificate.
func (i *issuer) getIssuerChain() ([][]byte, error) {
	// If a full chain is configured, use it
	if len(i.config.IssuerChain) > 0 {
		chain := make([][]byte, len(i.config.IssuerChain))
		for idx, cert := range i.config.IssuerChain {
			chain[idx] = cert.Raw
		}
		return chain, nil
	}

	// Fall back to just the immediate issuer certificate
	issuerCert, err := i.config.Signer.Certificate()
	if err != nil {
		return nil, err
	}

	return [][]byte{issuerCert.Raw}, nil
}

// replacePoisonWithSCTs replaces the poison extension with the SCT list.
func (i *issuer) replacePoisonWithSCTs(template *x509.Certificate, scts []ct.SignedCertificateTimestamp) *x509.Certificate {
	finalTemplate := *template

	// Filter out any existing CT extensions
	var extensions []pkix.Extension
	for _, ext := range finalTemplate.ExtraExtensions {
		if !ext.Id.Equal(ct.OIDPrecertPoison) && !ext.Id.Equal(ct.OIDSCTList) {
			extensions = append(extensions, ext)
		}
	}

	// Add SCT list if we have SCTs
	if len(scts) > 0 {
		sctExt, err := ct.MakeSCTListExtension(scts)
		if err == nil {
			extensions = append(extensions, sctExt)
		}
	}

	finalTemplate.ExtraExtensions = extensions
	return &finalTemplate
}

// logFailure logs an issuance failure.
func (i *issuer) logFailure(ctx context.Context, req *Request, phase IssuancePhase, err error) {
	if i.config.AuditLogger != nil {
		_ = i.config.AuditLogger.LogIssuanceFailure(ctx, req, phase, err)
	}
}

// generateIssuanceID generates a unique issuance ID.
func generateIssuanceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("issue-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
