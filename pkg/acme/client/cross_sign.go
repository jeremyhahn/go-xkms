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

package client

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

var (
	// ErrCrossSignerNotConfigured indicates that cross-signing was attempted without a configured cross-signer
	ErrCrossSignerNotConfigured = errors.New("acme-client: cross-signer not configured")

	// ErrCrossSignFailed indicates that the cross-signing operation failed
	ErrCrossSignFailed = errors.New("acme-client: cross-signing failed")

	// ErrInvalidCertificate indicates that the provided certificate is invalid
	ErrInvalidCertificate = errors.New("acme-client: invalid certificate")

	// ErrInvalidCSRForCrossSigning indicates that the CSR doesn't match the certificate
	ErrInvalidCSRForCrossSigning = errors.New("acme-client: CSR does not match certificate subject")

	// ErrNilCrossSignConfig indicates that nil configuration was provided
	ErrNilCrossSignConfig = errors.New("acme-client: nil cross-sign configuration")

	// ErrEmptyCrossSignDirectoryURL indicates that the directory URL is empty
	ErrEmptyCrossSignDirectoryURL = errors.New("acme-client: empty cross-sign directory URL")

	// ErrInvalidChallengeTypeForCrossSign indicates an unsupported challenge type
	ErrInvalidChallengeTypeForCrossSign = errors.New("acme-client: invalid challenge type for cross-signing")
)

// CrossSignConfig defines the configuration for cross-signing operations.
// Cross-signing allows a certificate issued by one CA to be signed by another CA,
// establishing a trust relationship between different certificate authorities.
//
// YAML keys follow the reference implementation (go-trusted-platform
// legacy) so existing `cross-sign:` config blocks continue to unmarshal
// cleanly: `directory`, `challenge`, `trusted-roots`, etc.
type CrossSignConfig struct {
	// DirectoryURL is the ACME directory endpoint of the cross-signing CA
	DirectoryURL string `yaml:"directory" json:"directory" mapstructure:"directory"`

	// ChallengeType specifies which challenge type to use for authorization
	// Supported types: http-01, dns-01, tls-alpn-01
	ChallengeType string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`

	// TrustedRoots contains PEM-encoded trusted root CA certificates for the cross-signer
	TrustedRoots []string `yaml:"trusted-roots,omitempty" json:"trusted_roots,omitempty" mapstructure:"trusted-roots"`

	// RequestServerBundle indicates whether to request the cross-signer's CA bundle
	RequestServerBundle bool `yaml:"request-server-bundle,omitempty" json:"request_server_bundle,omitempty" mapstructure:"request-server-bundle"`

	// Timeout for cross-signing operations
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" mapstructure:"timeout"`

	// RetryAttempts specifies the number of retry attempts for failed requests
	RetryAttempts int `yaml:"retry-attempts,omitempty" json:"retry_attempts,omitempty" mapstructure:"retry-attempts"`

	// RetryDelay specifies the delay between retry attempts
	RetryDelay time.Duration `yaml:"retry-delay,omitempty" json:"retry_delay,omitempty" mapstructure:"retry-delay"`
}

// Validate validates the cross-sign configuration
func (c *CrossSignConfig) Validate() error {
	if c == nil {
		return ErrNilCrossSignConfig
	}

	if c.DirectoryURL == "" {
		return ErrEmptyCrossSignDirectoryURL
	}

	if c.ChallengeType == "" {
		return ErrMissingChallengeType
	}

	// Validate challenge type is supported
	switch c.ChallengeType {
	case string(ChallengeTypeHTTP01),
		string(ChallengeTypeDNS01),
		string(ChallengeTypeTLSALPN01):
		// Valid challenge type
	default:
		return ErrInvalidChallengeTypeForCrossSign
	}

	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}

	if c.RetryAttempts < 0 {
		c.RetryAttempts = 3
	}

	if c.RetryDelay <= 0 {
		c.RetryDelay = 1 * time.Second
	}

	return nil
}

// CrossSignerFromClient creates a new ACME client configured for cross-signing operations.
// It takes an existing client and cross-sign configuration to create a client
// that connects to a different CA for cross-signing purposes.
//
// Parameters:
//   - client: The existing ACME client (used for storage and logging configuration)
//   - config: Configuration for the cross-signing CA connection
//
// Returns:
//   - A new Client configured to interact with the cross-signing CA
//   - An error if the configuration is invalid or client creation fails
func CrossSignerFromClient(client *Client, config *CrossSignConfig) (*Client, error) {
	if client == nil {
		return nil, ErrInvalidConfiguration
	}

	if err := config.Validate(); err != nil {
		return nil, caerrors.MalformedError("invalid cross-sign configuration: %v", err)
	}

	// Create a new client configuration for the cross-signer
	crossSignerConfig := &Config{
		DirectoryURL:        config.DirectoryURL,
		Timeout:             config.Timeout,
		RequestServerBundle: config.RequestServerBundle,
		TrustedRoots:        config.TrustedRoots,
		RetryAttempts:       config.RetryAttempts,
		RetryDelay:          config.RetryDelay,
		MaxRetryDelay:       30 * time.Second,
	}

	// Create a new client for cross-signing using the original client's credentials
	crossSignerParams := &Params{
		AccountEmail:       client.accountEmail,
		AccountSigner:      client.accountSigner,
		Config:             crossSignerConfig,
		Logger:             client.logger.With(slog.String("component", "cross-signer")),
		Storage:            client.storage,
		CertificateStorage: client.certificateStorage,
		OrderStorage:       client.orderStorage,
	}

	crossSigner, err := NewClient(crossSignerParams)
	if err != nil {
		return nil, caerrors.InternalServerError("failed to create cross-signer client: %v", err)
	}

	client.logger.Info("created cross-signer client",
		slog.String("directory_url", config.DirectoryURL),
		slog.String("challenge_type", config.ChallengeType))

	return crossSigner, nil
}

// CrossSign performs a cross-signing operation on an existing certificate.
// Cross-signing creates a new certificate with the same subject and public key
// but signed by a different CA, establishing a trust relationship between CAs.
//
// The workflow:
//  1. Validates the provided certificate and CSR
//  2. Extracts the subject from the certificate for authorization
//  3. Creates a new order with the cross-signer ACME server
//  4. Completes the required challenge verification
//  5. Finalizes the order to obtain the cross-signed certificate
//
// Parameters:
//   - ctx: Context for the operation
//   - csr: The original Certificate Signing Request in DER format
//   - certDER: The certificate to be cross-signed in DER format
//
// Returns:
//   - The cross-signed x509 certificate
//   - An error if the operation fails at any stage
func (c *Client) CrossSign(ctx context.Context, csr []byte, certDER []byte) (*x509.Certificate, error) {
	c.logger.Info("initiating cross-signing operation")

	// Validate inputs
	if len(csr) == 0 {
		return nil, ErrMissingCSR
	}

	if len(certDER) == 0 {
		return nil, ErrInvalidCertificate
	}

	// Parse the certificate to be cross-signed
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, caerrors.MalformedError("invalid certificate: failed to parse certificate: %v", err)
	}

	// Parse the CSR to validate it matches the certificate
	csrParsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, caerrors.BadCSRError("invalid CSR for cross-signing: failed to parse CSR: %v", err)
	}

	// Validate that the CSR subject matches the certificate subject
	if cert.Subject.String() != csrParsed.Subject.String() {
		return nil, caerrors.BadCSRError("CSR does not match certificate: certificate subject '%s' does not match CSR subject '%s'",
			cert.Subject.String(), csrParsed.Subject.String())
	}

	c.logger.Debug("validated certificate and CSR",
		slog.String("subject", cert.Subject.CommonName),
		slog.Time("not_before", cert.NotBefore),
		slog.Time("not_after", cert.NotAfter))

	// Extract authorization identifiers from the certificate
	// For cross-signing, we typically use the CN or SANs from the certificate
	authzID, authzType, err := c.extractAuthzFromCertificate(cert)
	if err != nil {
		return nil, caerrors.MalformedError("failed to extract authorization from certificate: %v", err)
	}

	c.logger.Debug("extracted authorization",
		slog.String("type", authzType),
		slog.String("value", authzID))

	// Create an order with the cross-signer for the same identifiers
	order, err := c.client.AuthorizeOrder(ctx, []acme.AuthzID{
		{
			Type:  authzType,
			Value: authzID,
		},
	})
	if err != nil {
		return nil, caerrors.InternalServerError("cross-sign failed: failed to authorize cross-sign order: %v", err)
	}

	c.logger.Debug("created cross-sign order",
		slog.String("order_url", order.URI),
		slog.String("status", order.Status))

	// Process each authorization
	for _, authzURL := range order.AuthzURLs {
		if err := c.processAuthorization(ctx, authzURL); err != nil {
			return nil, caerrors.InternalServerError("cross-sign failed: authorization failed: %v", err)
		}
	}

	// Finalize the order with the original CSR to get the cross-signed certificate
	c.logger.Debug("finalizing cross-sign order", slog.String("finalize_url", order.FinalizeURL))

	certChain, certURL, err := c.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, caerrors.InternalServerError("cross-sign failed: failed to finalize cross-sign order: %v", err)
	}

	// Parse the cross-signed certificate
	crossSignedCert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, caerrors.MalformedError("cross-sign failed: failed to parse cross-signed certificate: %v", err)
	}

	// Store the cross-signed certificate
	if c.certificateStorage != nil {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certChain[0],
		})
		certEntity := &entities.ACMECertificate{
			CertURL:   certURL,
			PEM:       string(certPEM),
			IssuedAt:  time.Now(),
			Status:    "valid",
			ExpiresAt: crossSignedCert.NotAfter,
		}
		if err := c.certificateStorage.Save(ctx, certEntity); err != nil {
			c.logger.Warn("failed to save cross-signed certificate to storage",
				slog.String("error", err.Error()))
		}
	}

	c.logger.Info("successfully completed cross-signing operation",
		slog.String("subject", crossSignedCert.Subject.CommonName),
		slog.String("issuer", crossSignedCert.Issuer.CommonName),
		slog.Time("not_before", crossSignedCert.NotBefore),
		slog.Time("not_after", crossSignedCert.NotAfter),
		slog.String("serial", crossSignedCert.SerialNumber.String()))

	return crossSignedCert, nil
}

// extractAuthzFromCertificate extracts authorization identifiers from a certificate.
// It prioritizes DNS names from SANs, falls back to CN, and supports IP addresses.
//
// Returns:
//   - authzValue: The authorization value (domain name or IP)
//   - authzType: The authorization type (dns or ip)
//   - error: If no valid authorization identifier is found
func (c *Client) extractAuthzFromCertificate(cert *x509.Certificate) (string, string, error) {
	// Try DNS names from Subject Alternative Names first
	if len(cert.DNSNames) > 0 {
		// Use the first DNS name (typically matches CN)
		return cert.DNSNames[0], "dns", nil
	}

	// Try IP addresses from Subject Alternative Names
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String(), "ip", nil
	}

	// Fall back to Common Name if no SANs
	if cert.Subject.CommonName != "" {
		// Assume Common Name is a DNS name
		return cert.Subject.CommonName, "dns", nil
	}

	return "", "", caerrors.MalformedError("no valid authorization identifier found in certificate")
}

// processAuthorization handles the authorization process for a given authorization URL.
// It retrieves the authorization, finds a suitable challenge, completes it, and waits for validation.
//
// Parameters:
//   - ctx: Context for the operation
//   - authzURL: The authorization URL to process
//
// Returns:
//   - An error if the authorization process fails
func (c *Client) processAuthorization(ctx context.Context, authzURL string) error {
	// Get the authorization
	authz, err := c.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return caerrors.InternalServerError("failed to get authorization: %v", err)
	}

	c.logger.Debug("processing authorization",
		slog.String("identifier", authz.Identifier.Value),
		slog.String("status", authz.Status))

	// If already valid, skip challenge processing
	if authz.Status == acme.StatusValid {
		c.logger.Debug("authorization already valid", slog.String("identifier", authz.Identifier.Value))
		return nil
	}

	// Find a suitable challenge
	// For cross-signing, we typically use standard challenges (http-01, dns-01, tls-alpn-01)
	var selectedChallenge *acme.Challenge
	for i := range authz.Challenges {
		challenge := authz.Challenges[i]
		switch challenge.Type {
		case "http-01", "dns-01", "tls-alpn-01":
			selectedChallenge = challenge
			c.logger.Debug("selected challenge",
				slog.String("type", challenge.Type),
				slog.String("token", challenge.Token))
			goto challengeFound
		}
	}

challengeFound:
	if selectedChallenge == nil {
		return caerrors.MalformedError("no suitable challenge found for cross-signing")
	}

	// Accept the challenge
	// Note: In a production implementation, you would set up the challenge response
	// before accepting it (e.g., placing a file for http-01, setting DNS record for dns-01)
	_, err = c.client.Accept(ctx, selectedChallenge)
	if err != nil {
		return caerrors.InternalServerError("failed to accept challenge: %v", err)
	}

	c.logger.Debug("accepted challenge", slog.String("type", selectedChallenge.Type))

	// Wait for the authorization to complete
	authz, err = c.client.WaitAuthorization(ctx, authz.URI)
	if err != nil {
		return caerrors.InternalServerError("failed to wait for authorization: %v", err)
	}

	if authz.Status != acme.StatusValid {
		return caerrors.InternalServerError("authorization failed with status: %s", authz.Status)
	}

	c.logger.Debug("authorization completed successfully",
		slog.String("identifier", authz.Identifier.Value))

	return nil
}

// CrossSignWithChallenge performs cross-signing with custom challenge setup and cleanup.
// This provides more control over the challenge process compared to the basic CrossSign method.
//
// Parameters:
//   - ctx: Context for the operation
//   - csr: The original Certificate Signing Request in DER format
//   - certDER: The certificate to be cross-signed in DER format
//   - challengeSetup: Function to set up the challenge response
//   - challengeCleanup: Function to clean up after challenge validation
//
// Returns:
//   - The cross-signed x509 certificate
//   - An error if the operation fails
func (c *Client) CrossSignWithChallenge(
	ctx context.Context,
	csr []byte,
	certDER []byte,
	challengeSetup ChallengeSetupFunc,
	challengeCleanup ChallengeCleanupFunc,
) (*x509.Certificate, error) {
	c.logger.Info("initiating cross-signing operation with custom challenge handlers")

	// Validate inputs
	if len(csr) == 0 {
		return nil, ErrMissingCSR
	}

	if len(certDER) == 0 {
		return nil, ErrInvalidCertificate
	}

	if challengeSetup == nil {
		return nil, ErrInvalidChallengeSetup
	}

	// Parse the certificate to be cross-signed
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, caerrors.MalformedError("invalid certificate: failed to parse certificate: %v", err)
	}

	// Parse the CSR to validate it matches the certificate
	csrParsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, caerrors.BadCSRError("invalid CSR for cross-signing: failed to parse CSR: %v", err)
	}

	// Validate that the CSR subject matches the certificate subject
	if cert.Subject.String() != csrParsed.Subject.String() {
		return nil, caerrors.BadCSRError("CSR does not match certificate: certificate subject '%s' does not match CSR subject '%s'",
			cert.Subject.String(), csrParsed.Subject.String())
	}

	// Extract authorization identifiers from the certificate
	authzID, authzType, err := c.extractAuthzFromCertificate(cert)
	if err != nil {
		return nil, caerrors.MalformedError("failed to extract authorization from certificate: %v", err)
	}

	// Create an order with the cross-signer
	order, err := c.client.AuthorizeOrder(ctx, []acme.AuthzID{
		{
			Type:  authzType,
			Value: authzID,
		},
	})
	if err != nil {
		return nil, caerrors.InternalServerError("cross-sign failed: failed to authorize cross-sign order: %v", err)
	}

	// Process each authorization with custom challenge handlers
	for _, authzURL := range order.AuthzURLs {
		authz, err := c.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, caerrors.InternalServerError("failed to get authorization: %v", err)
		}

		// Skip if already valid
		if authz.Status == acme.StatusValid {
			continue
		}

		// Find and process a challenge
		var selectedChallenge *acme.Challenge
		for i := range authz.Challenges {
			challenge := authz.Challenges[i]
			switch challenge.Type {
			case "http-01", "dns-01", "tls-alpn-01":
				// Generate key authorization
				keyAuth, err := c.client.HTTP01ChallengeResponse(challenge.Token)
				if err != nil {
					return nil, caerrors.InternalServerError("failed to generate key authorization: %v", err)
				}

				// Setup challenge using custom handler
				if err := challengeSetup(challenge.Type, challenge.Token, keyAuth); err != nil {
					return nil, caerrors.InternalServerError("challenge setup failed: %v", err)
				}

				selectedChallenge = challenge
				goto challengeSetup
			}
		}

	challengeSetup:
		if selectedChallenge == nil {
			return nil, caerrors.MalformedError("no suitable challenge found")
		}

		// Accept the challenge
		_, err = c.client.Accept(ctx, selectedChallenge)
		if err != nil {
			return nil, caerrors.InternalServerError("failed to accept challenge: %v", err)
		}

		// Wait for authorization
		authz, err = c.client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return nil, caerrors.InternalServerError("failed to wait for authorization: %v", err)
		}

		if authz.Status != acme.StatusValid {
			return nil, caerrors.InternalServerError("authorization failed with status: %s", authz.Status)
		}

		// Cleanup challenge if handler provided
		if challengeCleanup != nil {
			challengeCleanup(selectedChallenge.Type)
		}
	}

	// Finalize the order
	certChain, certURL, err := c.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, caerrors.InternalServerError("cross-sign failed: failed to finalize cross-sign order: %v", err)
	}

	// Parse the cross-signed certificate
	crossSignedCert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, caerrors.MalformedError("cross-sign failed: failed to parse cross-signed certificate: %v", err)
	}

	// Store the certificate
	if c.certificateStorage != nil {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certChain[0],
		})
		certEntity := &entities.ACMECertificate{
			CertURL:   certURL,
			PEM:       string(certPEM),
			IssuedAt:  time.Now(),
			Status:    "valid",
			ExpiresAt: crossSignedCert.NotAfter,
		}
		if err := c.certificateStorage.Save(ctx, certEntity); err != nil {
			c.logger.Warn("failed to save cross-signed certificate to storage",
				slog.String("error", err.Error()))
		}
	}

	c.logger.Info("successfully completed cross-signing operation",
		slog.String("subject", crossSignedCert.Subject.CommonName),
		slog.String("issuer", crossSignedCert.Issuer.CommonName))

	return crossSignedCert, nil
}
