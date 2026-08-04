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

package workflow

// RegisterRequest contains parameters for ACME account registration.
type RegisterRequest struct {
	// Email is the contact email address for the account.
	Email string

	// TermsOfServiceAgreed indicates whether the account holder agrees to the ToS.
	TermsOfServiceAgreed bool
}

// RegisterResponse contains the result of ACME account registration.
type RegisterResponse struct {
	// AccountURL is the URL of the registered account resource.
	AccountURL string

	// Status is the account status after registration.
	Status string

	// Contact contains the contact URLs associated with the account.
	Contact []string
}

// CertificateRequest contains parameters for requesting an ACME certificate.
type CertificateRequest struct {
	// Domains is the list of DNS names for the certificate.
	Domains []string

	// CSR is the DER-encoded Certificate Signing Request.
	// If nil, the caller must provide the CSR before finalization.
	CSR []byte

	// ChallengeType specifies the preferred challenge type (e.g., "http-01", "dns-01", "tls-alpn-01").
	ChallengeType string

	// ChallengeHandler is the callback for setting up challenge responses.
	ChallengeHandler ChallengeHandler

	// AccountURL is the URL of the account to use.
	// If empty, the caller must have registered previously.
	AccountURL string
}

// CertificateResponse contains the result of an ACME certificate issuance.
type CertificateResponse struct {
	// CertificateChain is the PEM-encoded certificate chain.
	CertificateChain string

	// CertificateURL is the URL of the issued certificate resource.
	CertificateURL string

	// OrderURL is the URL of the completed order.
	OrderURL string
}

// RevokeRequest contains parameters for revoking an ACME certificate.
type RevokeRequest struct {
	// Certificate is the DER-encoded certificate to revoke, base64url-encoded.
	Certificate string

	// Reason is the RFC 5280 revocation reason code.
	Reason int
}

// ChallengeHandler is called when an ACME challenge needs to be solved.
// The handler should set up the challenge response (e.g., HTTP server, DNS record)
// and return a cleanup function that tears down the response once validation completes.
type ChallengeHandler interface {
	// Setup provisions the challenge response for the given parameters.
	// It returns a cleanup function and any error encountered.
	Setup(challengeType, token, keyAuth, domain string) (cleanup func(), err error)
}

// ChallengeHandlerFunc adapts a plain function to the ChallengeHandler interface.
type ChallengeHandlerFunc func(challengeType, token, keyAuth, domain string) (func(), error)

// Setup calls the underlying function.
func (f ChallengeHandlerFunc) Setup(challengeType, token, keyAuth, domain string) (func(), error) {
	return f(challengeType, token, keyAuth, domain)
}
