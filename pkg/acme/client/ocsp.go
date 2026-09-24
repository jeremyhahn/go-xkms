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

package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// OCSP error types
var (
	// ErrOCSPNoIssuer indicates no issuer certificate was provided
	ErrOCSPNoIssuer = errors.New("acme-client: no issuer certificate provided")

	// ErrOCSPNoResponder indicates no OCSP responder URL found in certificate
	ErrOCSPNoResponder = errors.New("acme-client: no OCSP responder URL in certificate")

	// ErrOCSPRequestFailed indicates the OCSP request failed
	ErrOCSPRequestFailed = errors.New("acme-client: OCSP request failed")

	// ErrOCSPResponseParseFailed indicates the OCSP response could not be parsed
	ErrOCSPResponseParseFailed = errors.New("acme-client: failed to parse OCSP response")

	// ErrOCSPResponseInvalid indicates the OCSP response is invalid
	ErrOCSPResponseInvalid = errors.New("acme-client: invalid OCSP response")

	// ErrOCSPCertRevoked indicates the certificate has been revoked
	ErrOCSPCertRevoked = errors.New("acme-client: certificate has been revoked")

	// ErrOCSPCertUnknown indicates the OCSP responder doesn't know the certificate
	ErrOCSPCertUnknown = errors.New("acme-client: certificate unknown to OCSP responder")
)

const (
	// OCSPContentType is the content type for OCSP requests
	OCSPContentType = "application/ocsp-request"

	// defaultOCSPTimeout is the default timeout for OCSP requests
	defaultOCSPTimeout = 30 * time.Second
)

// OCSPResponse contains the result of an OCSP query
type OCSPResponse struct {
	// Raw is the raw OCSP response bytes (for stapling)
	Raw []byte

	// Response is the parsed OCSP response
	Response *ocsp.Response

	// Status is the certificate status (Good, Revoked, or Unknown)
	Status ocsp.ResponseStatus

	// ThisUpdate is when this response was produced
	ThisUpdate time.Time

	// NextUpdate is when the next update will be available
	NextUpdate time.Time

	// ProducedAt is when the response was produced
	ProducedAt time.Time

	// RevokedAt is when the certificate was revoked (if revoked)
	RevokedAt time.Time

	// RevocationReason is the reason for revocation (if revoked)
	RevocationReason int
}

// IsGood returns true if the certificate status is Good
func (or *OCSPResponse) IsGood() bool {
	return or != nil && or.Response != nil && or.Response.Status == ocsp.Good
}

// IsRevoked returns true if the certificate status is Revoked
func (or *OCSPResponse) IsRevoked() bool {
	return or != nil && or.Response != nil && or.Response.Status == ocsp.Revoked
}

// IsUnknown returns true if the certificate status is Unknown
func (or *OCSPResponse) IsUnknown() bool {
	return or != nil && or.Response != nil && or.Response.Status == ocsp.Unknown
}

// IsStale returns true if the response is past its NextUpdate time
func (or *OCSPResponse) IsStale() bool {
	if or == nil || or.Response == nil {
		return true
	}
	return time.Now().After(or.NextUpdate)
}

// ShouldRefresh returns true if the response should be refreshed.
// It returns true when we're past 50% of the validity period.
func (or *OCSPResponse) ShouldRefresh() bool {
	if or == nil || or.Response == nil {
		return true
	}
	validityPeriod := or.NextUpdate.Sub(or.ThisUpdate)
	halfLife := or.ThisUpdate.Add(validityPeriod / 2)
	return time.Now().After(halfLife)
}

// GetOCSP fetches an OCSP response for the given certificate.
// The issuer certificate is required to construct and verify the OCSP request.
//
// This method is useful for OCSP stapling, where the TLS server includes the
// OCSP response in the TLS handshake to prove certificate validity.
//
// Example usage:
//
//	ocspResp, err := client.GetOCSP(ctx, cert, issuer)
//	if err != nil {
//	    return err
//	}
//	if ocspResp.IsGood() {
//	    // Certificate is valid, use ocspResp.Raw for stapling
//	    tlsConfig.OCSPStaple = ocspResp.Raw
//	}
func (c *Client) GetOCSP(ctx context.Context, cert, issuer *x509.Certificate) (*OCSPResponse, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}
	if issuer == nil {
		return nil, ErrOCSPNoIssuer
	}

	// Get OCSP responder URL from certificate
	if len(cert.OCSPServer) == 0 {
		return nil, ErrOCSPNoResponder
	}

	ocspURL := cert.OCSPServer[0]

	c.logger.Info("fetching OCSP response",
		slog.String("subject", cert.Subject.CommonName),
		slog.String("ocspURL", ocspURL))

	return GetOCSP(ctx, cert, issuer, ocspURL, c.httpClient)
}

// GetOCSP is a standalone function that fetches an OCSP response for a certificate.
// This can be used without a Client instance when you just need OCSP checking.
//
// Parameters:
//   - ctx: context for cancellation
//   - cert: the certificate to check
//   - issuer: the issuer certificate (required for OCSP request construction)
//   - ocspURL: the OCSP responder URL (if empty, uses cert.OCSPServer[0])
//   - httpClient: optional HTTP client (if nil, uses default client)
func GetOCSP(ctx context.Context, cert, issuer *x509.Certificate, ocspURL string, httpClient *http.Client) (*OCSPResponse, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}
	if issuer == nil {
		return nil, ErrOCSPNoIssuer
	}

	// Use certificate's OCSP URL if not provided
	if ocspURL == "" {
		if len(cert.OCSPServer) == 0 {
			return nil, ErrOCSPNoResponder
		}
		ocspURL = cert.OCSPServer[0]
	}

	// Create OCSP request. golang.org/x/crypto/ocsp defaults RequestOptions
	// to SHA-1 (crypto.Hash zero value) when opts is nil, and crypto/sha1
	// panics rather than erroring under GODEBUG=fips140=only -- a request
	// this client itself originates has no reason to default to a hash the
	// runtime it is calling from cannot compute. SHA-256 is requested
	// explicitly instead; every responder RFC 6960 was written against
	// supports it.
	ocspReq, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, caerrors.OCSPFailureError("failed to create OCSP request: %v", err)
	}

	// Use provided HTTP client or create a default one
	client := httpClient
	if client == nil {
		client = &http.Client{
			Timeout: defaultOCSPTimeout,
		}
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(ocspReq))
	if err != nil {
		return nil, caerrors.ConnectionFailureError("OCSP: failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", OCSPContentType)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("OCSP: HTTP request failed: %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("ocsp: failed to close response body", slog.String("error", closeErr.Error()))
		}
	}()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return nil, caerrors.ConnectionFailureError("OCSP: server returned status %d", resp.StatusCode)
	}

	// Read response body
	rawResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, caerrors.OCSPFailureError("failed to read OCSP response body: %v", err)
	}

	// Parse OCSP response
	ocspResp, err := ocsp.ParseResponse(rawResponse, issuer)
	if err != nil {
		// Try parsing without verifying against issuer
		// Some OCSP responders use a different signing certificate
		ocspResp, err = ocsp.ParseResponseForCert(rawResponse, cert, issuer)
		if err != nil {
			return nil, caerrors.OCSPFailureError("failed to parse OCSP response: %v", err)
		}
	}

	// Build response
	result := &OCSPResponse{
		Raw:        rawResponse,
		Response:   ocspResp,
		ThisUpdate: ocspResp.ThisUpdate,
		NextUpdate: ocspResp.NextUpdate,
		ProducedAt: ocspResp.ProducedAt,
	}

	// Handle status
	switch ocspResp.Status {
	case ocsp.Good:
		result.Status = ocsp.Success
	case ocsp.Revoked:
		result.Status = ocsp.Success
		result.RevokedAt = ocspResp.RevokedAt
		result.RevocationReason = ocspResp.RevocationReason
	case ocsp.Unknown:
		result.Status = ocsp.Success
	}

	return result, nil
}

// CheckOCSP is a convenience function that checks if a certificate is valid.
// It returns nil if the certificate is valid (OCSP status Good),
// or an error if revoked, unknown, or the OCSP check failed.
func CheckOCSP(ctx context.Context, cert, issuer *x509.Certificate) error {
	resp, err := GetOCSP(ctx, cert, issuer, "", nil)
	if err != nil {
		return err
	}

	switch resp.Response.Status {
	case ocsp.Good:
		return nil
	case ocsp.Revoked:
		return caerrors.OCSPFailureError("certificate revoked at %s (reason: %d)",
			resp.RevokedAt.Format(time.RFC3339), resp.RevocationReason)
	case ocsp.Unknown:
		return ErrOCSPCertUnknown
	default:
		return caerrors.OCSPFailureError("unexpected OCSP status %d", resp.Response.Status)
	}
}

// MustStapleOID is the OID for the OCSP Must-Staple extension
// id-pe-tlsfeature (1.3.6.1.5.5.7.1.24)
var MustStapleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

// HasMustStaple checks if a certificate has the OCSP Must-Staple extension.
// When present, TLS servers MUST provide OCSP stapling for this certificate.
func HasMustStaple(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(MustStapleOID) {
			return true
		}
	}
	return false
}
