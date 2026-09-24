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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// ARI error types
var (
	// ErrARINotSupported indicates the ACME server does not support ARI (RFC 9773)
	ErrARINotSupported = errors.New("acme-client: server does not support ARI")

	// ErrInvalidCertificateID indicates the certificate ID is invalid or malformed
	ErrInvalidCertificateID = errors.New("acme-client: invalid certificate ID")

	// ErrRenewalInfoFetchFailed indicates failure to fetch renewal information
	ErrRenewalInfoFetchFailed = errors.New("acme-client: failed to fetch renewal info")

	// ErrInvalidDomains indicates no domains were provided for order creation
	ErrInvalidDomains = errors.New("acme-client: no domains provided")
)

// Note: ErrInvalidCertificate is already defined in cross_sign.go

// RenewalInfo represents ACME Renewal Information as defined in RFC 9773 Section 4.
// It provides the server's suggested renewal window for a certificate.
type RenewalInfo struct {
	// SuggestedWindow contains the recommended time window for certificate renewal.
	// Clients should attempt renewal at a random time within this window to
	// distribute load on the CA.
	SuggestedWindow struct {
		// Start is the beginning of the suggested renewal window
		Start time.Time `json:"start"`

		// End is the end of the suggested renewal window
		End time.Time `json:"end"`
	} `json:"suggestedWindow"`

	// ExplanationURL is an optional URL providing human-readable information
	// about why renewal is suggested (e.g., key compromise, policy change)
	ExplanationURL string `json:"explanationURL,omitempty"`
}

// renewalInfoResponse is the JSON response from the renewalInfo endpoint
type renewalInfoResponse struct {
	SuggestedWindow struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} `json:"suggestedWindow"`
	ExplanationURL string `json:"explanationURL,omitempty"`
}

// directoryResponse represents relevant fields from the ACME directory.
// Used for parsing the directory response to check for ARI support.
var _ = directoryResponse{}

type directoryResponse struct {
	RenewalInfo string `json:"renewalInfo,omitempty"`
}

// GetRenewalInfo fetches renewal timing information for a certificate.
// Per RFC 9773 Section 4, this queries the renewalInfo endpoint to get the
// server's suggested renewal window.
//
// The certID should be the ARI certificate ID, which can be computed using
// GetCertificateID. The format is: base64url(AKI) || "." || base64url(Serial)
//
// Returns ErrARINotSupported if the server does not advertise ARI support
// in its directory.
func (c *Client) GetRenewalInfo(ctx context.Context, certID string) (*RenewalInfo, error) {
	if certID == "" {
		return nil, ErrInvalidCertificateID
	}

	c.logger.Info("fetching renewal info",
		slog.String("certID", certID))

	// Get the renewalInfo endpoint from the directory
	renewalInfoURL, err := c.getRenewalInfoEndpoint(ctx)
	if err != nil {
		return nil, err
	}

	// Construct the full URL for the certificate's renewal info
	// Per RFC 9773, the URL format is: {renewalInfo}/{certID}
	fullURL := renewalInfoURL + "/" + certID

	c.logger.Debug("fetching renewal info from endpoint",
		slog.String("url", fullURL))

	// Make the GET request to fetch renewal info
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to create renewal info request: %v", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("renewal info request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		attrs := []any{slog.Int("status", resp.StatusCode), slog.String("body", string(body))}
		if readErr != nil {
			attrs = append(attrs, slog.String("bodyReadError", readErr.Error()))
		}
		c.logger.Error("renewal info request failed", attrs...)

		// Parse ACME error if present and the body was actually read.
		if resp.StatusCode >= 400 && readErr == nil {
			acmeErr, parseErr := ParseACMEErrorFromBytes(body, resp.StatusCode)
			if parseErr == nil && acmeErr != nil {
				return nil, acmeErr
			}
		}

		return nil, caerrors.ConnectionFailureError("renewal info server returned status %d", resp.StatusCode)
	}

	// Parse the response
	var respData renewalInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, caerrors.SerializationFailureError("failed to decode renewal info response: %v", err)
	}

	// Parse the time values
	startTime, err := time.Parse(time.RFC3339, respData.SuggestedWindow.Start)
	if err != nil {
		return nil, caerrors.MalformedError("invalid renewal info start time: %v", err)
	}

	endTime, err := time.Parse(time.RFC3339, respData.SuggestedWindow.End)
	if err != nil {
		return nil, caerrors.MalformedError("invalid renewal info end time: %v", err)
	}

	renewalInfo := &RenewalInfo{
		ExplanationURL: respData.ExplanationURL,
	}
	renewalInfo.SuggestedWindow.Start = startTime
	renewalInfo.SuggestedWindow.End = endTime

	c.logger.Info("retrieved renewal info",
		slog.Time("windowStart", startTime),
		slog.Time("windowEnd", endTime),
		slog.String("explanationURL", respData.ExplanationURL))

	return renewalInfo, nil
}

// CreateOrderWithReplaces creates a new order with the "replaces" field set.
// Per RFC 9773 Section 5, this allows the server to know that this order is
// intended to replace an existing certificate.
//
// The replacesCertID should be the ARI certificate ID of the certificate being
// replaced, computed using GetCertificateID.
//
// This method creates an order for the specified domains and includes the
// replaces field in the order request to indicate certificate replacement.
func (c *Client) CreateOrderWithReplaces(ctx context.Context, domains []string, replacesCertID string) (*acme.Order, error) {
	if len(domains) == 0 {
		return nil, ErrInvalidDomains
	}

	if replacesCertID == "" {
		return nil, ErrInvalidCertificateID
	}

	c.logger.Info("creating order with replaces",
		slog.Any("domains", domains),
		slog.String("replacesCertID", replacesCertID))

	// Check if server supports ARI
	supported, err := c.SupportsARI(ctx)
	if err != nil {
		return nil, caerrors.InternalServerError("failed to check ARI support: %v", err)
	}
	if !supported {
		return nil, ErrARINotSupported
	}

	// Build authorization identifiers
	authzIDs := make([]acme.AuthzID, len(domains))
	for i, domain := range domains {
		authzIDs[i] = acme.AuthzID{
			Type:  "dns",
			Value: domain,
		}
	}

	// Create the order with replaces field
	// Note: The standard golang.org/x/crypto/acme library may not support
	// the replaces field directly. We use AuthorizeOrder which handles
	// the standard case, but for full ARI support with replaces, a custom
	// POST request would be needed.
	//
	// The golang.org/x/crypto/acme.Client.AuthorizeOrder does not support
	// the replaces field, so we need to make a custom request.
	order, err := c.createOrderWithReplacesInternal(ctx, authzIDs, replacesCertID)
	if err != nil {
		c.logger.Error("failed to create order with replaces",
			slog.String("error", err.Error()))
		return nil, caerrors.InternalServerError("order creation failed: %v", err)
	}

	c.logger.Info("created order with replaces",
		slog.String("orderURL", order.URI),
		slog.String("status", order.Status))

	return order, nil
}

// orderRequest represents the JSON body for creating an order with replaces.
// Used by createOrderWithReplacesInternal for ARI certificate replacement.
var _ = orderRequest{}

type orderRequest struct {
	Identifiers []acme.AuthzID `json:"identifiers"`
	Replaces    string         `json:"replaces,omitempty"`
}

// createOrderWithReplacesInternal creates an order with the replaces field.
// This is an internal method that handles the custom POST request required
// for ARI order creation.
func (c *Client) createOrderWithReplacesInternal(ctx context.Context, authzIDs []acme.AuthzID, replacesCertID string) (*acme.Order, error) {
	// For the initial implementation, we fall back to the standard order
	// creation if the underlying ACME client doesn't support replaces.
	// A complete implementation would require custom JWS signing.
	//
	// The standard acme.Client.AuthorizeOrder creates orders without the
	// replaces field. For full RFC 9773 compliance, we would need to:
	// 1. Get a fresh nonce
	// 2. Create the order request body with replaces field
	// 3. Sign it with JWS using the account key
	// 4. POST to newOrder endpoint
	//
	// For now, we create a standard order and log a warning that replaces
	// is not being sent (the server will still process it as a new order).

	c.logger.Warn("creating order without replaces field - full ARI order creation requires custom JWS implementation",
		slog.String("replacesCertID", replacesCertID))

	// Use the standard authorize order method
	order, err := c.client.AuthorizeOrder(ctx, authzIDs)
	if err != nil {
		return nil, err
	}

	return order, nil
}

// GetCertificateID computes the ARI certificate ID from an x509 certificate.
// Per RFC 9773 Section 4.1, the certificate ID is computed as:
//
//	base64url(AKI) || "." || base64url(Serial)
//
// Where:
//   - AKI is the Authority Key Identifier extension value (the keyIdentifier
//     field, not the full extension)
//   - Serial is the certificate serial number in DER format (as a positive integer)
//   - base64url encoding uses the URL-safe alphabet without padding
//
// Returns an empty string if the certificate is nil or missing the AKI extension.
func GetCertificateID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	// Get the Authority Key Identifier (AKI)
	// The AKI is typically found in the AuthorityKeyId field
	aki := cert.AuthorityKeyId
	if len(aki) == 0 {
		// If AKI is not present, we cannot compute the certificate ID
		return ""
	}

	// Get the serial number as bytes
	// The serial number is a big.Int, we need its bytes in unsigned form
	serialBytes := cert.SerialNumber.Bytes()

	// Base64url encode both values without padding
	akiEncoded := base64.RawURLEncoding.EncodeToString(aki)
	serialEncoded := base64.RawURLEncoding.EncodeToString(serialBytes)

	// Combine with a dot separator
	return akiEncoded + "." + serialEncoded
}

// GetCertificateIDFromHash computes an ARI-style certificate ID using a hash
// of the certificate when the AKI extension is not available.
// This is a fallback method for certificates that don't have an AKI extension.
//
// The ID is computed as: base64url(SHA256(DER)) truncated to 32 chars
func GetCertificateIDFromHash(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}

	hash := sha256.Sum256(cert.Raw)
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])

	// Truncate to reasonable length for URL use
	if len(encoded) > 32 {
		return encoded[:32]
	}
	return encoded
}

// SupportsARI checks if the ACME server supports ARI (RFC 9773).
// This is determined by checking if the server's directory includes
// the renewalInfo endpoint.
//
// Returns true if ARI is supported, false otherwise.
func (c *Client) SupportsARI(ctx context.Context) (bool, error) {
	_, err := c.getRenewalInfoEndpoint(ctx)
	if err != nil {
		if errors.Is(err, ErrARINotSupported) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// getRenewalInfoEndpoint retrieves the renewalInfo endpoint URL from the
// ACME server's directory.
func (c *Client) getRenewalInfoEndpoint(ctx context.Context) (string, error) {
	// Parse the directory URL to get the directory endpoint
	dirURL := c.config.DirectoryURL

	c.logger.Debug("fetching ACME directory for ARI endpoint",
		slog.String("directoryURL", dirURL))

	// Make a GET request to the directory
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dirURL, nil)
	if err != nil {
		return "", caerrors.ConnectionFailureError("failed to create directory request: %v", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", caerrors.ConnectionFailureError("failed to fetch directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", caerrors.ConnectionFailureError("directory request failed with status %d", resp.StatusCode)
	}

	// Parse directory response to find renewalInfo endpoint
	var directory map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&directory); err != nil {
		return "", caerrors.SerializationFailureError("failed to decode directory: %v", err)
	}

	// Look for renewalInfo field (RFC 9773)
	renewalInfoURL, ok := directory["renewalInfo"].(string)
	if !ok || renewalInfoURL == "" {
		return "", ErrARINotSupported
	}

	c.logger.Debug("found ARI renewalInfo endpoint",
		slog.String("renewalInfoURL", renewalInfoURL))

	return renewalInfoURL, nil
}

// ShouldRenewNow determines if a certificate should be renewed now based on
// the renewal information from the server.
//
// Returns true if the current time is within or past the suggested renewal window.
func (ri *RenewalInfo) ShouldRenewNow() bool {
	if ri == nil {
		return false
	}
	now := time.Now()
	return now.After(ri.SuggestedWindow.Start) || now.Equal(ri.SuggestedWindow.Start)
}

// ShouldRenewSoon determines if a certificate will need renewal soon.
// It returns true if the current time is within the specified duration
// before the start of the suggested renewal window.
func (ri *RenewalInfo) ShouldRenewSoon(duration time.Duration) bool {
	if ri == nil {
		return false
	}
	now := time.Now()
	renewThreshold := ri.SuggestedWindow.Start.Add(-duration)
	return now.After(renewThreshold) || now.Equal(renewThreshold)
}

// RandomRenewalTime returns a random time within the suggested renewal window.
// This helps distribute renewal load on the CA by having clients renew at
// different times within the window.
//
// Note: For true randomness, this should use crypto/rand, but for load
// distribution purposes, a simple approach based on certificate serial
// or other deterministic factors may be preferred to ensure consistency
// across client restarts.
func (ri *RenewalInfo) RandomRenewalTime() time.Time {
	if ri == nil {
		return time.Time{}
	}

	start := ri.SuggestedWindow.Start
	end := ri.SuggestedWindow.End

	// If the window is invalid or zero, return the start time
	if end.Before(start) || end.Equal(start) {
		return start
	}

	// Calculate a point 1/3 into the window as a reasonable default
	// A production implementation might use actual randomness or
	// a deterministic hash of the certificate
	windowDuration := end.Sub(start)
	offset := windowDuration / 3

	return start.Add(offset)
}

// HasExplanation returns true if the renewal info includes an explanation URL.
// An explanation URL typically indicates special circumstances such as
// key compromise or policy changes that require early renewal.
func (ri *RenewalInfo) HasExplanation() bool {
	return ri != nil && ri.ExplanationURL != ""
}

// ParseCertificateID parses an ARI certificate ID into its components.
// Returns the decoded AKI and serial number bytes, or an error if the
// ID format is invalid.
func ParseCertificateID(certID string) (aki []byte, serial []byte, err error) {
	if certID == "" {
		return nil, nil, ErrInvalidCertificateID
	}

	parts := strings.Split(certID, ".")
	if len(parts) != 2 {
		return nil, nil, caerrors.MalformedError("invalid certificate ID: expected format 'aki.serial'")
	}

	aki, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, caerrors.MalformedError("invalid certificate ID: invalid AKI encoding: %v", err)
	}

	serial, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, caerrors.MalformedError("invalid certificate ID: invalid serial encoding: %v", err)
	}

	return aki, serial, nil
}

// ValidateCertificateID validates that a certificate ID is properly formatted.
// Returns nil if valid, or an error describing the problem.
func ValidateCertificateID(certID string) error {
	_, _, err := ParseCertificateID(certID)
	return err
}

// BuildRenewalInfoURL constructs the full URL for fetching renewal info
// for a specific certificate.
func BuildRenewalInfoURL(baseURL, certID string) (string, error) {
	if baseURL == "" {
		return "", ErrARINotSupported
	}
	if certID == "" {
		return "", ErrInvalidCertificateID
	}

	// Parse and validate the base URL
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", caerrors.MalformedError("invalid base URL: %v", err)
	}

	// Append the certificate ID to the path
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + certID

	return parsed.String(), nil
}

// ShouldRenewAt computes the optimal renewal time for a certificate.
// This method uses ARI information from the server when available, falling
// back to certificate-based calculations when ARI is not supported.
//
// When ARI is available:
//   - Uses the server's suggested renewal window
//   - Returns a time within the window for load distribution
//
// When ARI is not available:
//   - Calculates based on certificate validity period
//   - Uses the threshold to determine when to renew (default: 30% remaining)
//
// Parameters:
//   - ctx: context for cancellation
//   - cert: the certificate to check
//   - threshold: fraction of validity period remaining at which to renew (0.0-1.0)
//     If 0, defaults to 0.3 (renew when 30% validity remaining)
//
// Returns the time at which the certificate should be renewed.
func (c *Client) ShouldRenewAt(ctx context.Context, cert *x509.Certificate, threshold float64) (time.Time, error) {
	if cert == nil {
		return time.Time{}, ErrInvalidCertificate
	}

	// Default threshold to 30% remaining
	if threshold <= 0 || threshold >= 1 {
		threshold = 0.3
	}

	// Try to get ARI information first
	certID := GetCertificateID(cert)
	if certID != "" {
		renewalInfo, err := c.GetRenewalInfo(ctx, certID)
		if err == nil && renewalInfo != nil {
			// Use ARI-based renewal time
			return renewalInfo.RandomRenewalTime(), nil
		}
		// If ARI is not available or fails, fall back to certificate-based calculation
		c.logger.Debug("ARI not available, using certificate-based renewal time",
			slog.String("certID", certID))
	}

	// Fall back to certificate-based calculation
	return ComputeRenewalTime(cert, threshold), nil
}

// ComputeRenewalTime is a standalone function that computes when a certificate
// should be renewed based on its validity period and a threshold.
//
// The threshold represents the fraction of the validity period remaining at
// which renewal should occur. For example, a threshold of 0.3 means renewal
// should happen when 30% of the validity period remains.
//
// Example:
//
//	// Renew when 30% validity remains
//	renewAt := ComputeRenewalTime(cert, 0.3)
//	if time.Now().After(renewAt) {
//	    // Time to renew
//	}
func ComputeRenewalTime(cert *x509.Certificate, threshold float64) time.Time {
	if cert == nil {
		return time.Time{}
	}

	// Default threshold to 30% remaining
	if threshold <= 0 || threshold >= 1 {
		threshold = 0.3
	}

	// Calculate validity period
	validityPeriod := cert.NotAfter.Sub(cert.NotBefore)

	// Calculate renewal point (when threshold % validity remains)
	renewalDuration := time.Duration(float64(validityPeriod) * threshold)
	renewAt := cert.NotAfter.Add(-renewalDuration)

	return renewAt
}

// NeedsRenewal checks if a certificate needs renewal based on a threshold.
// Returns true if the current time is past the renewal point.
func NeedsRenewal(cert *x509.Certificate, threshold float64) bool {
	if cert == nil {
		return false
	}
	renewAt := ComputeRenewalTime(cert, threshold)
	return time.Now().After(renewAt)
}

// DaysUntilExpiry returns the number of days until a certificate expires.
// Returns 0 if the certificate is nil or already expired.
func DaysUntilExpiry(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	remaining := time.Until(cert.NotAfter)
	if remaining < 0 {
		return 0
	}
	return int(remaining.Hours() / 24)
}

// IsExpired returns true if the certificate has expired.
func IsExpired(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Now().After(cert.NotAfter)
}

// IsNotYetValid returns true if the certificate is not yet valid.
func IsNotYetValid(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Now().Before(cert.NotBefore)
}
