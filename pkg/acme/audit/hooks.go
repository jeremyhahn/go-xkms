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

package audit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
)

// HTTPMiddleware creates HTTP middleware that automatically audits requests
func HTTPMiddleware(logger AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !logger.Enabled() {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Extract request context
			ctx := r.Context()
			sourceIP := extractClientIP(r)
			userAgent := r.UserAgent()

			// Generate request ID if not present
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = generateRequestID()
			}

			// Add context values
			ctx = ContextWithRequestID(ctx, requestID)
			ctx = ContextWithSourceIP(ctx, sourceIP)
			ctx = ContextWithUserAgent(ctx, userAgent)

			// Create response writer wrapper to capture status code
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(rw, r.WithContext(ctx))

			// Log the request
			duration := time.Since(start).Milliseconds()
			result := ResultSuccess
			if rw.statusCode >= 400 {
				result = ResultFailure
			}

			event := NewEventBuilder(EventType("HTTP_REQUEST")).
				WithActor(extractActorFromRequest(r)).
				WithResource(r.URL.Path).
				WithAction(r.Method).
				WithResult(result).
				WithRequestID(requestID).
				WithSourceIP(sourceIP).
				WithUserAgent(userAgent).
				WithDuration(duration).
				WithDetail("method", r.Method).
				WithDetail("path", r.URL.Path).
				WithDetail("status_code", rw.statusCode).
				Build()

			if err := logger.Log(ctx, event); err != nil {
				// Log error but don't fail the request
				fmt.Printf("audit: failed to log HTTP request: %v\n", err)
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// trustedProxies is the set of reverse proxies permitted to name the client
// in X-Forwarded-For / X-Real-IP for audit source-IP attribution. It must be
// the same *ratelimit.TrustedProxies the ACME server's own rate limiter uses
// (acmeserver.TrustedProxies) — both are sourced from the single
// server.trusted_proxies configuration key by SetTrustedProxies — so a
// forwarding header is trusted, or not, identically for rate limiting and
// for the audit trail. The nil zero value trusts no proxy, the secure
// default: until SetTrustedProxies is called, extractClientIP resolves to
// the transport peer address alone.
var trustedProxies *ratelimit.TrustedProxies

// SetTrustedProxies configures the reverse-proxy set that extractClientIP
// (and so the HTTP audit middleware and RequestContext) trusts to name the
// client in X-Forwarded-For / X-Real-IP. Call it once during start-up with
// the same *ratelimit.TrustedProxies value passed to the ACME server's rate
// limiter, so both derive the client identity from the same trusted-proxy
// set and neither introduces a second server.trusted_proxies-shaped config
// key. A nil proxies — the default before SetTrustedProxies is ever called —
// trusts no proxy.
func SetTrustedProxies(proxies *ratelimit.TrustedProxies) {
	trustedProxies = proxies
}

// extractClientIP resolves the address of the client that sent r using the
// shared trusted-proxy resolver (ratelimit.TrustedProxies.ClientIP): the
// transport peer address, or, only when that peer is a configured trusted
// proxy, the right-most untrusted X-Forwarded-For hop (then X-Real-IP). A
// request from any other peer is attributed to its own transport address, so
// a client cannot forge the recorded source IP by sending a forwarding
// header.
func extractClientIP(r *http.Request) string {
	return trustedProxies.ClientIP(r)
}

// ClientIP returns the address of the client that sent r, resolved through
// the same trusted-proxy rules as extractClientIP. Handlers use it to stamp
// audit events with the true origin of a request rather than the address of
// the proxy in front of the CA.
func ClientIP(r *http.Request) string {
	return extractClientIP(r)
}

// RequestContext returns a context carrying the request attributes that every
// audit event recorded while handling r should reference: the correlation ID
// (the client's X-Request-ID when it supplied one), the client address, and
// the user agent. Passing the result to the Log* helpers below is what ties an
// audit record back to the request that caused it.
func RequestContext(ctx context.Context, r *http.Request) context.Context {
	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = generateRequestID()
	}

	ctx = ContextWithRequestID(ctx, requestID)
	ctx = ContextWithSourceIP(ctx, extractClientIP(r))
	return ContextWithUserAgent(ctx, r.UserAgent())
}

// extractActorFromRequest extracts the actor (account ID or system) from request
func extractActorFromRequest(r *http.Request) string {
	// Try to get account ID from context or headers
	if accountID := r.Header.Get("X-Account-ID"); accountID != "" {
		return fmt.Sprintf("account:%s", accountID)
	}

	return "system"
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	// Use timestamp + random component for uniqueness
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// AuditableOperation wraps a function with audit logging
func AuditableOperation(
	ctx context.Context,
	logger AuditLogger,
	eventType EventType,
	actor, resource, action string,
	details map[string]interface{},
	operation func() error) error {

	if !logger.Enabled() {
		return operation()
	}

	start := time.Now()
	err := operation()
	duration := time.Since(start).Milliseconds()

	result := ResultSuccess
	builder := NewEventBuilder(eventType).
		WithActor(actor).
		WithResource(resource).
		WithAction(action).
		WithDuration(duration).
		WithDetails(details)

	if err != nil {
		result = ResultFailure
		builder.WithError(err)
	}

	event := builder.WithResult(result).Build()

	if logErr := logger.Log(ctx, event); logErr != nil {
		// Log error but don't fail the operation
		fmt.Printf("audit: failed to log operation: %v\n", logErr)
	}

	return err
}

// LogCertificateIssued logs a certificate issuance event
func LogCertificateIssued(
	ctx context.Context,
	logger AuditLogger,
	accountID, orderID, commonName string,
	validityDays int,
	serialNumber string) error {

	if !logger.Enabled() {
		return nil
	}

	details := map[string]interface{}{
		"common_name":   commonName,
		"validity_days": validityDays,
		"serial_number": serialNumber,
	}

	return logger.LogWithContext(
		ctx,
		EventCertificateIssued,
		fmt.Sprintf("account:%s", accountID),
		fmt.Sprintf("order:%s", orderID),
		"issue",
		ResultSuccess,
		details,
	)
}

// LogCertificateRevoked logs a certificate revocation event
func LogCertificateRevoked(
	ctx context.Context,
	logger AuditLogger,
	accountID, serialNumber string,
	reason int) error {

	if !logger.Enabled() {
		return nil
	}

	details := map[string]interface{}{
		"serial_number": serialNumber,
		"reason_code":   reason,
	}

	return logger.LogWithContext(
		ctx,
		EventCertificateRevoked,
		fmt.Sprintf("account:%s", accountID),
		fmt.Sprintf("certificate:%s", serialNumber),
		"revoke",
		ResultSuccess,
		details,
	)
}

// LogAccountCreated logs an account creation event
func LogAccountCreated(
	ctx context.Context,
	logger AuditLogger,
	accountID string,
	contact []string,
	externalAccount bool) error {

	if !logger.Enabled() {
		return nil
	}

	details := map[string]interface{}{
		"contact":          contact,
		"external_account": externalAccount,
	}

	return logger.LogWithContext(
		ctx,
		EventAccountCreated,
		"system",
		fmt.Sprintf("account:%s", accountID),
		"create",
		ResultSuccess,
		details,
	)
}

// LogOrderCreated logs an order creation event
func LogOrderCreated(
	ctx context.Context,
	logger AuditLogger,
	accountID, orderID string,
	identifiers []string) error {

	if !logger.Enabled() {
		return nil
	}

	details := map[string]interface{}{
		"identifiers": identifiers,
	}

	return logger.LogWithContext(
		ctx,
		EventOrderCreated,
		fmt.Sprintf("account:%s", accountID),
		fmt.Sprintf("order:%s", orderID),
		"create",
		ResultSuccess,
		details,
	)
}

// LogOrderFinalized logs an order finalization event
func LogOrderFinalized(
	ctx context.Context,
	logger AuditLogger,
	accountID, orderID string,
	certificateURL string) error {

	if !logger.Enabled() {
		return nil
	}

	details := map[string]interface{}{
		"certificate_url": certificateURL,
	}

	return logger.LogWithContext(
		ctx,
		EventOrderFinalized,
		fmt.Sprintf("account:%s", accountID),
		fmt.Sprintf("order:%s", orderID),
		"finalize",
		ResultSuccess,
		details,
	)
}

// LogChallengeCompleted logs a challenge completion event
func LogChallengeCompleted(
	ctx context.Context,
	logger AuditLogger,
	accountID, challengeID, challengeType string,
	success bool) error {

	if !logger.Enabled() {
		return nil
	}

	result := ResultSuccess
	if !success {
		result = ResultFailure
	}

	details := map[string]interface{}{
		"challenge_type": challengeType,
	}

	return logger.LogWithContext(
		ctx,
		EventChallengeCompleted,
		fmt.Sprintf("account:%s", accountID),
		fmt.Sprintf("challenge:%s", challengeID),
		"validate",
		result,
		details,
	)
}

// LogKeyChange logs an account key change event
func LogKeyChange(
	ctx context.Context,
	logger AuditLogger,
	accountID string,
	oldKeyFingerprint, newKeyFingerprint string) error {

	if !logger.Enabled() {
		return nil
	}

	details := map[string]interface{}{
		"old_key_fingerprint": oldKeyFingerprint,
		"new_key_fingerprint": newKeyFingerprint,
	}

	return logger.LogWithContext(
		ctx,
		EventAccountKeyChanged,
		fmt.Sprintf("account:%s", accountID),
		fmt.Sprintf("account:%s", accountID),
		"key_rollover",
		ResultSuccess,
		details,
	)
}

// LogAuthenticationFailed logs an authentication failure
func LogAuthenticationFailed(
	ctx context.Context,
	logger AuditLogger,
	reason string) error {

	if !logger.Enabled() {
		return nil
	}

	details := map[string]interface{}{
		"reason": reason,
	}

	return logger.LogWithContext(
		ctx,
		EventAuthenticationFailed,
		"unknown",
		"authentication",
		"authenticate",
		ResultFailure,
		details,
	)
}

// LogTPMEnrollment logs a TPM enrollment event
func LogTPMEnrollment(
	ctx context.Context,
	logger AuditLogger,
	accountID, deviceID string,
	ekCert, akCert string) error {

	if !logger.Enabled() {
		return nil
	}

	details := map[string]interface{}{
		"device_id": deviceID,
		"ek_cert":   ekCert,
		"ak_cert":   akCert,
	}

	return logger.LogWithContext(
		ctx,
		EventTPMEnrollment,
		fmt.Sprintf("account:%s", accountID),
		fmt.Sprintf("device:%s", deviceID),
		"enroll",
		ResultSuccess,
		details,
	)
}
