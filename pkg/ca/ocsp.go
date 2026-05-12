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

// Package ca provides an RFC 6960 OCSP responder that consumes revocation
// records persisted by the core CA (see recordRevocation/loadPersistedRevocations
// in ca_extensions.go). The responder is a standalone helper — callers build
// one with NewOCSPResponder and feed it DER-encoded OCSP requests.
package ca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// =============================================================================
// OCSP Errors
// =============================================================================

var (
	// ErrOCSPInvalidRequest indicates the OCSP request is nil or missing
	// required fields (hash algorithm, serial number).
	ErrOCSPInvalidRequest = errors.New("ca: invalid ocsp request")

	// ErrOCSPRequestParseFailed indicates the DER-encoded request could
	// not be parsed as an RFC 6960 OCSPRequest.
	ErrOCSPRequestParseFailed = errors.New("ca: failed to parse ocsp request")

	// ErrOCSPResponseFailed indicates building the OCSP response failed.
	ErrOCSPResponseFailed = errors.New("ca: failed to create ocsp response")

	// ErrOCSPSigningFailed indicates signing the OCSP response failed.
	ErrOCSPSigningFailed = errors.New("ca: failed to sign ocsp response")

	// ErrOCSPCertNotFound indicates the certificate for which an OCSP
	// response was requested is unknown to the CA.
	ErrOCSPCertNotFound = errors.New("ca: certificate not found for ocsp check")

	// ErrOCSPStorageError indicates a backing-store failure while servicing
	// the OCSP request. Per RFC 6960 the responder returns status Unknown
	// rather than Good when storage fails.
	ErrOCSPStorageError = errors.New("ca: ocsp storage error")
)

// =============================================================================
// Configuration
// =============================================================================

// OCSPResponderConfig configures an OCSPResponder.
type OCSPResponderConfig struct {
	// CacheTTL is how long a signed OCSP response is cached in memory.
	// Zero uses DefaultOCSPResponderConfig().CacheTTL.
	CacheTTL time.Duration

	// NextUpdate is the interval baked into the OCSP response that tells
	// relying parties when to next poll. Zero uses the default (7 days).
	NextUpdate time.Duration
}

// DefaultOCSPResponderConfig returns sensible production defaults: 1-hour
// cache, 7-day NextUpdate.
func DefaultOCSPResponderConfig() OCSPResponderConfig {
	return OCSPResponderConfig{
		CacheTTL:   1 * time.Hour,
		NextUpdate: 7 * 24 * time.Hour,
	}
}

// =============================================================================
// OCSPResponder
// =============================================================================

// OCSPResponder implements an RFC 6960 OCSP responder that sits in front of a
// *CA. It serves GOOD/REVOKED/UNKNOWN responses signed with the CA's issuing
// key and caches responses in memory for CacheTTL.
//
// Thread-safe: Yes.
type OCSPResponder struct {
	ca     *CA
	config OCSPResponderConfig

	cacheMu sync.RWMutex
	cache   map[string]*cachedOCSPResponse
}

// cachedOCSPResponse is an in-memory cache entry for a signed OCSP response.
type cachedOCSPResponse struct {
	response  []byte
	expiresAt time.Time
}

// NewOCSPResponder returns an OCSPResponder bound to the given CA. If config
// contains a zero CacheTTL, DefaultOCSPResponderConfig is used instead so
// callers can pass OCSPResponderConfig{} for defaults.
func NewOCSPResponder(ca *CA, config OCSPResponderConfig) *OCSPResponder {
	if config.CacheTTL == 0 {
		config = DefaultOCSPResponderConfig()
	}
	return &OCSPResponder{
		ca:     ca,
		config: config,
		cache:  make(map[string]*cachedOCSPResponse),
	}
}

// HandleRequest parses the DER-encoded OCSP request, produces a signed
// OCSP response, and returns the DER-encoded response bytes. This is the
// primary entry point for HTTP OCSP endpoints.
func (o *OCSPResponder) HandleRequest(requestBytes []byte) ([]byte, error) {
	req, err := o.parseRequest(requestBytes)
	if err != nil {
		return nil, err
	}
	return o.createResponse(req)
}

// parseRequest decodes and validates an OCSPRequest per RFC 6960.
func (o *OCSPResponder) parseRequest(requestBytes []byte) (*ocsp.Request, error) {
	if len(requestBytes) == 0 {
		return nil, ErrOCSPInvalidRequest
	}
	req, err := ocsp.ParseRequest(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPRequestParseFailed, err)
	}
	if req.HashAlgorithm == 0 {
		return nil, fmt.Errorf("%w: missing hash algorithm", ErrOCSPInvalidRequest)
	}
	if req.SerialNumber == nil {
		return nil, fmt.Errorf("%w: missing serial number", ErrOCSPInvalidRequest)
	}
	return req, nil
}

// createResponse builds and signs the OCSP response for req. Cached responses
// are returned directly when their TTL has not expired.
func (o *OCSPResponder) createResponse(req *ocsp.Request) ([]byte, error) {
	cacheKey := ocspCacheKey(req.SerialNumber)
	if cached := o.getCachedResponse(cacheKey); cached != nil {
		return cached, nil
	}

	// Select the issuing certificate + signer. The intermediate, when
	// present, signs responses for certificates it issued; a root-only CA
	// signs with its own key.
	o.ca.mu.RLock()
	var issuerCert *x509.Certificate
	if o.ca.config.HasIntermediate() {
		issuerCert = o.ca.intermediateCert
	} else {
		issuerCert = o.ca.rootCert
	}
	o.ca.mu.RUnlock()
	if issuerCert == nil {
		return nil, fmt.Errorf("%w: no issuing certificate", ErrOCSPResponseFailed)
	}

	signer, err := o.ca.Signer()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPSigningFailed, err)
	}

	status, revocationTime, revocationReason, err := o.checkCertificateStatus(req.SerialNumber)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		ThisUpdate:       now,
		NextUpdate:       now.Add(o.config.NextUpdate),
		ProducedAt:       now,
		Certificate:      issuerCert,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revocationTime,
		RevocationReason: revocationReason,
	}

	responseBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, template, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPResponseFailed, err)
	}

	o.cacheResponse(cacheKey, responseBytes)
	return responseBytes, nil
}

// checkCertificateStatus reports whether the given serial number is revoked.
// Storage lookups first consult the in-memory revocation map (always
// populated for recent revocations) and fall back to the object store so
// revocations persisted before the current process started are visible.
func (o *OCSPResponder) checkCertificateStatus(serial *big.Int) (int, time.Time, int, error) {
	// Hot path: in-memory check — RevokeCert and Revoke both update this map.
	o.ca.revocationsMutex.RLock()
	info, revoked := o.ca.revocations[serial.Text(10)]
	o.ca.revocationsMutex.RUnlock()
	if revoked {
		return ocsp.Revoked, info.RevocationTime, info.Reason, nil
	}

	// Cold path: consult the object store (when configured). Load() normally
	// populates the in-memory map, but a fresh CA that hasn't been reloaded
	// since another instance wrote a revocation still needs to read through.
	if o.ca.objectStore == nil {
		return ocsp.Good, time.Time{}, 0, nil
	}

	rec, err := o.loadRevocationFromStore(serial)
	if err != nil {
		if errors.Is(err, ErrCRLNotFound) {
			return ocsp.Good, time.Time{}, 0, nil
		}
		return ocsp.Unknown, time.Time{}, 0, fmt.Errorf("%w: %v", ErrOCSPStorageError, err)
	}
	return ocsp.Revoked, rec.RevokedAt, rec.Reason, nil
}

// loadRevocationFromStore reads a single persistedRevocation from the
// object store. Returns ErrCRLNotFound when no record exists for serial.
func (o *OCSPResponder) loadRevocationFromStore(serial *big.Int) (*persistedRevocation, error) {
	key := revocationKey(serial) + ".json"
	reader, err := o.ca.objectStore.Get(key)
	if err != nil {
		// List-and-scan fallback for backends that return opaque errors
		// on missing keys. Keeps the responder robust against divergent
		// store implementations.
		keys, listErr := o.ca.objectStore.List(revocationKeyPrefix)
		if listErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrOCSPStorageError, listErr)
		}
		for _, k := range keys {
			if k == key {
				// Key exists in listing but Get failed — surface the
				// original Get error rather than pretending it's absent.
				return nil, fmt.Errorf("%w: %v", ErrOCSPStorageError, err)
			}
		}
		return nil, ErrCRLNotFound
	}
	defer func() { _ = reader.Close() }()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPStorageError, err)
	}
	var rec persistedRevocation
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPStorageError, err)
	}
	return &rec, nil
}

// =============================================================================
// Cache Helpers
// =============================================================================

// ocspCacheKey builds a deterministic cache key from a serial number.
func ocspCacheKey(serial *big.Int) string {
	return "ocsp:" + serial.Text(10)
}

// getCachedResponse returns the cached response for key, or nil when absent
// or expired.
func (o *OCSPResponder) getCachedResponse(key string) []byte {
	o.cacheMu.RLock()
	defer o.cacheMu.RUnlock()
	cached, ok := o.cache[key]
	if !ok {
		return nil
	}
	if time.Now().After(cached.expiresAt) {
		return nil
	}
	return cached.response
}

// cacheResponse stores a signed OCSP response in the cache.
func (o *OCSPResponder) cacheResponse(key string, response []byte) {
	o.cacheMu.Lock()
	defer o.cacheMu.Unlock()
	o.cache[key] = &cachedOCSPResponse{
		response:  response,
		expiresAt: time.Now().Add(o.config.CacheTTL),
	}
}

// ClearCache drops every cached OCSP response. Use after bulk revocations
// so clients see the new status without waiting for cache expiry.
func (o *OCSPResponder) ClearCache() {
	o.cacheMu.Lock()
	defer o.cacheMu.Unlock()
	o.cache = make(map[string]*cachedOCSPResponse)
}

// =============================================================================
// Helpers for Callers / Tests
// =============================================================================

// VerifyOCSPResponse parses and returns a previously-produced OCSP response
// without signature validation — useful for diagnostics and round-trip tests.
func (o *OCSPResponder) VerifyOCSPResponse(responseBytes []byte) (*ocsp.Response, error) {
	if len(responseBytes) == 0 {
		return nil, ErrOCSPInvalidRequest
	}
	resp, err := ocsp.ParseResponse(responseBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPResponseFailed, err)
	}
	return resp, nil
}

// CreateOCSPRequest builds a DER-encoded OCSP request for the given
// (cert, issuer) pair. Primarily intended for testing.
func CreateOCSPRequest(cert *x509.Certificate, issuer *x509.Certificate, opts *ocsp.RequestOptions) ([]byte, error) {
	if cert == nil || issuer == nil {
		return nil, ErrInvalidCertificate
	}
	if opts == nil {
		opts = &ocsp.RequestOptions{Hash: crypto.SHA256}
	}
	data, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPRequestParseFailed, err)
	}
	return data, nil
}

// Assert that bytes.Reader is imported for response builder (keeps the
// import needed when the tree shakes unused imports via goimports).
var _ = bytes.NewReader
