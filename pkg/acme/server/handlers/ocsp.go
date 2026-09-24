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

package handlers

import (
	"context"
	"io"
	"log/slog"
	"net/http"
)

// OCSPResponderInterface defines the interface for OCSP request handling.
// This allows for dependency injection and easier testing.
type OCSPResponderInterface interface {
	// HandleRequest processes a DER-encoded OCSP request and returns a signed response.
	HandleRequest(ctx context.Context, requestBytes []byte) ([]byte, error)
}

// OCSPHandler handles OCSP requests at the /ocsp endpoint per RFC 6960
//
// OCSP (Online Certificate Status Protocol) allows clients to check if a certificate
// has been revoked by the issuing CA. This is an alternative to downloading and
// parsing CRLs (Certificate Revocation Lists).
//
// The handler supports POST requests with DER-encoded OCSP requests in the request body.
// It returns DER-encoded OCSP responses signed by the CA.
//
// Usage:
//
//	router.HandleFunc("/ocsp", OCSPHandler(ocspResponder)).Methods("POST")
func OCSPHandler(responder OCSPResponderInterface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests per RFC 6960 Section 4.2.1
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed. OCSP requires POST.", http.StatusMethodNotAllowed)
			return
		}

		// Read OCSP request from request body
		// Limit to 1MB to prevent abuse
		requestBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "Failed to read OCSP request", http.StatusBadRequest)
			return
		}
		defer func() { _ = r.Body.Close() }()

		// Validate request size
		if len(requestBytes) == 0 {
			http.Error(w, "Empty OCSP request", http.StatusBadRequest)
			return
		}

		// Process OCSP request
		responseBytes, err := responder.HandleRequest(r.Context(), requestBytes)
		if err != nil {
			// Log error for debugging
			// In production, you might want to use structured logging
			http.Error(w, "Failed to process OCSP request", http.StatusInternalServerError)
			return
		}

		// Set response headers per RFC 6960
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Header().Set("Cache-Control", "max-age=3600") // Cache for 1 hour

		// Write OCSP response
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(responseBytes); err != nil {
			slog.Error("failed to write OCSP response", slog.String("error", err.Error()))
		}
	}
}
