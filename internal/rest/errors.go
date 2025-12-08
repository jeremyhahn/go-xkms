// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// Common errors
var (
	ErrInvalidRequest  = errors.New("invalid request")
	ErrInvalidBackend  = errors.New("invalid backend")
	ErrInvalidKeyType  = errors.New("invalid key type")
	ErrMissingKeyID    = errors.New("missing key_id")
	ErrMissingBackend  = errors.New("missing backend parameter")
	ErrBackendNotFound = errors.New("backend not found")
	ErrInternalError   = errors.New("internal server error")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrForbidden       = errors.New("forbidden")
)

// writeError writes an error response to the client.
func writeError(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := ErrorResponse{
		Error: err.Error(),
		Code:  statusCode,
	}

	if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
		log.Printf("Failed to encode error response: %v", encErr)
	}
}

// writeErrorWithMessage writes an error response with a custom message.
func writeErrorWithMessage(w http.ResponseWriter, err error, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := ErrorResponse{
		Error:   err.Error(),
		Message: message,
		Code:    statusCode,
	}

	if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
		log.Printf("Failed to encode error response: %v", encErr)
	}
}

// mapErrorToStatusCode maps errors to HTTP status codes.
func mapErrorToStatusCode(err error) int {
	switch {
	case errors.Is(err, storage.ErrNotFound),
		errors.Is(err, backend.ErrKeyNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrInvalidBackend),
		errors.Is(err, ErrInvalidKeyType),
		errors.Is(err, ErrMissingKeyID),
		errors.Is(err, ErrMissingBackend),
		errors.Is(err, backend.ErrInvalidKeyType),
		errors.Is(err, backend.ErrInvalidKeyPartition):
		return http.StatusBadRequest
	case errors.Is(err, storage.ErrAlreadyExists):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// handleError is a convenience function that maps the error to a status code
// and writes the error response.
func handleError(w http.ResponseWriter, err error) {
	statusCode := mapErrorToStatusCode(err)
	writeError(w, err, statusCode)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
		writeError(w, err, http.StatusInternalServerError)
	}
}
