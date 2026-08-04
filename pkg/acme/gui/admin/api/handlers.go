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

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// handlers holds shared state for all GUI API handlers.
type handlers struct {
	client trustedca.Client
	logger *slog.Logger
}

func newHandlers(client trustedca.Client, logger *slog.Logger) *handlers {
	return &handlers{
		client: client,
		logger: logger,
	}
}

// apiResponse matches the admin API response envelope.
type apiResponse struct {
	Success    bool        `json:"success"`
	Data       interface{} `json:"data,omitempty"`
	Error      *errorInfo  `json:"error,omitempty"`
	Pagination interface{} `json:"pagination,omitempty"`
}

type errorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}, pagination interface{}) {
	resp := apiResponse{
		Success:    true,
		Data:       data,
		Pagination: pagination,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeErrorResponse(w http.ResponseWriter, statusCode int, code, message string) {
	resp := apiResponse{
		Success: false,
		Error: &errorInfo{
			Code:    code,
			Message: message,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

func parseInt(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}
	return val
}
