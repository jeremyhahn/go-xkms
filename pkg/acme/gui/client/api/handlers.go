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

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/workflow"
)

// handlers holds all HTTP handler methods and shared dependencies.
// The workflow field handles Register and Revoke operations through the SDK
// transport layer, while the service field handles operations that require
// local infrastructure (certificate requests, renewals, and device
// operations).
type handlers struct {
	wf      workflow.Workflow
	service *svc.Service
	logger  *slog.Logger
}

// newHandlers creates a new handlers instance. The workflow parameter may be
// nil when no SDK client is configured; in that case all operations fall back
// to the service layer.
func newHandlers(wf workflow.Workflow, service *svc.Service, logger *slog.Logger) *handlers {
	return &handlers{
		wf:      wf,
		service: service,
		logger:  logger,
	}
}

// apiResponse is the standard JSON response envelope.
type apiResponse struct {
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(&apiResponse{Data: data}); err != nil {
		// Headers and status are already written; there is no way to
		// report this to the client, so it's only logged.
		slog.Error("failed to write JSON response", slog.String("error", err.Error()))
	}
}

// writeError writes a JSON error response with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(&apiResponse{Error: msg}); err != nil {
		slog.Error("failed to write JSON error response", slog.String("error", err.Error()))
	}
}
