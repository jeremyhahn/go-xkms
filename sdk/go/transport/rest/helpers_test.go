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

package rest

import (
	"encoding/json"
	"net/http"
	"testing"
)

// writeJSON writes a JSON body with the given status code.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Logf("failed to encode response: %v", err)
	}
}

// writeErr writes a JSON error body matching the {"error": ...} shape the SDK
// client extracts for non-2xx responses.
func writeErr(t *testing.T, w http.ResponseWriter, status int, msg string) {
	t.Helper()
	writeJSON(t, w, status, map[string]string{"error": msg})
}
