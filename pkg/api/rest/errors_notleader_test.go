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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

func TestHandleError_NotLeader(t *testing.T) {
	rec := httptest.NewRecorder()
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 2, LeaderAddress: "10.0.0.2:63001"}

	// Simulate the servicer error reaching a handler wrapped in business context.
	handleError(rec, fmt.Errorf("generate key: %w", src))

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
	if got := rec.Header().Get("X-XKMS-Leader-Address"); got != "10.0.0.2:63001" {
		t.Fatalf("X-XKMS-Leader-Address = %q, want 10.0.0.2:63001", got)
	}
	if got := rec.Header().Get("X-XKMS-Leader-ID"); got != "2" {
		t.Fatalf("X-XKMS-Leader-ID = %q, want 2", got)
	}
	if got := rec.Header().Get("X-XKMS-Shard-ID"); got != "1" {
		t.Fatalf("X-XKMS-Shard-ID = %q, want 1", got)
	}

	var body NotLeaderResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ShardID != 1 || body.LeaderID != 2 || body.LeaderAddress != "10.0.0.2:63001" {
		t.Fatalf("body = %+v, want shard 1 / leader 2 / 10.0.0.2:63001", body)
	}
}

func TestHandleError_NotLeaderUnknown(t *testing.T) {
	rec := httptest.NewRecorder()
	handleError(rec, &qrdbtransport.NotLeaderError{ShardID: 4})

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
	// Leader unknown: no leader headers should be emitted.
	if got := rec.Header().Get("X-XKMS-Leader-ID"); got != "" {
		t.Fatalf("X-XKMS-Leader-ID = %q, want empty", got)
	}
	if got := rec.Header().Get("X-XKMS-Leader-Address"); got != "" {
		t.Fatalf("X-XKMS-Leader-Address = %q, want empty", got)
	}
}

func TestHandleError_NonLeaderUnaffected(t *testing.T) {
	rec := httptest.NewRecorder()
	handleError(rec, ErrInvalidRequest)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (non-leader error mapping unchanged)", rec.Code, http.StatusBadRequest)
	}
}
