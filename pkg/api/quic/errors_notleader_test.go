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

package quic

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

func testServer() *Server {
	return &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestSendServiceError_NotLeader(t *testing.T) {
	s := testServer()
	rec := httptest.NewRecorder()
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 2, LeaderAddress: "10.0.0.2:63001"}

	s.sendServiceError(rec, &errs.Wrapped{Msg: "generate key", Err: src}, http.StatusInternalServerError, "failed to generate key")

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
	if got := rec.Header().Get("X-XKMS-Leader-Address"); got != "10.0.0.2:63001" {
		t.Fatalf("X-XKMS-Leader-Address = %q, want 10.0.0.2:63001", got)
	}
	if got := rec.Header().Get("X-XKMS-Shard-ID"); got != "1" {
		t.Fatalf("X-XKMS-Shard-ID = %q, want 1", got)
	}

	var body NotLeaderResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ShardID != 1 || body.LeaderID != 2 || body.LeaderAddress != "10.0.0.2:63001" {
		t.Fatalf("body = %+v", body)
	}
}

func TestSendServiceError_Fallback(t *testing.T) {
	s := testServer()
	rec := httptest.NewRecorder()

	s.sendServiceError(rec, &errs.Message{Msg: "disk full"}, http.StatusInternalServerError, "failed to generate key")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if rec.Header().Get("X-XKMS-Shard-ID") != "" {
		t.Fatal("unexpected leader header on non-leader error")
	}
}
