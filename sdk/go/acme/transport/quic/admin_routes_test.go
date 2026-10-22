// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"net/http"
	"testing"
)

// TestExtractAdminField pins the field-extraction contract used to
// substitute path parameters (e.g. {tenantId}) from an admin request: a
// present string field returns verbatim, a present numeric field is
// formatted as a base-10 integer (never scientific notation, since JSON
// unmarshals all numbers as float64), and every failure mode returns "".
func TestExtractAdminField(t *testing.T) {
	type req struct {
		TenantID string `json:"tenantId"`
		Count    int    `json:"count"`
	}

	tests := []struct {
		name  string
		req   interface{}
		field string
		want  string
	}{
		{"nil request", nil, "tenantId", ""},
		{"string field present", req{TenantID: "t-1"}, "tenantId", "t-1"},
		{"numeric field present", req{Count: 42}, "count", "42"},
		{"field absent", req{TenantID: "t-1"}, "missing", ""},
		{"unmarshalable request", make(chan int), "tenantId", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractAdminField(tc.req, tc.field); got != tc.want {
				t.Fatalf("extractAdminField(%v, %q) = %q, want %q", tc.req, tc.field, got, tc.want)
			}
		})
	}
}

// TestDecodeAdminJSONResponse pins the generic admin response decoder: an
// empty body decodes to (nil, nil) rather than a JSON decode error (some
// admin endpoints answer 204/200 with no body), a well-formed body decodes
// to its Go value, and malformed JSON surfaces the decode error.
func TestDecodeAdminJSONResponse(t *testing.T) {
	t.Run("empty body", func(t *testing.T) {
		got, err := decodeAdminJSONResponse(nil, http.Header{})
		if err != nil || got != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("well-formed body", func(t *testing.T) {
		got, err := decodeAdminJSONResponse([]byte(`{"status":"ok"}`), http.Header{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m, ok := got.(map[string]interface{})
		if !ok || m["status"] != "ok" {
			t.Fatalf("unexpected decoded value: %#v", got)
		}
	})

	t.Run("malformed body", func(t *testing.T) {
		_, err := decodeAdminJSONResponse([]byte(`{not valid json`), http.Header{})
		if err == nil {
			t.Fatal("expected a decode error for malformed JSON")
		}
	})
}

// TestResolveAdminURL pins dynamic admin URL resolution: a known route
// substitutes every path field from the request, an unknown route key
// resolves to "", and a request missing one of the required fields also
// resolves to "" rather than emitting a URL with a literal "{field}" in it.
func TestResolveAdminURL(t *testing.T) {
	type certReq struct {
		Serial string `json:"serial"`
	}
	type eabReq struct {
		TenantID string `json:"tenantId"`
		KID      string `json:"kid"`
	}

	t.Run("single field substitution", func(t *testing.T) {
		key := routeKey{service: "admin.certificate", method: "get"}
		got := resolveAdminURL("https://ca.example.test", key, certReq{Serial: "0xABC"})
		want := "https://ca.example.test/admin/certificates/0xABC"
		if got != want {
			t.Fatalf("resolveAdminURL = %q, want %q", got, want)
		}
	})

	t.Run("multi field substitution", func(t *testing.T) {
		key := routeKey{service: "admin.eab", method: "get"}
		got := resolveAdminURL("https://ca.example.test", key, eabReq{TenantID: "t-1", KID: "k-1"})
		want := "https://ca.example.test/api/v1/tenants/t-1/eab/k-1"
		if got != want {
			t.Fatalf("resolveAdminURL = %q, want %q", got, want)
		}
	})

	t.Run("unknown route key", func(t *testing.T) {
		key := routeKey{service: "admin.nonexistent", method: "get"}
		if got := resolveAdminURL("https://ca.example.test", key, certReq{Serial: "x"}); got != "" {
			t.Fatalf("resolveAdminURL for an unknown key = %q, want empty", got)
		}
	})

	t.Run("missing required field", func(t *testing.T) {
		key := routeKey{service: "admin.certificate", method: "get"}
		if got := resolveAdminURL("https://ca.example.test", key, certReq{}); got != "" {
			t.Fatalf("resolveAdminURL with a missing field = %q, want empty", got)
		}
	})

	t.Run("tenant list carries its pagination as the core query", func(t *testing.T) {
		type listReq struct {
			Page    int    `json:"page,omitempty"`
			PerPage int    `json:"per_page,omitempty"`
			Status  string `json:"status,omitempty"`
		}
		key := routeKey{service: "admin.tenant", method: "list"}
		got := resolveAdminURL("https://ca.example.test", key, listReq{Page: 2, PerPage: 25, Status: "active"})
		want := "https://ca.example.test/api/v1/tenants/?page=2&page_size=25&status=active"
		if got != want {
			t.Fatalf("resolveAdminURL = %q, want %q", got, want)
		}
	})

	t.Run("tenant list with a request that is not an object", func(t *testing.T) {
		key := routeKey{service: "admin.tenant", method: "list"}
		if got := resolveAdminURL("https://ca.example.test", key, []int{1}); got != "" {
			t.Fatalf("resolveAdminURL with an unencodable request = %q, want empty", got)
		}
	})
}

// TestAdminDynamicPath_BodyEncoder pins that the dynamic-path route's body
// encoder only serializes a body for POST/PUT (GET/DELETE never carry one).
func TestAdminDynamicPath_BodyEncoder(t *testing.T) {
	type body struct {
		Name string `json:"name"`
	}

	post := adminDynamicPath(http.MethodPost, "/api/v1/tenants/{tenantId}", "tenantId")
	data, err := post.bodyEncoder(body{Name: "acme"})
	if err != nil {
		t.Fatalf("POST bodyEncoder: %v", err)
	}
	if string(data) != `{"name":"acme"}` {
		t.Fatalf("POST bodyEncoder = %s, want the encoded JSON body", data)
	}

	get := adminDynamicPath(http.MethodGet, "/api/v1/tenants/{tenantId}", "tenantId")
	data, err = get.bodyEncoder(body{Name: "acme"})
	if err != nil || data != nil {
		t.Fatalf("GET bodyEncoder = (%v, %v), want (nil, nil)", data, err)
	}
}

// TestAdminDynamicFields_BodyEncoder mirrors
// TestAdminDynamicPath_BodyEncoder for the multi-field variant.
func TestAdminDynamicFields_BodyEncoder(t *testing.T) {
	type body struct {
		Status string `json:"status"`
	}

	put := adminDynamicFields(http.MethodPut, "/api/v1/tenants/{tenantId}/roles/{id}", "tenantId", "id")
	data, err := put.bodyEncoder(body{Status: "active"})
	if err != nil {
		t.Fatalf("PUT bodyEncoder: %v", err)
	}
	if string(data) != `{"status":"active"}` {
		t.Fatalf("PUT bodyEncoder = %s, want the encoded JSON body", data)
	}

	del := adminDynamicFields(http.MethodDelete, "/api/v1/tenants/{tenantId}/roles/{id}", "tenantId", "id")
	data, err = del.bodyEncoder(body{Status: "active"})
	if err != nil || data != nil {
		t.Fatalf("DELETE bodyEncoder = (%v, %v), want (nil, nil)", data, err)
	}
}
