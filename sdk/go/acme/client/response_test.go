// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

func TestMapResponse(t *testing.T) {
	t.Run("success_with_data_field", func(t *testing.T) {
		raw := map[string]interface{}{
			"Data": map[string]interface{}{
				"name":  "test",
				"value": float64(42),
			},
			"Nonce":    "abc123",
			"Location": "https://example.com/acme/acct/1",
		}

		type target struct {
			Name  string  `json:"name"`
			Value float64 `json:"value"`
		}

		var result target
		err := MapResponse(raw, &result)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Name != "test" {
			t.Errorf("expected name 'test', got %q", result.Name)
		}
		if result.Value != 42 {
			t.Errorf("expected value 42, got %f", result.Value)
		}
	})

	t.Run("success_with_direct_map", func(t *testing.T) {
		raw := map[string]interface{}{
			"status":  "valid",
			"contact": []interface{}{"mailto:test@example.com"},
		}

		type target struct {
			Status  string   `json:"status"`
			Contact []string `json:"contact"`
		}

		var result target
		err := MapResponse(raw, &result)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != "valid" {
			t.Errorf("expected status 'valid', got %q", result.Status)
		}
		if len(result.Contact) != 1 || result.Contact[0] != "mailto:test@example.com" {
			t.Errorf("unexpected contact: %v", result.Contact)
		}
	})

	t.Run("success_with_lowercase_data_field", func(t *testing.T) {
		raw := map[string]interface{}{
			"data": map[string]interface{}{
				"name": "lowercase-data",
			},
		}

		type target struct {
			Name string `json:"name"`
		}

		var result target
		err := MapResponse(raw, &result)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Name != "lowercase-data" {
			t.Errorf("expected name 'lowercase-data', got %q", result.Name)
		}
	})

	t.Run("success_with_struct_response", func(t *testing.T) {
		type response struct {
			Data map[string]interface{} `json:"Data"`
		}
		raw := &response{
			Data: map[string]interface{}{
				"name": "struct-response",
			},
		}

		type target struct {
			Name string `json:"name"`
		}

		var result target
		err := MapResponse(raw, &result)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Name != "struct-response" {
			t.Errorf("expected name 'struct-response', got %q", result.Name)
		}
	})

	t.Run("error_nil_response", func(t *testing.T) {
		type target struct{}
		var result target
		err := MapResponse(nil, &result)
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})

	t.Run("error_nil_target", func(t *testing.T) {
		raw := map[string]interface{}{"key": "value"}
		err := MapResponse(raw, nil)
		if err == nil {
			t.Fatal("expected error for nil target")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got: %v", err)
		}
	})

	t.Run("error_non_map_response", func(t *testing.T) {
		// A string that can't be marshaled to a map
		raw := "just a string"
		type target struct {
			Name string `json:"name"`
		}
		var result target
		err := MapResponse(raw, &result)
		if err == nil {
			t.Fatal("expected error for non-map response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}

func TestExtractNonce(t *testing.T) {
	t.Run("success_uppercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"Nonce": "nonce-abc-123",
		}
		nonce := ExtractNonce(raw)
		if nonce != "nonce-abc-123" {
			t.Errorf("expected 'nonce-abc-123', got %q", nonce)
		}
	})

	t.Run("success_lowercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"nonce": "nonce-xyz",
		}
		nonce := ExtractNonce(raw)
		if nonce != "nonce-xyz" {
			t.Errorf("expected 'nonce-xyz', got %q", nonce)
		}
	})

	t.Run("empty_on_nil", func(t *testing.T) {
		nonce := ExtractNonce(nil)
		if nonce != "" {
			t.Errorf("expected empty string, got %q", nonce)
		}
	})

	t.Run("empty_when_missing", func(t *testing.T) {
		raw := map[string]interface{}{
			"other": "field",
		}
		nonce := ExtractNonce(raw)
		if nonce != "" {
			t.Errorf("expected empty string, got %q", nonce)
		}
	})
}

func TestExtractLocation(t *testing.T) {
	t.Run("success_uppercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"Location": "https://example.com/acme/acct/1",
		}
		loc := ExtractLocation(raw)
		if loc != "https://example.com/acme/acct/1" {
			t.Errorf("expected location URL, got %q", loc)
		}
	})

	t.Run("success_lowercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"location": "https://example.com/acme/acct/2",
		}
		loc := ExtractLocation(raw)
		if loc != "https://example.com/acme/acct/2" {
			t.Errorf("expected location URL, got %q", loc)
		}
	})

	t.Run("empty_on_nil", func(t *testing.T) {
		loc := ExtractLocation(nil)
		if loc != "" {
			t.Errorf("expected empty string, got %q", loc)
		}
	})

	t.Run("empty_when_missing", func(t *testing.T) {
		raw := map[string]interface{}{
			"other": "field",
		}
		loc := ExtractLocation(raw)
		if loc != "" {
			t.Errorf("expected empty string, got %q", loc)
		}
	})
}

func TestExtractBody(t *testing.T) {
	t.Run("success_uppercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"Body": "certificate-pem-data",
		}
		body := ExtractBody(raw)
		if string(body) != "certificate-pem-data" {
			t.Errorf("expected body data, got %q", string(body))
		}
	})

	t.Run("success_lowercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"body": "lowercase-body-data",
		}
		body := ExtractBody(raw)
		if string(body) != "lowercase-body-data" {
			t.Errorf("expected body data, got %q", string(body))
		}
	})

	t.Run("nil_on_nil_response", func(t *testing.T) {
		body := ExtractBody(nil)
		if body != nil {
			t.Errorf("expected nil, got %v", body)
		}
	})

	t.Run("nil_when_missing", func(t *testing.T) {
		raw := map[string]interface{}{
			"other": "field",
		}
		body := ExtractBody(raw)
		if body != nil {
			t.Errorf("expected nil, got %v", body)
		}
	})
}

func TestIsPEMResponse(t *testing.T) {
	t.Run("true_when_pem_uppercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"IsPEM": true,
		}
		if !IsPEMResponse(raw) {
			t.Error("expected true for PEM response")
		}
	})

	t.Run("true_when_pem_lowercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"isPEM": true,
		}
		if !IsPEMResponse(raw) {
			t.Error("expected true for lowercase PEM response")
		}
	})

	t.Run("false_when_not_pem", func(t *testing.T) {
		raw := map[string]interface{}{
			"IsPEM": false,
		}
		if IsPEMResponse(raw) {
			t.Error("expected false for non-PEM response")
		}
	})

	t.Run("false_on_nil", func(t *testing.T) {
		if IsPEMResponse(nil) {
			t.Error("expected false for nil response")
		}
	})

	t.Run("false_when_missing", func(t *testing.T) {
		raw := map[string]interface{}{
			"other": "field",
		}
		if IsPEMResponse(raw) {
			t.Error("expected false when IsPEM field missing")
		}
	})
}

func TestExtractStatusCode(t *testing.T) {
	t.Run("success_uppercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"StatusCode": float64(200),
		}
		code := ExtractStatusCode(raw)
		if code != 200 {
			t.Errorf("expected 200, got %d", code)
		}
	})

	t.Run("success_lowercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"statusCode": float64(404),
		}
		code := ExtractStatusCode(raw)
		if code != 404 {
			t.Errorf("expected 404, got %d", code)
		}
	})

	t.Run("zero_on_nil", func(t *testing.T) {
		code := ExtractStatusCode(nil)
		if code != 0 {
			t.Errorf("expected 0, got %d", code)
		}
	})

	t.Run("zero_when_missing", func(t *testing.T) {
		raw := map[string]interface{}{
			"other": "field",
		}
		code := ExtractStatusCode(raw)
		if code != 0 {
			t.Errorf("expected 0, got %d", code)
		}
	})
}

func TestExtractHeaders(t *testing.T) {
	t.Run("success_uppercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"Headers": map[string]interface{}{
				"Content-Type": []interface{}{"application/json"},
				"X-Custom":     []interface{}{"val1", "val2"},
			},
		}
		headers := ExtractHeaders(raw)
		if headers == nil {
			t.Fatal("expected non-nil headers")
		}
		if headers.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type, got %q", headers.Get("Content-Type"))
		}
		if len(headers.Values("X-Custom")) != 2 {
			t.Errorf("expected 2 X-Custom values, got %d", len(headers.Values("X-Custom")))
		}
	})

	t.Run("success_lowercase", func(t *testing.T) {
		raw := map[string]interface{}{
			"headers": map[string]interface{}{
				"Content-Type": []interface{}{"text/plain"},
			},
		}
		headers := ExtractHeaders(raw)
		if headers == nil {
			t.Fatal("expected non-nil headers")
		}
		if headers.Get("Content-Type") != "text/plain" {
			t.Errorf("expected Content-Type text/plain, got %q", headers.Get("Content-Type"))
		}
	})

	t.Run("nil_on_nil_response", func(t *testing.T) {
		headers := ExtractHeaders(nil)
		if headers != nil {
			t.Errorf("expected nil, got %v", headers)
		}
	})

	t.Run("nil_when_no_headers", func(t *testing.T) {
		raw := map[string]interface{}{
			"other": "field",
		}
		headers := ExtractHeaders(raw)
		if headers != nil {
			t.Errorf("expected nil, got %v", headers)
		}
	})

	t.Run("nil_when_headers_not_map", func(t *testing.T) {
		raw := map[string]interface{}{
			"Headers": "not-a-map",
		}
		headers := ExtractHeaders(raw)
		if headers != nil {
			t.Errorf("expected nil for non-map headers, got %v", headers)
		}
	})

	t.Run("skips_non_string_values", func(t *testing.T) {
		raw := map[string]interface{}{
			"Headers": map[string]interface{}{
				"Good": []interface{}{"value"},
				"Bad":  []interface{}{123},
			},
		}
		headers := ExtractHeaders(raw)
		if headers == nil {
			t.Fatal("expected non-nil headers")
		}
		if headers.Get("Good") != "value" {
			t.Errorf("expected Good header, got %q", headers.Get("Good"))
		}
		if len(headers.Values("Bad")) != 0 {
			t.Errorf("expected no Bad values, got %v", headers.Values("Bad"))
		}
	})

	t.Run("empty_headers_returns_empty", func(t *testing.T) {
		raw := map[string]interface{}{
			"Headers": map[string]interface{}{},
		}
		headers := ExtractHeaders(raw)
		if headers == nil {
			t.Fatal("expected non-nil headers")
		}
		if len(headers) != 0 {
			t.Errorf("expected empty headers, got %v", headers)
		}
	})
}

func TestExtractLinks(t *testing.T) {
	t.Run("success_with_link_header", func(t *testing.T) {
		raw := map[string]interface{}{
			"Headers": map[string]interface{}{
				"Link": []interface{}{
					`<https://example.com/acme/cert/alt>; rel="alternate"`,
				},
			},
		}
		links := ExtractLinks(raw)
		if len(links) != 1 {
			t.Fatalf("expected 1 link, got %d", len(links))
		}
		if links[0] != "https://example.com/acme/cert/alt" {
			t.Errorf("expected alt cert URL, got %q", links[0])
		}
	})

	t.Run("nil_when_no_headers", func(t *testing.T) {
		raw := map[string]interface{}{
			"StatusCode": float64(200),
		}
		links := ExtractLinks(raw)
		if links != nil {
			t.Errorf("expected nil, got %v", links)
		}
	})

	t.Run("nil_on_nil_response", func(t *testing.T) {
		links := ExtractLinks(nil)
		if links != nil {
			t.Errorf("expected nil, got %v", links)
		}
	})

	t.Run("nil_when_no_link_key", func(t *testing.T) {
		raw := map[string]interface{}{
			"Headers": map[string]interface{}{
				"Content-Type": []interface{}{"application/json"},
			},
		}
		links := ExtractLinks(raw)
		if links != nil {
			t.Errorf("expected nil when no Link header, got %v", links)
		}
	})

	t.Run("nil_when_link_not_slice", func(t *testing.T) {
		raw := map[string]interface{}{
			"Headers": map[string]interface{}{
				"Link": "not-a-slice",
			},
		}
		links := ExtractLinks(raw)
		if links != nil {
			t.Errorf("expected nil for non-slice Link, got %v", links)
		}
	})

	t.Run("lowercase_headers", func(t *testing.T) {
		raw := map[string]interface{}{
			"headers": map[string]interface{}{
				"Link": []interface{}{
					`<https://example.com/alt>; rel="alternate"`,
				},
			},
		}
		links := ExtractLinks(raw)
		if len(links) != 1 {
			t.Fatalf("expected 1 link, got %d", len(links))
		}
	})

	t.Run("headers_not_map", func(t *testing.T) {
		raw := map[string]interface{}{
			"Headers": "not-a-map",
		}
		links := ExtractLinks(raw)
		if links != nil {
			t.Errorf("expected nil for non-map headers, got %v", links)
		}
	})
}

func TestParseLinkURL(t *testing.T) {
	t.Run("standard_format", func(t *testing.T) {
		url := parseLinkURL(`<https://example.com/cert>; rel="alternate"`)
		if url != "https://example.com/cert" {
			t.Errorf("expected URL, got %q", url)
		}
	})

	t.Run("empty_string", func(t *testing.T) {
		url := parseLinkURL("")
		if url != "" {
			t.Errorf("expected empty string, got %q", url)
		}
	})

	t.Run("no_angle_brackets", func(t *testing.T) {
		url := parseLinkURL("https://example.com/cert")
		if url != "https://example.com/cert" {
			t.Errorf("expected raw URL, got %q", url)
		}
	})

	t.Run("whitespace_trimmed", func(t *testing.T) {
		url := parseLinkURL("  <https://example.com/cert>; rel=\"alternate\"  ")
		if url != "https://example.com/cert" {
			t.Errorf("expected URL with trimmed whitespace, got %q", url)
		}
	})
}

func TestMarshalToMap(t *testing.T) {
	t.Run("nil_returns_nil", func(t *testing.T) {
		result := marshalToMap(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("map_fast_path", func(t *testing.T) {
		m := map[string]interface{}{"key": "value"}
		result := marshalToMap(m)
		if result == nil {
			t.Fatal("expected non-nil map")
		}
		if result["key"] != "value" {
			t.Errorf("expected key=value, got %v", result["key"])
		}
	})

	t.Run("struct_to_map", func(t *testing.T) {
		type s struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}
		result := marshalToMap(&s{Name: "test", Value: 42})
		if result == nil {
			t.Fatal("expected non-nil map")
		}
		if result["name"] != "test" {
			t.Errorf("expected name=test, got %v", result["name"])
		}
	})

	t.Run("non_marshalable_returns_nil", func(t *testing.T) {
		result := marshalToMap(make(chan int))
		if result != nil {
			t.Errorf("expected nil for non-marshalable type, got %v", result)
		}
	})

	t.Run("non_map_json_returns_nil", func(t *testing.T) {
		// A slice marshals to JSON array, which can't unmarshal to map
		result := marshalToMap([]string{"a", "b"})
		if result != nil {
			t.Errorf("expected nil for JSON array, got %v", result)
		}
	})
}

func TestExtractData(t *testing.T) {
	t.Run("returns_data_field", func(t *testing.T) {
		raw := map[string]interface{}{
			"Data": map[string]interface{}{
				"key": "value",
			},
		}
		result := extractData(raw)
		if result == nil {
			t.Fatal("expected non-nil data")
		}
		if result["key"] != "value" {
			t.Errorf("expected key=value, got %v", result["key"])
		}
	})

	t.Run("returns_map_when_no_data_field", func(t *testing.T) {
		raw := map[string]interface{}{
			"key": "value",
		}
		result := extractData(raw)
		if result == nil {
			t.Fatal("expected non-nil data")
		}
		if result["key"] != "value" {
			t.Errorf("expected key=value, got %v", result["key"])
		}
	})

	t.Run("nil_on_nil", func(t *testing.T) {
		result := extractData(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("non_map_data_field_returns_wrapper", func(t *testing.T) {
		raw := map[string]interface{}{
			"Data": "not-a-map",
			"key":  "value",
		}
		result := extractData(raw)
		if result == nil {
			t.Fatal("expected non-nil data")
		}
		if result["key"] != "value" {
			t.Errorf("expected key=value from wrapper, got %v", result["key"])
		}
	})
}

// Verify ExtractHeaders returns proper http.Header type.
func TestExtractHeaders_HTTPHeaderType(t *testing.T) {
	raw := map[string]interface{}{
		"Headers": map[string]interface{}{
			"Content-Type": []interface{}{"application/json"},
		},
	}
	headers := ExtractHeaders(raw)
	if headers == nil {
		t.Fatal("expected non-nil headers")
	}
	// Verify it's the correct type
	_ = headers
}
