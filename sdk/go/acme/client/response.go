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

// Package client provides shared utilities for ACME SDK client implementations.
package client

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// MapResponse converts a transport response to a typed response struct.
// It extracts the parsed data from the transport response and decodes it
// into the target struct using JSON re-marshaling for transport-agnostic
// type conversion.
func MapResponse(raw interface{}, target interface{}) error {
	if raw == nil {
		return errors.NewInternal("client.MapResponse", "nil response from transport")
	}
	if target == nil {
		return errors.NewInvalidInput("client.MapResponse", "nil target for response mapping")
	}

	data := extractData(raw)
	if data == nil {
		return errors.NewInternal("client.MapResponse", "no data in transport response")
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "client.MapResponse",
			"failed to marshal response data")
	}

	if err := json.Unmarshal(jsonBytes, target); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "client.MapResponse",
			"failed to unmarshal response into target")
	}

	return nil
}

// ExtractNonce extracts the nonce from a transport response if available.
func ExtractNonce(raw interface{}) string {
	if raw == nil {
		return ""
	}

	m := marshalToMap(raw)
	if m == nil {
		return ""
	}

	if n, ok := m["Nonce"].(string); ok {
		return n
	}
	if n, ok := m["nonce"].(string); ok {
		return n
	}

	return ""
}

// ExtractLocation extracts the location URL from a transport response if available.
func ExtractLocation(raw interface{}) string {
	if raw == nil {
		return ""
	}

	m := marshalToMap(raw)
	if m == nil {
		return ""
	}

	if l, ok := m["Location"].(string); ok {
		return l
	}
	if l, ok := m["location"].(string); ok {
		return l
	}

	return ""
}

// ExtractBody extracts the raw body bytes from a transport response if available.
func ExtractBody(raw interface{}) []byte {
	if raw == nil {
		return nil
	}

	m := marshalToMap(raw)
	if m == nil {
		return nil
	}

	// Body is stored as base64-encoded string in JSON
	if b, ok := m["Body"].(string); ok {
		return []byte(b)
	}
	if b, ok := m["body"].(string); ok {
		return []byte(b)
	}

	return nil
}

// IsPEMResponse returns true if the transport response contains PEM data.
func IsPEMResponse(raw interface{}) bool {
	if raw == nil {
		return false
	}

	m := marshalToMap(raw)
	if m == nil {
		return false
	}

	if isPEM, ok := m["IsPEM"].(bool); ok {
		return isPEM
	}
	if isPEM, ok := m["isPEM"].(bool); ok {
		return isPEM
	}

	return false
}

// ExtractLinks extracts Link header URLs from a transport response.
func ExtractLinks(raw interface{}) []string {
	if raw == nil {
		return nil
	}

	m := marshalToMap(raw)
	if m == nil {
		return nil
	}

	// Extract headers map and parse Link header values
	headersRaw, ok := m["Headers"]
	if !ok {
		headersRaw, ok = m["headers"]
		if !ok {
			return nil
		}
	}

	headersMap, ok := headersRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	linkValues, ok := headersMap["Link"]
	if !ok {
		return nil
	}

	linkSlice, ok := linkValues.([]interface{})
	if !ok {
		return nil
	}

	var links []string
	for _, v := range linkSlice {
		if s, ok := v.(string); ok {
			links = append(links, parseLinkURL(s))
		}
	}

	return links
}

// ExtractStatusCode extracts the HTTP status code from a transport response.
func ExtractStatusCode(raw interface{}) int {
	if raw == nil {
		return 0
	}

	m := marshalToMap(raw)
	if m == nil {
		return 0
	}

	if sc, ok := m["StatusCode"].(float64); ok {
		return int(sc)
	}
	if sc, ok := m["statusCode"].(float64); ok {
		return int(sc)
	}

	return 0
}

// ExtractHeaders extracts HTTP headers from a transport response.
func ExtractHeaders(raw interface{}) http.Header {
	if raw == nil {
		return nil
	}

	m := marshalToMap(raw)
	if m == nil {
		return nil
	}

	headersRaw, ok := m["Headers"]
	if !ok {
		headersRaw, ok = m["headers"]
		if !ok {
			return nil
		}
	}

	headersMap, ok := headersRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	headers := make(http.Header)
	for key, val := range headersMap {
		if arr, ok := val.([]interface{}); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					headers.Add(key, s)
				}
			}
		}
	}

	return headers
}

// extractData extracts the parsed data from a transport response.
// For REST responses, this is the Data field containing parsed JSON.
// For other responses, it attempts to find a data-bearing field.
func extractData(raw interface{}) map[string]interface{} {
	m := marshalToMap(raw)
	if m == nil {
		return nil
	}

	// If there's a Data field (REST Response), prefer that
	if data, ok := m["Data"].(map[string]interface{}); ok {
		return data
	}
	if data, ok := m["data"].(map[string]interface{}); ok {
		return data
	}

	return m
}

// marshalToMap converts an arbitrary struct to a map via JSON round-trip.
func marshalToMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}

	// Fast path for map types
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}

	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil
	}

	return result
}

// parseLinkURL extracts the URL from a Link header value.
// Link header format: <url>; rel="relation"
func parseLinkURL(link string) string {
	link = strings.TrimSpace(link)
	if len(link) == 0 {
		return ""
	}

	start := strings.IndexByte(link, '<')
	end := strings.IndexByte(link, '>')
	if start >= 0 && end > start {
		return link[start+1 : end]
	}

	return link
}
