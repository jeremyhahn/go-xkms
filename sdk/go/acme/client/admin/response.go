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

package admin

import (
	"encoding/base64"
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// extractResponseData extracts the actual JSON data from a transport response.
// Different transports return data differently:
// - REST: Response{Data: map[string]interface{}{...}} (parsed JSON in Data field)
// - gRPC: map[string]interface{}{...} (direct parsed JSON)
// - Unix: Response{Body: []byte{...}} (raw JSON bytes in Body field)
// - MCP: json.RawMessage (raw JSON bytes)
func extractResponseData(raw interface{}) ([]byte, error) {
	// If raw is already a map (gRPC transport), marshal it directly.
	if m, ok := raw.(map[string]interface{}); ok {
		return json.Marshal(m)
	}

	// Marshal the transport response to inspect its structure.
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "admin.extractResponseData",
			"failed to marshal transport response")
	}

	// Try to parse as a map to find Data or Body fields.
	var wrapper map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &wrapper); err != nil {
		// Not a map - return the raw bytes (might be a JSON value directly).
		return jsonBytes, nil
	}

	// REST transport: Data contains the parsed JSON response.
	if data, ok := wrapper["Data"].(map[string]interface{}); ok {
		return json.Marshal(data)
	}

	// Unix transport: Body contains base64-encoded raw JSON bytes.
	if bodyStr, ok := wrapper["Body"].(string); ok && bodyStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(bodyStr)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "admin.extractResponseData",
				"failed to decode Body field")
		}
		return decoded, nil
	}

	// Fallback: use the wrapper map itself.
	return json.Marshal(wrapper)
}

// mapResponse converts a raw transport response into the target struct.
func mapResponse(raw interface{}, target interface{}) error {
	if raw == nil {
		return errors.NewInternal("admin.mapResponse", "nil response from transport")
	}

	dataBytes, err := extractResponseData(raw)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(dataBytes, target); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "admin.mapResponse",
			"failed to decode response data")
	}

	return nil
}

// mapListResponse converts a raw transport response into a slice target
// and extracts pagination metadata.
func mapListResponse(raw interface{}, itemsKey string, items interface{}, pagination **Pagination) error {
	if raw == nil {
		return errors.NewInternal("admin.mapListResponse", "nil response from transport")
	}

	dataBytes, err := extractResponseData(raw)
	if err != nil {
		return err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "admin.mapListResponse",
			"failed to unmarshal response data")
	}

	// Extract items: try "items" key first, then legacy itemsKey.
	itemsRaw, ok := data["items"]
	if !ok {
		itemsRaw, ok = data[itemsKey]
	}
	if ok && itemsRaw != nil {
		itemsBytes, err := json.Marshal(itemsRaw)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "admin.mapListResponse",
				"failed to marshal list items")
		}
		if err := json.Unmarshal(itemsBytes, items); err != nil {
			return errors.Wrap(err, errors.CodeInternal, "admin.mapListResponse",
				"failed to decode list items")
		}
	}

	// Extract pagination from top-level fields.
	if pagination != nil {
		p := &Pagination{}
		if total, ok := data["total"].(float64); ok {
			p.Total = int(total)
		}
		if page, ok := data["page"].(float64); ok {
			p.Page = int(page)
		}
		if perPage, ok := data["per_page"].(float64); ok {
			p.PerPage = int(perPage)
		}
		if p.Total > 0 || p.Page > 0 {
			*pagination = p
		}
	}

	return nil
}
