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

package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected int
	}{
		{"ParseError", ErrCodeParseError, -32700},
		{"InvalidRequest", ErrCodeInvalidRequest, -32600},
		{"MethodNotFound", ErrCodeMethodNotFound, -32601},
		{"InvalidParams", ErrCodeInvalidParams, -32602},
		{"InternalError", ErrCodeInternalError, -32603},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.expected {
				t.Errorf("got %v, expected %v", tt.code, tt.expected)
			}
		})
	}
}

func TestKeyInfo_MarshalJSON_OmitsEmptyOptionalFields(t *testing.T) {
	keyInfo := KeyInfo{
		KeyID:   "minimal-key",
		KeyType: "SIGNING",
		Backend: "software",
	}

	data, err := json.Marshal(keyInfo)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if strings.Contains(jsonStr, "algorithm") {
		t.Errorf("expected algorithm field to be omitted when empty, got: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "public_key_pem") {
		t.Errorf("expected public_key_pem field to be omitted when empty, got: %s", jsonStr)
	}
}

func TestListKeysParams_MarshalJSON_EmptyBackend(t *testing.T) {
	params := ListKeysParams{}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if strings.Contains(jsonStr, "backend") {
		t.Errorf("expected backend field to be omitted when empty, got: %s", jsonStr)
	}
}
