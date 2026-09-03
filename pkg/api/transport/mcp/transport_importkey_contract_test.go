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
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestImportKey_ParamsReachTheHandlerStruct is the regression for go-xkms#159.
//
// Transport.ImportKey marshalled a transport.ImportKeyRequest straight onto the
// wire, but the handler decodes xkmsmcp.ImportKeyParams, and the two disagreed
// on the field carrying the key: "wrapped_key_material" against "wrapped_key".
// WrappedKey therefore arrived nil on every import, and aes_key_size, hash and
// partition were dropped with it.
//
// The assertion is deliberately made against the handler's own params struct
// rather than against a JSON blob: what matters is that what this transport
// sends is what the server-side struct actually receives.
func TestImportKey_ParamsReachTheHandlerStruct(t *testing.T) {
	var captured xkmsmcp.ImportKeyParams

	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		if err := json.Unmarshal(req.Params, &captured); err != nil {
			return jsonrpcResponse{ErrorText: err.Error()}
		}
		data, _ := json.Marshal(transport.ImportKeyResponse{Success: true, KeyID: captured.KeyID})
		return jsonrpcResponse{Result: data}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	material := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	req := &transport.ImportKeyRequest{
		Backend:            "software",
		KeyID:              "imported.example",
		KeyType:            "symmetric",
		KeySize:            256,
		AESKeySize:         256,
		Hash:               "SHA-256",
		Partition:          "p1",
		Curve:              "P-256",
		WrappedKeyMaterial: material,
		Algorithm:          "RSAES_OAEP_SHA_256",
		ImportToken:        []byte("token"),
		Metadata:           map[string]string{"origin": "test"},
	}

	resp, err := tr.ImportKey(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.Success)

	// The fatal one: without the key material the import cannot do anything.
	assert.Equal(t, material, captured.WrappedKey,
		"the wrapped key material must reach the handler's params struct")

	// The fields the mismatch silently dropped alongside it.
	assert.Equal(t, 256, captured.AESKeySize, "aes_key_size must survive the hop")
	assert.Equal(t, "SHA-256", captured.Hash, "hash must survive the hop")
	assert.Equal(t, "p1", captured.Partition, "partition must survive the hop")

	// And the fields that already worked must keep working.
	assert.Equal(t, "software", captured.Backend)
	assert.Equal(t, "imported.example", captured.KeyID)
	assert.Equal(t, "symmetric", captured.KeyType)
	assert.Equal(t, 256, captured.KeySize)
	assert.Equal(t, "P-256", captured.Curve)
	assert.Equal(t, "RSAES_OAEP_SHA_256", captured.Algorithm)
	assert.Equal(t, []byte("token"), captured.ImportToken)
	assert.Equal(t, map[string]string{"origin": "test"}, captured.Metadata)
}

// TestImportKey_ParamsAndRequestAgreeOnFieldNames locks the contract go-xkms
// #159 found broken. Transport.ImportKey now builds xkmsmcp.ImportKeyParams by
// name, so a renamed FIELD is a compile error -- but a renamed JSON TAG is not,
// and a tag is what actually travels. This asserts the two structs still
// describe the same wire vocabulary.
//
// TenantID is the one deliberate exception: transport.ImportKeyRequest carries
// it, the MCP params struct does not, because this transport's handlers take
// the tenant from the authenticated caller and reject a wire-supplied one
// (tenantForRequest in pkg/api/mcp). It is listed here rather than silently
// skipped so that removing it from the exception list is a deliberate act.
func TestImportKey_ParamsAndRequestAgreeOnFieldNames(t *testing.T) {
	// The params struct names the key material "wrapped_key", matching every
	// other params struct on this transport; the request struct calls the same
	// field "wrapped_key_material". The mapping is intentional and is what
	// Transport.ImportKey implements.
	renamed := map[string]string{"wrapped_key_material": "wrapped_key"}
	notOnTheWire := map[string]bool{"tenant_id": true}

	requestTags := jsonTagSet(t, transport.ImportKeyRequest{})
	paramsTags := jsonTagSet(t, xkmsmcp.ImportKeyParams{})

	for tag := range requestTags {
		if notOnTheWire[tag] {
			continue
		}
		want := tag
		if mapped, ok := renamed[tag]; ok {
			want = mapped
		}
		assert.Truef(t, paramsTags[want],
			"transport.ImportKeyRequest field %q has no counterpart %q on xkmsmcp.ImportKeyParams; "+
				"a field the request can express but the params struct cannot is silently dropped on import",
			tag, want)
	}

	for tag := range paramsTags {
		var want string
		for from, to := range renamed {
			if to == tag {
				want = from
			}
		}
		if want == "" {
			want = tag
		}
		assert.Truef(t, requestTags[want],
			"xkmsmcp.ImportKeyParams field %q has no counterpart %q on transport.ImportKeyRequest; "+
				"a params field no caller can populate is a control that does not exist",
			tag, want)
	}
}

// jsonTagSet returns the set of JSON field names v marshals to.
func jsonTagSet(t *testing.T, v interface{}) map[string]bool {
	t.Helper()

	typ := reflect.TypeOf(v)
	tags := make(map[string]bool, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		tags[strings.Split(tag, ",")[0]] = true
	}
	return tags
}
