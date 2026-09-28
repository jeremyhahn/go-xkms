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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestJSONCodec_Name pins the gRPC content-type codec name.
func TestJSONCodec_Name(t *testing.T) {
	assert.Equal(t, "json", jsonCodec{}.Name())
}

// TestJSONCodec_Marshal_PlainStruct verifies a plain Go struct (an SDK
// client type, not a proto.Message) is marshaled with standard json, using
// its own json tags.
func TestJSONCodec_Marshal_PlainStruct(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	data, err := jsonCodec{}.Marshal(payload{Name: "alice"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"alice"}`, string(data))
}

// TestJSONCodec_Marshal_ProtoMessage verifies a proto.Message is marshaled
// with protojson using proto (snake_case/original) field names rather than
// protojson's camelCase default, matching the admin Go types' json tags.
func TestJSONCodec_Marshal_ProtoMessage(t *testing.T) {
	msg := wrapperspb.String("hello")

	data, err := jsonCodec{}.Marshal(msg)
	require.NoError(t, err)
	assert.JSONEq(t, `"hello"`, string(data))
}

// TestJSONCodec_Unmarshal_PlainStruct verifies a plain Go struct is decoded
// with standard json.
func TestJSONCodec_Unmarshal_PlainStruct(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	var p payload

	err := jsonCodec{}.Unmarshal([]byte(`{"name":"bob"}`), &p)
	require.NoError(t, err)
	assert.Equal(t, "bob", p.Name)
}

// TestJSONCodec_Unmarshal_ProtoMessage verifies a proto.Message is decoded
// with protojson, and that unknown fields are discarded rather than
// rejected, per protoUnmarshaler's DiscardUnknown option.
func TestJSONCodec_Unmarshal_ProtoMessage(t *testing.T) {
	var msg wrapperspb.StringValue

	err := jsonCodec{}.Unmarshal([]byte(`"world"`), &msg)
	require.NoError(t, err)
	assert.Equal(t, "world", msg.GetValue())
}

// TestJSONCodec_Unmarshal_PlainStruct_InvalidJSON verifies a malformed
// payload surfaces the underlying json error rather than being swallowed.
func TestJSONCodec_Unmarshal_PlainStruct_InvalidJSON(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	var p payload

	err := jsonCodec{}.Unmarshal([]byte(`{not valid json`), &p)
	assert.Error(t, err)
}
