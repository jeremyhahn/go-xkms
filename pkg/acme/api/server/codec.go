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

package server

import (
	"encoding/json"

	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// jsonCodec implements grpc encoding.Codec using JSON serialization.
// It uses protojson for proto.Message types (server-side request/response)
// and standard json for plain Go structs (SDK client types).
type jsonCodec struct{}

// protoMarshaler configures protojson to output snake_case proto field names.
// This ensures consistency with the admin Go types which use snake_case
// json tags (e.g., json:"mac_key", json:"created_at").
var protoMarshaler = protojson.MarshalOptions{
	UseProtoNames: true,
}

// Marshal serializes v to JSON bytes.
func (jsonCodec) Marshal(v interface{}) ([]byte, error) {
	if pm, ok := v.(proto.Message); ok {
		return protoMarshaler.Marshal(pm)
	}
	return json.Marshal(v)
}

// protoUnmarshaler accepts both camelCase and snake_case field names
// and discards unknown fields for forward compatibility.
var protoUnmarshaler = protojson.UnmarshalOptions{
	DiscardUnknown: true,
}

// Unmarshal deserializes JSON data into v.
func (jsonCodec) Unmarshal(data []byte, v interface{}) error {
	if pm, ok := v.(proto.Message); ok {
		return protoUnmarshaler.Unmarshal(data, pm)
	}
	return json.Unmarshal(data, v)
}

// Name returns the codec name used in the gRPC content-type header.
func (jsonCodec) Name() string {
	return "json"
}

func init() {
	encoding.RegisterCodec(jsonCodec{})
}
