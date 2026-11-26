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

package jwe

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestParseEncryptedAny(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil)
	if err != nil {
		t.Fatalf("new encrypter: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)
	obj, err := encrypter.Encrypt(payload)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("compact serialize: %v", err)
	}
	full := obj.FullSerialize()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "compact", input: compact},
		{name: "json", input: full},
		{name: "json with leading white space", input: " \t\r\n" + full},
		{name: "not a jwe", input: "not a jwe", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEncryptedAny(tt.input,
				[]jose.KeyAlgorithm{jose.DIRECT},
				[]jose.ContentEncryption{jose.A256GCM})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseEncryptedAny(%q) returned no error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseEncryptedAny: %v", err)
			}
			out, err := got.Decrypt(key)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(out, payload) {
				t.Fatalf("payload = %q, want %q", out, payload)
			}
		})
	}
}
