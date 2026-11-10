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

package handlers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestParseSignedAny(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, nil)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("compact serialize: %v", err)
	}
	full := jws.FullSerialize()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "compact", input: compact},
		{name: "json", input: full},
		{name: "json with leading white space", input: " \t\r\n" + full},
		{name: "not a jws", input: "not a jws", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSignedAny(tt.input, []jose.SignatureAlgorithm{jose.EdDSA})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSignedAny(%q) returned no error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSignedAny: %v", err)
			}
			out, err := got.Verify(pub)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !bytes.Equal(out, payload) {
				t.Fatalf("payload = %q, want %q", out, payload)
			}
		})
	}
}
