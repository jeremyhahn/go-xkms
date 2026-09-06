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

package pkcs11

import (
	"context"
	"errors"
	"strings"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestExportKeyMaterialKeyTypeIsCanonicalAlgorithmFamily pins the algorithm
// family this transport reports for exported key material.
//
// This package used to answer "which family is this key" with its own
// formatter, a fourth copy of a question go-xkms#336 reduced to one method,
// KeyAttributes.AlgorithmString. The response field is asserted against a
// literal rather than against that method, so a transport that grew a private
// opinion again -- or a change to the canonical resolution order that this
// transport was never meant to follow -- shows up as a failure here rather
// than agreeing with itself (go-xkms#402).
//
// The second assertion is the property that matters: the family reported for
// a key and the family the key is stored under are the same word. Those are
// the two answers that must never disagree.
func TestExportKeyMaterialKeyTypeIsCanonicalAlgorithmFamily(t *testing.T) {
	const keyID = "export-family-key"

	tr := newDeriveTestTransport(t)
	attrs := newSymmetricKey(t, keyID, true)

	resp, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		Backend: deriveBackend,
		KeyID:   keyID,
	})
	if err != nil {
		t.Fatalf("ExportKeyMaterial() error = %v", err)
	}

	if want := string(xkms.SymmetricAES256GCM); resp.KeyType != want {
		t.Errorf("ExportKeyMaterial() KeyType = %q, want %q", resp.KeyType, want)
	}

	// ID resolves the family into the last segment of the storage identifier,
	// lowercased; the response keeps the display spelling. Equality up to case
	// is agreement on the family.
	id := attrs.ID()
	idFamily := id[strings.LastIndex(id, ":")+1:]
	if !strings.EqualFold(resp.KeyType, idFamily) {
		t.Errorf("ExportKeyMaterial() KeyType = %q resolves a different family than ID %q", resp.KeyType, id)
	}

	if want := len(resp.KeyMaterial) * 8; resp.KeySize != want {
		t.Errorf("ExportKeyMaterial() KeySize = %d, want %d", resp.KeySize, want)
	}
}

// TestExportKeyMaterialRefusesUnexportableKey covers the path that produces no
// KeyType at all: a key whose material the backend will not release.
//
// It is the reason the deleted formatter's asymmetric and "unknown" branches
// were unreachable here. A backend refuses raw material for anything but a
// single-family symmetric key, so by the time a family is reported the only
// family left to report is the symmetric one.
func TestExportKeyMaterialRefusesUnexportableKey(t *testing.T) {
	const keyID = "unexportable-key"

	tr := newDeriveTestTransport(t)
	newSymmetricKey(t, keyID, false)

	resp, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		Backend: deriveBackend,
		KeyID:   keyID,
	})
	if err == nil {
		t.Fatalf("ExportKeyMaterial() returned %+v for a non-exportable key, want an error", resp)
	}
	if resp != nil {
		t.Errorf("ExportKeyMaterial() response = %+v, want nil alongside an error", resp)
	}
	if !errors.Is(err, ErrExportFailed) {
		t.Errorf("ExportKeyMaterial() error = %v, want it to wrap ErrExportFailed", err)
	}
}

// TestExportKeyMaterialRejectsBadRequests covers the request-shaped refusals
// that precede any family resolution.
func TestExportKeyMaterialRejectsBadRequests(t *testing.T) {
	tr := newDeriveTestTransport(t)

	tests := []struct {
		name string
		req  *transport.ExportKeyMaterialRequest
		want error
	}{
		{
			name: "NilRequest",
			req:  nil,
			want: ErrNilRequest,
		},
		{
			name: "UnknownBackend",
			req:  &transport.ExportKeyMaterialRequest{Backend: "no-such-backend", KeyID: "any"},
			want: ErrBackendNotFound,
		},
		{
			name: "UnknownKey",
			req:  &transport.ExportKeyMaterialRequest{Backend: deriveBackend, KeyID: "no-such-key"},
			want: ErrKeyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tr.ExportKeyMaterial(context.Background(), tt.req)
			if err == nil {
				t.Fatalf("ExportKeyMaterial() returned %+v, want %v", resp, tt.want)
			}
			if resp != nil {
				t.Errorf("ExportKeyMaterial() response = %+v, want nil alongside an error", resp)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("ExportKeyMaterial() error = %v, want it to wrap %v", err, tt.want)
			}
		})
	}
}
