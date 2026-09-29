// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

import (
	"encoding/json"
	"testing"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// TestRestImportRequest_PassphraseWipeReachesMarshaledBytes is a white-box
// regression test for go-xkms#1257: restKeysClient.Import used to hold the
// passphrase in a string field (PassphraseB64) and "wipe" it by zeroing
// []byte(wire.PassphraseB64) — a throwaway copy the []byte conversion
// mints, never the string's own (immutable, unwipeable) backing bytes. The
// wipe was consequently a no-op on the value encoding/json actually read.
//
// restImportRequest.Passphrase is now []byte, so this proves the wipe
// reaches the SAME backing array json.Marshal reads, not an independent
// copy: alias below shares wire.Passphrase's backing array by construction
// (a slice assignment, not a conversion), so it can only read back as zero
// if secure.Wipe(wire.Passphrase) zeroed the real array.
func TestRestImportRequest_PassphraseWipeReachesMarshaledBytes(t *testing.T) {
	const secret = "correct horse battery staple"

	wire := restImportRequest{
		Scope:      "user",
		Owner:      "alice",
		Name:       "wiped",
		Passphrase: []byte(secret),
	}
	alias := wire.Passphrase

	// json.Marshal, exactly as restClient.do does, reads wire.Passphrase's
	// backing array to produce the base64 wire form. Capture it before the
	// wipe as a positive control: if the field were never populated, the
	// assertions below would prove nothing.
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded struct {
		Passphrase []byte `json:"passphrase_b64"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if string(decoded.Passphrase) != secret {
		t.Fatalf("wire body carried %q, want %q (positive control failed)", decoded.Passphrase, secret)
	}

	// This is the exact operation restKeysClient.Import performs on wire
	// after k.c.do returns.
	secure.Wipe(wire.Passphrase)
	wire.Passphrase = nil

	for i, b := range alias {
		if b != 0 {
			t.Fatalf("byte %d of the marshaled backing array not zeroed: %d", i, b)
		}
	}
}
