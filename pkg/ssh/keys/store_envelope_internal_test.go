// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package keys

import (
	"bytes"
	"testing"
)

// TestStoredEnvelope_Wipe proves wipe zeroes the PEM's backing array and
// drops the reference, and tolerates an envelope that holds none.
func TestStoredEnvelope_Wipe(t *testing.T) {
	pem := []byte("secret pem")
	env := &storedEnvelope{MaterialPEM: pem}
	env.wipe()
	if env.MaterialPEM != nil {
		t.Errorf("MaterialPEM = %q, want nil", env.MaterialPEM)
	}
	if !bytes.Equal(pem, make([]byte, len(pem))) {
		t.Errorf("backing array not zeroed: %q", pem)
	}
	(&storedEnvelope{}).wipe()
}
