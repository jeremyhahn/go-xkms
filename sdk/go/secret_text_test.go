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

package xkms

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Assignability block: the SDK names are aliases of the pkg/types originals,
// not new types, so values cross the boundary without conversion.
var (
	_ types.SecretBytes       = SecretBytes(nil)
	_ SecretBytes             = types.SecretBytes(nil)
	_ types.SecretText        = SecretText{}
	_ SecretText              = types.SecretText{}
	_ *types.SecretBytesError = (*SecretBytesError)(nil)
	_ *types.SecretTextError  = (*SecretTextError)(nil)
)

func TestSecretText_ThroughTheSDK(t *testing.T) {
	var text SecretText
	if err := json.Unmarshal([]byte(`"hunter2"`), &text); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	defer text.Destroy()

	out, err := json.Marshal(text)
	if err != nil || string(out) != `"hunter2"` {
		t.Errorf("marshal = %s, %v", out, err)
	}
}

func TestSecretErrors_ThroughTheSDK(t *testing.T) {
	var bytesErr *SecretBytesError
	var secret SecretBytes
	if err := json.Unmarshal([]byte(`42`), &secret); !errors.As(err, &bytesErr) {
		t.Errorf("want *SecretBytesError, got %v", err)
	}

	var text SecretText
	if err := json.Unmarshal([]byte(`"x"`), &text); err != nil {
		t.Fatal(err)
	}
	copy2 := text
	text.Destroy()
	var textErr *SecretTextError
	if _, err := copy2.Copy(); !errors.As(err, &textErr) {
		t.Errorf("want *SecretTextError reading a destroyed copy, got %v", err)
	}
}
