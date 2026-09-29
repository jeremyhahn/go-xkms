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

package netguard

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadLimited_AcceptsBodyAtOrUnderLimit(t *testing.T) {
	t.Parallel()
	body, err := ReadLimited(bytes.NewReader([]byte("0123456789")), 10)
	if err != nil {
		t.Fatalf("ReadLimited() error = %v", err)
	}
	if string(body) != "0123456789" {
		t.Fatalf("body = %q, want 0123456789", body)
	}
}

func TestReadLimited_RefusesBodyOverLimit(t *testing.T) {
	t.Parallel()
	_, err := ReadLimited(bytes.NewReader([]byte("0123456789A")), 10)
	var tooLarge *ResponseTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("ReadLimited() error = %v, want *ResponseTooLargeError", err)
	}
	if tooLarge.Limit != 10 {
		t.Fatalf("ResponseTooLargeError.Limit = %d, want 10", tooLarge.Limit)
	}
}
