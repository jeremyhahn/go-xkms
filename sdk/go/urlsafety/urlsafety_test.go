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

package urlsafety_test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/urlsafety"
)

// TestValidateLaunchURL_AcceptsHTTPS proves an ordinary https URL passes and
// comes back parsed.
func TestValidateLaunchURL_AcceptsHTTPS(t *testing.T) {
	u, err := urlsafety.ValidateLaunchURL("https://login.example.com/authorize?x=1")
	if err != nil {
		t.Fatalf("ValidateLaunchURL: %v", err)
	}
	if u.Host != "login.example.com" {
		t.Fatalf("host = %q", u.Host)
	}
}

// TestValidateLaunchURL_RefusesUnsafeURLs proves the launcher guard refuses
// the shapes it exists to stop.
func TestValidateLaunchURL_RefusesUnsafeURLs(t *testing.T) {
	for _, raw := range []string{"", "javascript:alert(1)", "file:///etc/passwd", "-flag", "https://"} {
		if _, err := urlsafety.ValidateLaunchURL(raw); err == nil {
			t.Fatalf("ValidateLaunchURL(%q) accepted an unsafe URL", raw)
		}
	}
}
