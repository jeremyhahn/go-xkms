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

package pwimport

import (
	"testing"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// testSecret seals s into a *secure.Secret for test fixtures.
func testSecret(t *testing.T, s string) *secure.Secret {
	t.Helper()
	secret, err := secure.NewSecret(t.Context(), []byte(s))
	if err != nil {
		t.Fatalf("testSecret: %v", err)
	}
	return secret
}

// openSecretString opens secret and returns a copy of its contents as a
// string, for asserting on test fixtures only.
func openSecretString(t *testing.T, secret *secure.Secret) string {
	t.Helper()
	if secret == nil {
		return ""
	}
	buf, err := secret.Open(t.Context())
	if err != nil {
		t.Fatalf("openSecretString: %v", err)
	}
	defer buf.Destroy()
	var s string
	if err := buf.WithBytes(func(b []byte) error {
		s = string(b)
		return nil
	}); err != nil {
		t.Fatalf("openSecretString: %v", err)
	}
	return s
}
