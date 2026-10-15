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

package pairingproto

import (
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// mustSecretText holds text in protected memory for a wire record under test.
func mustSecretText(text string) xkms.SecretText {
	s, err := xkms.NewSecretText([]byte(text))
	if err != nil {
		panic(err)
	}
	return s
}

// textOf reads a SecretText back as a string so a test can compare it.
func textOf(s xkms.SecretText) string {
	b, err := s.Copy()
	if err != nil {
		panic(err)
	}
	defer secure.Wipe(b)
	return string(b)
}
