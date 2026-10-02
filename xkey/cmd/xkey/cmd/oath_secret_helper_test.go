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

package cmd

import (
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/cdp"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

// withOATHSecret stores secret on cred and returns cred, preserving the shape
// of the composite-literal tests written when the secret was an exported
// string field. It panics on a protected-memory failure, which in a test is a
// legitimate abort.
func withOATHSecret(cred *oath.Credential, secret string) *oath.Credential {
	if err := cred.SetSecret([]byte(secret)); err != nil {
		panic(err)
	}
	return cred
}

// secretText returns the credential's secret as a string for assertions, or ""
// when none is set. It panics on a protected-memory failure.
func secretText(cred interface{ Secret() ([]byte, error) }) string {
	b, err := cred.Secret()
	if err != nil {
		panic(err)
	}
	defer secure.Wipe(b)
	return string(b)
}

// passwordText returns the entry's password as a string for assertions, or ""
// when none is set. It panics on a protected-memory failure.
func passwordText(info *backup.PasswordInfo) string {
	b, err := info.Password()
	if err != nil {
		panic(err)
	}
	defer secure.Wipe(b)
	return string(b)
}

// privateKeyText returns the CDP credential's private key as a string for
// assertions, or "" when none is set. It panics on a protected-memory failure.
func privateKeyText(cred *cdp.StoredCredential) string {
	b, err := cred.PrivateKey()
	if err != nil {
		panic(err)
	}
	defer secure.Wipe(b)
	return string(b)
}

// mustSecretText holds text in protected memory for a wire record under test.
// It panics on a protected-memory failure, which in a test is a legitimate
// abort.
func mustSecretText(text string) xkms.SecretText {
	s, err := xkms.NewSecretText([]byte(text))
	if err != nil {
		panic(err)
	}
	return s
}

// textOf returns the secret text as a string for assertions. It panics on a
// protected-memory failure.
func textOf(s xkms.SecretText) string {
	b, err := s.Copy()
	if err != nil {
		panic(err)
	}
	defer secure.Wipe(b)
	return string(b)
}
