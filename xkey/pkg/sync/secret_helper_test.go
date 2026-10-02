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

package sync

import (
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
)

// secretText returns the credential's secret as a string for assertions, or ""
// when none is set. It panics on a protected-memory failure.
func secretText(info *backup.OATHCredentialInfo) string {
	b, err := info.Secret()
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

// mustCloneOATH returns an independent copy of info, as an accessor must hand
// out: the service destroys the records it is given. It panics on a
// protected-memory failure.
func mustCloneOATH(info *backup.OATHCredentialInfo) *backup.OATHCredentialInfo {
	clone, err := info.Clone()
	if err != nil {
		panic(err)
	}
	return clone
}

// mustClonePassword is mustCloneOATH for a password record.
func mustClonePassword(info *backup.PasswordInfo) *backup.PasswordInfo {
	clone, err := info.Clone()
	if err != nil {
		panic(err)
	}
	return clone
}
