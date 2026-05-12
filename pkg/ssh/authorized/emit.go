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

package authorized

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

// Emit produces a single authorized_keys-format line for e (without a
// trailing newline). The format is:
//
//	[options-list SP] <type> SP <base64-key> [SP comment]
//
// Emit does NOT open the Key's Secret — authorized_keys only contains
// public material, and ssh.MarshalAuthorizedKey produces that from the
// parsed PublicKey. Callers that need to wrap the output in a file
// should add the newline themselves or use EmitAll.
//
// Returns *NilInputError if e or e.Key or e.Key.PublicKey is nil.
func Emit(e *Entry) (string, error) {
	if e == nil {
		return "", &NilInputError{Field: "entry"}
	}
	if e.Key == nil {
		return "", &NilInputError{Field: "entry.Key"}
	}
	if e.Key.PublicKey == nil {
		return "", &NilInputError{Field: "entry.Key.PublicKey"}
	}

	// ssh.MarshalAuthorizedKey returns "<type> <base64>\n" — strip the
	// newline so callers control line termination and so the emission
	// round-trips through ParseLine without a trailing blank.
	marshaled := strings.TrimRight(string(ssh.MarshalAuthorizedKey(e.Key.PublicKey)), "\n")
	var b strings.Builder
	b.Grow(len(marshaled) + len(e.Comment) + 32)
	if len(e.Options) > 0 {
		b.WriteString(strings.Join(e.Options, ","))
		b.WriteByte(' ')
	}
	b.WriteString(marshaled)
	if e.Comment != "" {
		b.WriteByte(' ')
		b.WriteString(e.Comment)
	}
	return b.String(), nil
}

// EmitAll concatenates Emit outputs with newline separators and returns
// a single block suitable for writing to disk. An empty entries slice
// yields an empty string.
func EmitAll(entries []*Entry) (string, error) {
	if len(entries) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		line, err := Emit(e)
		if err != nil {
			return "", err
		}
		parts = append(parts, line)
	}
	// Trailing newline matches the convention OpenSSH uses when sshd
	// rewrites the file.
	return strings.Join(parts, "\n") + "\n", nil
}
