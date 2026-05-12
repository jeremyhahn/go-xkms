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
	"bytes"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
)

// ParseLine reads a single authorized_keys line and returns an *Entry.
// Whitespace and a single trailing newline are tolerated. Comment
// (starting with '#') and empty lines are rejected — use ParseAll for
// whole-file inputs.
//
// The returned Entry's Key has Material=nil (authorized_keys carries
// only the public half); other Key metadata (PublicKey, Algorithm,
// Fingerprint, CreatedAt-as-parse-time, Comment) is populated.
func ParseLine(line string) (*Entry, error) {
	trimmed := strings.TrimRight(line, "\n\r")
	if trimmed == "" {
		return nil, &MalformedLineError{Line: line, Err: errEmptyLine}
	}
	if strings.HasPrefix(strings.TrimLeft(trimmed, " \t"), "#") {
		return nil, &MalformedLineError{Line: line, Err: errCommentLine}
	}
	pub, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, &MalformedLineError{Line: trimmed, Err: err}
	}
	algo, algoErr := keys.AlgorithmFromPublicKey(pub)
	if algoErr != nil {
		return nil, &MalformedLineError{Line: trimmed, Err: algoErr}
	}
	return &Entry{
		Key: &keys.Key{
			PublicKey:   pub,
			Algorithm:   algo,
			Fingerprint: keys.Fingerprint(pub),
			Comment:     comment,
			CreatedAt:   time.Now().UTC(),
		},
		Options: opts,
		Comment: comment,
	}, nil
}

// ParseAll reads an entire authorized_keys file and returns its
// Entries. Blank lines and '#'-prefixed comment lines are skipped.
// Any malformed content line aborts the parse with the originating
// *MalformedLineError (callers recover by editing the file).
func ParseAll(data []byte) ([]*Entry, error) {
	var out []*Entry
	for _, raw := range bytes.Split(data, []byte("\n")) {
		line := strings.TrimRight(string(raw), "\r")
		stripped := strings.TrimLeft(line, " \t")
		if stripped == "" {
			continue
		}
		if strings.HasPrefix(stripped, "#") {
			continue
		}
		entry, err := ParseLine(line)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// sentinel errors for parse paths that don't have an underlying
// x/crypto/ssh error. We keep them unexported — they only surface
// wrapped inside MalformedLineError.
var (
	errEmptyLine   = parseErr("empty line")
	errCommentLine = parseErr("comment line")
)

// parseErr is a tiny errors.New wrapper constrained to parse.go so we
// don't leak an extra exported type.
type parseErr string

// Error implements the error interface.
func (e parseErr) Error() string { return string(e) }
