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

package checkpoint

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// HashSize is the size of an RFC 6962 SHA-256 Merkle tree root hash.
const HashSize = 32

// A Checkpoint is the note text of a transparency log checkpoint
// (tlog-checkpoint §Note text).
type Checkpoint struct {
	// Origin uniquely identifies the log, e.g. "example.com/log".
	Origin string

	// Size is the number of entries in the tree.
	Size uint64

	// Hash is the RFC 6962 Merkle tree root hash.
	Hash []byte

	// Extensions are the optional extension lines that follow the root
	// hash, each non-empty.
	Extensions []string
}

// Marshal encodes the checkpoint as note text: the origin, the decimal tree
// size, the base64 root hash and every extension line, each ending in a
// newline (tlog-checkpoint §Note text).
func (c *Checkpoint) Marshal() ([]byte, error) {
	if len(c.Hash) != HashSize {
		return nil, &errs.Detail{Err: ErrInvalidRootHash, Detail: "root hash must be " + strconv.Itoa(HashSize) + " bytes"}
	}
	lines := make([]string, 0, 3+len(c.Extensions))
	lines = append(lines, c.Origin, strconv.FormatUint(c.Size, 10), base64.StdEncoding.EncodeToString(c.Hash))
	lines = append(lines, c.Extensions...)
	for _, line := range lines {
		if line == "" || strings.Contains(line, "\n") {
			return nil, &errs.Detail{Err: ErrMalformedCheckpoint, Detail: "lines must be non-empty and free of newlines"}
		}
	}
	text := []byte(strings.Join(lines, "\n") + "\n")
	if !validNoteBytes(text) {
		return nil, &errs.Detail{Err: ErrMalformedCheckpoint, Detail: "invalid UTF-8 or control character"}
	}
	return text, nil
}

// ParseCheckpoint strictly parses checkpoint note text (tlog-checkpoint
// §Note text): at least three non-empty lines ending in a newline, a tree
// size in ASCII decimal without leading zeros, and a canonical base64
// 32-byte root hash.
func ParseCheckpoint(text []byte) (*Checkpoint, error) {
	if len(text) == 0 || text[len(text)-1] != '\n' || !validNoteBytes(text) {
		return nil, &errs.Detail{Err: ErrMalformedCheckpoint, Detail: "text must be valid note text ending in a newline"}
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) < 3 {
		return nil, &errs.Detail{Err: ErrMalformedCheckpoint, Detail: "fewer than three lines"}
	}
	for _, line := range lines {
		if line == "" {
			return nil, &errs.Detail{Err: ErrMalformedCheckpoint, Detail: "empty line"}
		}
	}
	size, err := parseTreeSize(lines[1])
	if err != nil {
		return nil, err
	}
	hash, ok := decodeBase64(lines[2])
	if !ok || len(hash) != HashSize {
		return nil, &errs.Detail{Err: ErrInvalidRootHash, Detail: "root hash must be canonical base64 of " + strconv.Itoa(HashSize) + " bytes"}
	}
	c := &Checkpoint{Origin: lines[0], Size: size, Hash: hash}
	if len(lines) > 3 {
		c.Extensions = lines[3:]
	}
	return c, nil
}

// parseTreeSize parses an ASCII decimal tree size: digits only, no leading
// zero except "0" itself, fitting in 64 bits.
func parseTreeSize(s string) (uint64, error) {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, &errs.Detail{Err: ErrInvalidTreeSize, Detail: "not ASCII decimal"}
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, &errs.Detail{Err: ErrInvalidTreeSize, Detail: "leading zero"}
	}
	size, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &errs.Joined{Lead: ErrInvalidTreeSize, Cause: err}
	}
	return size, nil
}

// SignCheckpoint marshals c and signs it with every signer, returning the
// signed checkpoint note.
func SignCheckpoint(c *Checkpoint, signers ...*Signer) ([]byte, error) {
	text, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	return Sign(text, signers...)
}

// OpenCheckpoint opens a signed checkpoint note with verifiers and parses
// its text. It returns the checkpoint with the opened note, whose
// Unverified signatures carry any cosignatures from unknown keys.
func OpenCheckpoint(note []byte, verifiers ...*Verifier) (*Checkpoint, *Note, error) {
	n, err := Open(note, verifiers...)
	if err != nil {
		return nil, nil, err
	}
	c, err := ParseCheckpoint(n.Text)
	if err != nil {
		return nil, nil, err
	}
	return c, n, nil
}
