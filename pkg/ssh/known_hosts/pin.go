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

package known_hosts

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// Source constants for Pin.Source documenting common provenances. These
// values are not validated — Source is free-text — but callers should
// prefer these strings so downstream log analysis can rely on them.
const (
	// SourceManual indicates the pin was added by an operator via an
	// API / CLI call (the default for Store.Add).
	SourceManual = "manual"

	// SourceFirstContact indicates the pin was recorded on a
	// trust-on-first-use bootstrap — either CallbackWithConfirm's built-in
	// TOFU confirmer path, or a caller layering its own accept flow on top
	// of Callback (e.g. pkg/ssh/connect's sync-back of host keys the
	// system ssh client accepted).
	SourceFirstContact = "first-contact"

	// SourceImport prefix identifies bulk-imported pins; the full
	// Source string is typically "imported:<origin>" (e.g.,
	// "imported:~/.ssh/known_hosts").
	SourceImport = "imported"
)

// Pin is a persisted fingerprint + host binding. Fingerprint is the
// canonical OpenSSH SHA256 form ("SHA256:<base64-no-padding>") and is
// computed by keys.Fingerprint for input ssh.PublicKey values.
//
// Pin carries no secret material — every field is safe to log or ship
// over a plain REST boundary. Integrity against tampering is the
// responsibility of the underlying storage.Backend (HMAC tags on the
// sealed backend; file permissions elsewhere).
type Pin struct {
	// Host is the canonical host identifier. Format is free-form but
	// must be safe for use as a storage-path component — use
	// ValidateHost before persisting.
	Host string

	// Fingerprint is the OpenSSH "SHA256:<base64-no-padding>" form of
	// the pinned public key.
	Fingerprint string

	// Algorithm is the SSH public-key algorithm name (e.g.,
	// "ssh-ed25519", "ecdsa-sha2-nistp256"). Carried for diagnostics
	// and for future algorithm-rotation tooling; Verify compares
	// fingerprints only.
	Algorithm string

	// Scope is the ownership scope (tenant / user / service).
	Scope scope.Scope

	// Owner is the scope-specific identifier (tenant ID, user ID, or
	// service ID).
	Owner string

	// AddedAt is the wall-clock time at which the pin was recorded.
	AddedAt time.Time

	// Source is free-text provenance. See the Source* constants for
	// suggested values.
	Source string

	// PublicKey is the SSH wire-format host public key
	// (ssh.PublicKey.Marshal()). Required: Store.Add rejects a pin with no
	// PublicKey (*PublicKeyRequiredError), and Verify compares the full key,
	// not just the Fingerprint. It also lets the pin be emitted as an
	// OpenSSH known_hosts line (Emit / EmitAll). Non-secret; safe to
	// log/ship. A pin persisted before this field existed decodes as
	// *LegacyPinError, not as a Pin with an empty PublicKey.
	PublicKey []byte
}

// ValidateHost returns nil if host is safe to use as a storage-path
// component. A valid host is non-empty, contains neither '/' nor NUL,
// and has no ".." path-traversal segments. Returns *InvalidHostError
// with a human-readable Reason on any violation.
//
// This is exported because the SDK surface accepts raw host strings
// from external callers; routing them through ValidateHost before
// construction of a Pin keeps the sanitization authoritative in this
// package.
func ValidateHost(host string) error {
	if host == "" {
		return &InvalidHostError{Value: host, Reason: "empty"}
	}
	if strings.ContainsRune(host, '/') {
		return &InvalidHostError{Value: host, Reason: "contains path separator"}
	}
	if strings.ContainsRune(host, 0) {
		return &InvalidHostError{Value: host, Reason: "contains NUL byte"}
	}
	if host == "." || host == ".." {
		return &InvalidHostError{Value: host, Reason: "path-traversal segment"}
	}
	return nil
}

// ValidateFingerprint returns nil if fp is a well-formed OpenSSH SHA256
// fingerprint: "SHA256:" prefix followed by a non-empty base64 body
// (std-alphabet, no padding, 43 chars for a SHA-256 digest). Returns
// *InvalidFingerprintError otherwise.
//
// The digest length is enforced, not merely documented: a body that
// decodes to anything other than 32 bytes cannot have been produced by
// SHA-256, so accepting it would let an operator typo reach a pin
// comparison that can never match.
func ValidateFingerprint(fp string) error {
	if fp == "" {
		return &InvalidFingerprintError{Value: fp, Reason: "empty"}
	}
	const prefix = "SHA256:"
	if !strings.HasPrefix(fp, prefix) {
		return &InvalidFingerprintError{Value: fp, Reason: "missing SHA256: prefix"}
	}
	body := strings.TrimPrefix(fp, prefix)
	if body == "" {
		return &InvalidFingerprintError{Value: fp, Reason: "empty body"}
	}
	// OpenSSH strips trailing '=' padding; the raw body is 43 chars for
	// a 32-byte digest encoded in standard base64 alphabet.
	digest, err := base64.RawStdEncoding.DecodeString(body)
	if err != nil {
		return &InvalidFingerprintError{Value: fp, Reason: "body is not base64 (no padding)"}
	}
	if len(digest) != sha256.Size {
		return &InvalidFingerprintError{Value: fp, Reason: "body is not a 32-byte SHA-256 digest"}
	}
	return nil
}
