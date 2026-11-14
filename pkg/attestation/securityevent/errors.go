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

package securityevent

import "errors"

// Decode errors. Each wraps the detail of the rule the input breaks; test
// for them with errors.Is.
var (
	// ErrMalformed reports input that is not one well-formed CBOR item of
	// the record's shape: invalid or truncated CBOR, trailing bytes, a tag,
	// a duplicate map key, or a member of the wrong type.
	ErrMalformed = errors.New("securityevent: malformed Claims-Set")

	// ErrUnknownKey reports a map key the format does not define.
	ErrUnknownKey = errors.New("securityevent: unknown key")

	// ErrMissingKey reports a member the format requires and the input
	// leaves out.
	ErrMissingKey = errors.New("securityevent: missing key")

	// ErrOutOfRange reports a value too wide for its field, or negative.
	ErrOutOfRange = errors.New("securityevent: value out of range")

	// ErrNotDeterministic reports input that decodes to a valid record but
	// is not its core deterministic encoding (RFC 8949 §4.2.1): a longer
	// than shortest argument, an indefinite length, or keys out of order.
	ErrNotDeterministic = errors.New("securityevent: not core deterministic encoding")
)

// ErrCountMismatch reports a record whose count is not the number of its
// entries. Encode and Decode both refuse one.
var ErrCountMismatch = errors.New("securityevent: count does not match entries")
