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

package tlog

import "errors"

// Head-signing errors: the CA key as go-qrdb's HeadSignerProvider.
var (
	// ErrNoKeyProvider indicates a HeadSignerProvider built without the CA
	// key provider it signs through.
	ErrNoKeyProvider = errors.New("tlog: no CA key provider")

	// ErrCAKeyUnavailable indicates the CA key provider did not answer a
	// signer: the CA is not initialized, sealed or its key revoked.
	ErrCAKeyUnavailable = errors.New("tlog: CA key unavailable")

	// ErrUnsupportedCAKey indicates a CA key go-qrdb cannot record as a
	// head-signing key: RFC 9162 §2.1.4 admits Ed25519 and ECDSA P-256 only.
	ErrUnsupportedCAKey = errors.New("tlog: CA key cannot sign tree heads")

	// ErrKeyTypeMismatch indicates a key request for a signature type other
	// than the CA key's.
	ErrKeyTypeMismatch = errors.New("tlog: requested key type is not the CA key's")

	// ErrKeyRefMismatch indicates the CA key is no longer the key the log
	// recorded: a signer request whose reference names another key.
	ErrKeyRefMismatch = errors.New("tlog: CA key is not the key the log recorded")
)

// Log errors: the service over go-qrdb's verifiable log.
var (
	// ErrNoClient indicates a log opened without a go-qrdb log client.
	ErrNoClient = errors.New("tlog: no verifiable-log client")

	// ErrNoVerifier indicates a log opened without the CA's checkpoint
	// verifier.
	ErrNoVerifier = errors.New("tlog: no checkpoint verifier")

	// ErrInvalidConfig indicates a log name or origin go-qrdb cannot address.
	ErrInvalidConfig = errors.New("tlog: invalid log configuration")

	// ErrLogRequest indicates go-qrdb refused or failed a log request.
	ErrLogRequest = errors.New("tlog: verifiable-log request failed")

	// ErrEntryExpired indicates an entry whose body the log has expired.
	ErrEntryExpired = errors.New("tlog: entry body expired")

	// ErrCheckpointMismatch indicates a signed tree head whose checkpoint does
	// not verify under the CA key, names another origin, or describes another
	// tree than the head it came with.
	ErrCheckpointMismatch = errors.New("tlog: checkpoint does not match the signed tree head")
)

// Entry errors: the versioned entry encoding.
var (
	// ErrInvalidEntry indicates an entry with a missing or invalid field.
	ErrInvalidEntry = errors.New("tlog: invalid entry")

	// ErrMalformedEntry indicates bytes that are not an encoded entry.
	ErrMalformedEntry = errors.New("tlog: malformed entry")

	// ErrUnsupportedVersion indicates an entry encoding version this build
	// does not read.
	ErrUnsupportedVersion = errors.New("tlog: unsupported entry encoding version")

	// ErrUnknownKind indicates an entry kind this build does not read.
	ErrUnknownKind = errors.New("tlog: unknown entry kind")
)
