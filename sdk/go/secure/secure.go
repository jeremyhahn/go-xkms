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

// Package secure re-exports go-qrdb's secure-memory types so go-xkms SDK
// consumers never need to import the upstream qrdb path or raw memguard.
//
// Every identifier is a direct alias or thin delegation to the canonical
// implementation in github.com/jeremyhahn/go-qrdb/sdk/go/secure — see that
// package for full documentation. Layering rule: go-xkms depends on
// go-qrdb, never the reverse; the SDK re-export keeps that edge inside
// the xkms module surface.
package secure

import (
	"context"

	qrdbsecure "github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// Secret is the re-export of qrdb's Secret — a long-lived, enclaved
// container for sensitive material. See qrdb secure package for rules.
type Secret = qrdbsecure.Secret

// Buffer is the re-export of qrdb's Buffer — a short-lived, mlocked,
// canary-guarded working copy. Always defer Destroy() after construction.
type Buffer = qrdbsecure.Buffer

// PassphraseProvider is the re-export of qrdb's PassphraseProvider
// interface for reading passphrases directly into a Buffer.
type PassphraseProvider = qrdbsecure.PassphraseProvider

// TerminalProvider is the re-export of qrdb's TerminalProvider —
// reads from /dev/tty with echo disabled.
type TerminalProvider = qrdbsecure.TerminalProvider

// StdinProvider is the re-export of qrdb's StdinProvider — reads from
// stdin until newline (CI / piped invocations).
type StdinProvider = qrdbsecure.StdinProvider

// CallbackProvider is the re-export of qrdb's CallbackProvider — wraps a
// user-supplied function that returns passphrase bytes.
type CallbackProvider = qrdbsecure.CallbackProvider

// Error type re-exports. Direct aliases preserve pointer identity, so
// errors.As / errors.Is keep working across the module boundary.
type (
	// NilSecretError is returned when Open is called on a nil or
	// destroyed Secret.
	NilSecretError = qrdbsecure.NilSecretError

	// NilBufferError is returned when a Buffer method is called on a nil
	// or destroyed Buffer.
	NilBufferError = qrdbsecure.NilBufferError

	// OpenError wraps an underlying memguard failure to unseal.
	OpenError = qrdbsecure.OpenError

	// InvalidSizeError is returned when a constructor receives a
	// non-positive size.
	InvalidSizeError = qrdbsecure.InvalidSizeError

	// ProviderError is returned by PassphraseProvider implementations on
	// I/O failure.
	ProviderError = qrdbsecure.ProviderError

	// NotInitializedError is returned by Purge when CatchInterrupt has
	// not yet been called.
	NotInitializedError = qrdbsecure.NotInitializedError
)

// NewSecret seals src into a new Secret. On return, src is wiped — the
// caller must not reuse the slice.
func NewSecret(src []byte) (*Secret, error) { return qrdbsecure.NewSecret(src) }

// NewSecretFromBuffer seals buf into a new Secret, consuming buf.
func NewSecretFromBuffer(buf *Buffer) (*Secret, error) {
	return qrdbsecure.NewSecretFromBuffer(buf)
}

// NewBuffer allocates a zero-filled mlocked Buffer of the given size.
func NewBuffer(size int) (*Buffer, error) { return qrdbsecure.NewBuffer(size) }

// NewBufferFromBytes copies src into an mlocked Buffer. On return, src
// is wiped.
func NewBufferFromBytes(src []byte) (*Buffer, error) {
	return qrdbsecure.NewBufferFromBytes(src)
}

// Wipe clears a caller-owned []byte using memguard's
// compiler-optimization-resistant wipe. No-op on empty slices.
func Wipe(b []byte) { qrdbsecure.Wipe(b) }

// NewTerminalProvider returns a TerminalProvider that reads passphrases
// from /dev/tty.
func NewTerminalProvider() *TerminalProvider { return qrdbsecure.NewTerminalProvider() }

// NewStdinProvider returns a StdinProvider reading from os.Stdin.
func NewStdinProvider() *StdinProvider { return qrdbsecure.NewStdinProvider() }

// NewCallbackProvider returns a CallbackProvider that invokes fn to
// obtain passphrase bytes.
func NewCallbackProvider(fn func(ctx context.Context, prompt string) ([]byte, error)) *CallbackProvider {
	return qrdbsecure.NewCallbackProvider(fn)
}

// CatchInterrupt wires SIGINT/SIGTERM to purge all mlocked memory before
// process exit. Call once, early in main().
//
// The installed handler hard os.Exit(1)s from inside the signal handler, so a
// daemon that drives its own graceful shutdown must use EnablePurge instead:
// CatchInterrupt's exit always wins the race and the shutdown path (including
// storage Close) never runs.
func CatchInterrupt() { qrdbsecure.CatchInterrupt() }

// EnablePurge arms the secure subsystem so Purge works, WITHOUT installing
// memguard's process signal handler. Use it in daemons that own their own
// SIGINT/SIGTERM handling and drive a graceful shutdown, paired with a
// deferred Purge in main().
func EnablePurge() { qrdbsecure.EnablePurge() }

// Purge performs an immediate, synchronous wipe of all mlocked memory.
// Returns NotInitializedError if CatchInterrupt has not run.
func Purge() error { return qrdbsecure.Purge() }

// PurgeOrPanic is a convenience for deferred cleanup in main(). Panics
// if CatchInterrupt was not called.
func PurgeOrPanic() { qrdbsecure.PurgeOrPanic() }
