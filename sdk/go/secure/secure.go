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
// consumers never need to import the upstream qrdb path or raw go-enclave.
//
// Every identifier is a direct alias or thin delegation to the canonical
// implementation in github.com/jeremyhahn/go-qrdb/sdk/go/secure — see that
// package for full documentation. Layering rule: go-xkms depends on
// go-qrdb, never the reverse; the SDK re-export keeps that edge inside
// the xkms module surface.
package secure

import (
	"context"
	"log/slog"

	qrdbsecure "github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// Secret is the re-export of qrdb's Secret — a long-lived, enclaved
// container for sensitive material. See qrdb secure package for rules.
type Secret = qrdbsecure.Secret

// Buffer is the re-export of qrdb's Buffer — a short-lived, mlocked,
// canary-guarded working copy. Always defer Destroy() after construction.
type Buffer = qrdbsecure.Buffer

// Borrower is the re-export of qrdb's Borrower -- the narrow interface (a
// WithBytes method) CopyOut needs from a Buffer, Secret or enclave.
type Borrower = qrdbsecure.Borrower

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

	// NestedBorrowError is returned when a borrow is opened inside another
	// borrow of the same value.
	NestedBorrowError = qrdbsecure.NestedBorrowError

	// EmptyBorrowError is returned when a borrow yields no bytes.
	EmptyBorrowError = qrdbsecure.EmptyBorrowError

	// ProcessHardeningError is returned by HardenProcess when the platform
	// refuses the mechanism or the tracer check cannot be made.
	ProcessHardeningError = qrdbsecure.ProcessHardeningError

	// ProcessInspectionOptOutError is returned by HardenProcess when
	// AllowProcessInspectionEnv holds a value strconv.ParseBool rejects.
	ProcessInspectionOptOutError = qrdbsecure.ProcessInspectionOptOutError

	// ProcessInspectionOptOutRefusedError is returned by HardenProcess when
	// the opt-out is set in FIPS 140-3 mode.
	ProcessInspectionOptOutRefusedError = qrdbsecure.ProcessInspectionOptOutRefusedError

	// ProcessTracedError is returned by HardenProcess when a tracer is
	// already attached.
	ProcessTracedError = qrdbsecure.ProcessTracedError
)

// ProcessHardening is the re-export of qrdb's ProcessHardening — what
// HardenProcess did to the process.
type ProcessHardening = qrdbsecure.ProcessHardening

// The HardenProcess outcomes.
const (
	ProcessHardened             = qrdbsecure.ProcessHardened
	ProcessInspectionAllowed    = qrdbsecure.ProcessInspectionAllowed
	ProcessHardeningUnavailable = qrdbsecure.ProcessHardeningUnavailable
)

// AllowProcessInspectionEnv names the environment variable that opts a
// process out of HardenProcess so a debugger can attach. A process that
// honours it logs a warning; FIPS 140-3 mode refuses it.
const AllowProcessInspectionEnv = qrdbsecure.AllowProcessInspectionEnv

// HardenProcess stops other processes from reading this one's memory: on
// Linux prctl(PR_SET_DUMPABLE, 0), on macOS ptrace(PT_DENY_ATTACH), elsewhere
// a logged no-op. It then refuses to continue if a tracer is already
// attached. It belongs to the binary that owns the process: call it once,
// first thing in main, before anything constructs a Buffer or Secret.
// Every error means the process is NOT hardened. A nil logger uses
// slog.Default.
func HardenProcess(logger *slog.Logger) (ProcessHardening, error) {
	return qrdbsecure.HardenProcess(logger)
}

// NewSecret seals src into a new Secret. On return, src is wiped — the
// caller must not reuse the slice. ctx bounds the wait for the process
// sealer.
func NewSecret(ctx context.Context, src []byte) (*Secret, error) {
	return qrdbsecure.NewSecret(ctx, src)
}

// NewSecretFromBuffer seals buf into a new Secret, consuming buf. ctx
// bounds the wait for the process sealer.
func NewSecretFromBuffer(ctx context.Context, buf *Buffer) (*Secret, error) {
	return qrdbsecure.NewSecretFromBuffer(ctx, buf)
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

// CopyOut copies protected bytes into a fresh caller-owned slice, holding
// the borrow across the whole copy. The caller owns the result and must
// Wipe it. An empty source is refused with *EmptyBorrowError rather than
// copied, so a caller never acts on a run of zeros.
func CopyOut(b Borrower) ([]byte, error) { return qrdbsecure.CopyOut(b) }

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

// WipeAll destroys every live locked-memory enclave the process holds --
// every outstanding Buffer and every plaintext a Secret.Open produced --
// and the process sealer's key material, so every live Secret becomes
// unopenable. It returns how many enclaves were still held. It belongs to
// the binary that owns the process, deferred at startup so it runs on every
// orderly exit; library code never calls it. It replaces the memguard-era
// CatchInterrupt/Purge pair: the binary drives its own signal handling and
// graceful shutdown, which runs the deferred WipeAll. ctx bounds the sweep;
// give it a deadline taken at shutdown.
func WipeAll(ctx context.Context) (int, error) { return qrdbsecure.WipeAll(ctx) }
