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

package pinselect

import (
	"errors"
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ErrStrategyNotPersisted indicates no PIN strategy has been recorded under
// the data directory yet: a fresh install, or PIN state that predates this
// package. Resolve treats it as "decide and persist"; a caller that must
// not manufacture state (a plain status read of a legacy store, say) treats
// it as "governing strategy unknown".
var ErrStrategyNotPersisted = errors.New("pinselect: no PIN strategy persisted for this data directory")

// StrategyLoadError wraps a failure reading or decoding the persisted strategy
// file. It is distinct from ErrStrategyNotPersisted, which means the file
// is simply absent.
type StrategyLoadError struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e *StrategyLoadError) Error() string {
	return fmt.Sprintf("pinselect: failed to load strategy from %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is / errors.As traversal.
func (e *StrategyLoadError) Unwrap() error { return e.Cause }

// StrategySaveError wraps a failure persisting the strategy file.
type StrategySaveError struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e *StrategySaveError) Error() string {
	return fmt.Sprintf("pinselect: failed to save strategy to %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is / errors.As traversal.
func (e *StrategySaveError) Unwrap() error { return e.Cause }

// ProviderUnavailableError is returned by Resolve when the data
// directory's persisted, governing PIN strategy needs a provider (TPM2,
// PKCS#11) that this build or host cannot supply right now: the device is
// absent, unprovisioned, or the binary was built without the driver.
//
// Resolve never substitutes a different backend in this case. Answering
// "VALID" from a store that does not govern login is exactly the defect
// go-xkms#307 reports; refusing, loudly and by name, is the fix.
type ProviderUnavailableError struct {
	// Strategy is the governing strategy that could not be reached.
	Strategy qrdbsdk.PINStrategyID
}

// Error implements the error interface.
func (e *ProviderUnavailableError) Error() string {
	return fmt.Sprintf(
		"pinselect: PIN strategy %q governs this device but is unavailable in this build/host; refusing to answer from a different backend",
		e.Strategy,
	)
}

// UnknownStrategyError is returned when the persisted strategy file names
// a strategy ID this build does not recognize (for example, a newer xKey
// version wrote a strategy an older binary has never heard of).
type UnknownStrategyError struct {
	Strategy qrdbsdk.PINStrategyID
}

// Error implements the error interface.
func (e *UnknownStrategyError) Error() string {
	return fmt.Sprintf("pinselect: unrecognized persisted PIN strategy %q", e.Strategy)
}

// StrategyMismatchError is returned by Resolve when the configured PIN
// strategy differs from the one recorded for the PIN directory. Changing
// the governing backend in place would orphan every PIN set under the
// recorded one, so it is refused by name rather than applied.
type StrategyMismatchError struct {
	Configured qrdbsdk.PINStrategyID
	Persisted  qrdbsdk.PINStrategyID
}

// Error implements the error interface.
func (e *StrategyMismatchError) Error() string {
	return fmt.Sprintf(
		"pinselect: configured PIN strategy %q differs from the recorded governing strategy %q; refusing to switch backends in place",
		e.Configured, e.Persisted,
	)
}
