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

// Package pinstrategy is the single, shared record of which PIN backend
// governs a device: TPM2, PKCS#11 or software. It is the fix for
// go-xkms#307, where the xKey GUI persisted its choice inside its own
// (cgo, GUI-only) config file while the headless daemon and `xkey pin`
// hard-coded the software backend, so a PIN set through one authenticated
// against another.
//
// pinstrategy has no cgo dependency and no GUI dependency: it is imported
// by the GUI, the headless daemon and the CLI alike, so all three read and
// write exactly one record and resolve it through exactly one rule (see
// Resolve). Callers supply their own environment adapters (how to reach a
// TPM, a PKCS#11 token, where software PIN state persists) through the
// same provider interfaces pkg/pinselect defines; pinstrategy adds the
// persistence layer pinselect itself does not know about.
package pinstrategy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// strategyFileName is the file recording the governing PIN strategy, kept
// beside the PIN state it governs (<pinDir>/strategy, i.e. a sibling of
// the qrdb software store's own <pinDir>/{so-pin,user-pin}) rather than
// in any single consumer's own config file (issue #307).
const strategyFileName = "strategy"

// strategyRecord is the on-disk representation of the persisted strategy.
type strategyRecord struct {
	Strategy qrdbsdk.PINStrategyID `json:"strategy"`
}

// Path returns the on-disk location of the persisted governing PIN
// strategy given pinDir, the directory holding PIN state
// (<dataDir>/pin by default, but callers that relocate PIN state — e.g.
// the headless daemon's --pin-state flag — pass that location instead):
// <pinDir>/strategy.
func Path(pinDir string) string {
	return filepath.Join(pinDir, strategyFileName)
}

// Load reads the governing PIN strategy persisted beside the PIN state in
// pinDir. It returns ErrStrategyNotPersisted (checked with errors.Is) when
// no strategy has been recorded yet, which is a distinct fact from a load
// failure: callers that can decide on the caller's behalf (Resolve) treat
// it as "auto-select and persist"; callers that must not manufacture
// state treat it as "governing strategy unknown" and report that rather
// than guessing.
func Load(pinDir string) (qrdbsdk.PINStrategyID, error) {
	path := Path(pinDir)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrStrategyNotPersisted
		}
		return "", &LoadError{Path: path, Cause: err}
	}

	var rec strategyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return "", &LoadError{Path: path, Cause: err}
	}
	if rec.Strategy == "" {
		return "", ErrStrategyNotPersisted
	}

	return rec.Strategy, nil
}

// Save persists strategy as the governing PIN strategy beside the PIN
// state in pinDir, creating pinDir if it does not already exist. The
// write is atomic (temp file, then rename) so a crash mid-write cannot
// leave a truncated file that Load would misread as corrupt or, worse, as
// a different strategy.
func Save(pinDir string, strategy qrdbsdk.PINStrategyID) error {
	path := Path(pinDir)

	if strategy == "" {
		return &SaveError{Path: path, Cause: errors.New("empty strategy")}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return &SaveError{Path: path, Cause: err}
	}

	data, err := json.MarshalIndent(strategyRecord{Strategy: strategy}, "", "  ")
	if err != nil {
		return &SaveError{Path: path, Cause: err}
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return &SaveError{Path: path, Cause: err}
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return &SaveError{Path: path, Cause: err}
	}

	return nil
}
