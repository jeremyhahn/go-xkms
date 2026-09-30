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

package server

import (
	"errors"
	"log/slog"
	"path/filepath"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/pinselect"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	pinadapter "github.com/jeremyhahn/go-xkms/pkg/storage/pinadapter"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// pinStrategies maps the pin.strategy setting to the strategy pinselect
// resolves. Empty means auto, the hardware-first choice xKey makes.
var pinStrategies = map[string]qrdbsdk.PINStrategyID{
	"":         pinselect.StrategyAuto,
	"auto":     pinselect.StrategyAuto,
	"software": qrdbsdk.PINStrategySoftware,
	"tpm2":     qrdbsdk.PINStrategyTPM2,
}

// initializePINManager builds the PIN backend through pinselect.Resolve, the
// same selection path xKey's GUI, headless daemon and CLI use: the governing
// strategy is recorded in <datastore.path>/pin/strategy, a TPM2 strategy puts
// the user PIN on the TPM's Platform SRK (PlatformKeyStore.PINBackend), and
// software keeps a salted hash under <datastore.path>/pin.
func (s *Server) initializePINManager() error {
	if !s.config.PIN.Enabled {
		s.logger.Info("PIN management disabled")
		return nil
	}

	strategy, ok := pinStrategies[s.config.PIN.Strategy]
	if !ok {
		return &ErrUnknownPINStrategy{Strategy: s.config.PIN.Strategy}
	}

	// PIN state -- the strategy record and the software store -- is
	// file-backed under datastore.path for every datastore engine.
	// config.Validate requires datastore.path for "standalone";
	// datastore.mode "remote" is the one shape that can still reach here
	// with it empty; refuse it rather than resolve "" + "/pin" into the
	// filesystem root's own "/pin" directory (go-xkms#666).
	if s.config.Datastore.Path == "" {
		return &ErrConfigRequired{
			Field:   "datastore.path",
			Backend: "pin",
			Hint:    "the PIN state directory is derived from datastore.path and must not resolve to the filesystem root",
		}
	}
	pinDir := filepath.Join(s.config.Datastore.Path, "pin")

	persisted, err := pinselect.LoadStrategy(pinDir)
	if err != nil && !errors.Is(err, pinselect.ErrStrategyNotPersisted) {
		return err
	}
	// An operator who configures tpm2, like a PIN directory that already
	// records it, says TPM2 governs: the Platform SRK is offered even before
	// this process has confirmed its auth value, and the backend reports the
	// PIN unset until a verification succeeds (see pinselect.NewTPMProvider).
	tpm2Governs := persisted == qrdbsdk.PINStrategyTPM2 || strategy == qrdbsdk.PINStrategyTPM2

	backend, governing, err := pinselect.Resolve(pinselect.ResolveConfig{
		PINDir:   pinDir,
		Strategy: strategy,
		Config: pinselect.Config{
			TPM:      pinselect.NewTPMProvider(s.acquirePINTPM, tpm2Governs, s.logger),
			Software: softwarePINProvider{dir: pinDir},
			Logger:   s.logger,
		},
	})
	if err != nil {
		return err
	}
	s.pinManager = backend

	s.logger.Info("PIN manager initialized", slog.String("strategy", string(governing)))
	return nil
}

// acquirePINTPM returns xkmsd's TPM -- the one the TPM2 key backend opened
// -- with its PlatformKeyStore attached, for the TPM2 PIN strategy. It
// reports ErrPINTPMUnavailable when backends.tpm2 is not enabled.
func (s *Server) acquirePINTPM() (pinselect.PlatformKeyStoreProvider, error) {
	backend, ok := s.keyProviders["tpm2"].(*tpm2backend.Backend)
	if !ok {
		return nil, ErrPINTPMUnavailable
	}
	tpm := backend.TPM()
	if _, err := pkgtpm2.AttachPlatformKeyStore(s.logger, tpm, backend.KeyBackend()); err != nil {
		return nil, err
	}
	return tpm, nil
}

// softwarePINProvider is the pinselect.SoftwareProvider for xkmsd: the
// software PIN store is file-backed in dir.
type softwarePINProvider struct {
	dir string
}

// Storage opens the file-backed software PIN store.
func (p softwarePINProvider) Storage() (qrdbsdk.PINStorage, error) {
	fileStore, err := filestorage.New(p.dir)
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "PIN state directory", Err: err}
	}
	store, err := pinadapter.New(fileStore)
	if err != nil {
		return nil, err
	}
	return store, nil
}

// HashConfig returns the software backend's PIN hash parameters.
func (p softwarePINProvider) HashConfig() qrdbsdk.PINHashConfig {
	return qrdbsdk.AutoDetectHashConfig()
}
