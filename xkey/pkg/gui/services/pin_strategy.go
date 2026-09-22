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

package services

import (
	"log/slog"
	"os"
	"path/filepath"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pinstrategy"
)

// ResolvePINBackend resolves the PIN backend that governs the PIN state
// under dataDir, through the shared pinstrategy package (go-xkms#307): the
// same rule the headless daemon and `xkey pin` use, so a PIN set through
// any one of them authenticates through the others. It is the business
// logic behind App.initPINService, kept in the service layer (rather than
// the Wails-bound App type) so it is unit-testable without a GUI runtime.
//
// tpmAccessor may be nil (no TPM in this environment); ResolvePINBackend
// still resolves, falling through to the software strategy exactly as
// pinselect does when its TPM provider reports unavailable.
func ResolvePINBackend(
	tpmAccessor *TPMAccessor,
	dataDir string,
	engine xkmssdk.StorageEngineKind,
	log *slog.Logger,
) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error) {
	if log == nil {
		log = slog.Default()
	}

	pinDir := filepath.Join(dataDir, "pin")

	persisted, loadErr := pinstrategy.Load(pinDir)
	persistedTPM2 := loadErr == nil && persisted == qrdbsdk.PINStrategyTPM2

	var tpmProvider xkmssdk.PINTPMProvider
	if tpmAccessor != nil {
		tpmProvider = pinstrategy.NewTPMProvider(func() (pinstrategy.PlatformKeyStoreProvider, error) {
			tpm, err := tpmAccessor.Acquire()
			if err != nil {
				return nil, err
			}
			tpmAccessor.Release()
			return tpm, nil
		}, persistedTPM2, log)
	}

	return pinstrategy.Resolve(pinstrategy.Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			TPM:      tpmProvider,
			Software: softwarePINProvider{dataDir: dataDir, engine: engine},
			Logger:   log,
		},
	})
}

// softwarePINProvider persists software PIN state under <dataDir>/pin and
// routes through the PIN adapter so the qrdb software backend observes
// the canonical not-found error on a fresh install, rather than treating
// the raw file storage backend's own not-found error as a load failure.
type softwarePINProvider struct {
	dataDir string
	engine  xkmssdk.StorageEngineKind
}

// Storage implements pinselect.SoftwareProvider.
func (p softwarePINProvider) Storage() (qrdbsdk.PINStorage, error) {
	pinDir := filepath.Join(p.dataDir, "pin")
	if err := os.MkdirAll(pinDir, 0700); err != nil {
		return nil, err
	}
	fs, err := xkmssdk.StorageOpenEngine(xkmssdk.StorageEngineConfig{Kind: p.engine, Path: pinDir})
	if err != nil {
		return nil, err
	}
	return xkmssdk.NewPINStoreAdapter(fs)
}

// HashConfig implements pinselect.SoftwareProvider.
func (p softwarePINProvider) HashConfig() qrdbsdk.PINHashConfig {
	return qrdbsdk.AutoDetectHashConfig()
}
