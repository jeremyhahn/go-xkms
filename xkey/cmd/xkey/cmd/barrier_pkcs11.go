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

package cmd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// barrierPresealSubdir is the directory, under the barrier data directory,
// of the pre-barrier secret store holding the PKCS#11 token PIN.
const barrierPresealSubdir = "preseal"

// barrierPKCS11CN names the PKCS#11 wrapping key that seals the barrier's
// root key.
const barrierPKCS11CN = "xkey-barrier-pkcs11"

// pkcs11 barrier strategy flags for `xkey barrier init`. The token PIN is
// never a flag: it is prompted for, or read from the first line of piped
// standard input, and sealed to this host's TPM.
var (
	barrierPKCS11Library string
	barrierPKCS11Token   string
)

// openBarrierPresealTPM opens the TPM the pre-barrier store seals through.
// Tests replace it to hold one provisioned simulator open across init and
// unseal, because the in-process simulator is reset on every open.
var openBarrierPresealTPM = openTPMModule

// ErrBarrierPKCS11PINEmpty indicates an empty PKCS#11 token PIN was entered.
var ErrBarrierPKCS11PINEmpty = &BarrierError{Operation: "read_pkcs11_pin", Message: "PKCS#11 PIN cannot be empty"}

func init() {
	barrierInitCmd.Flags().StringVar(&barrierPKCS11Library, "pkcs11-library", "",
		"PKCS#11 module path for the pkcs11 strategy")
	barrierInitCmd.Flags().StringVar(&barrierPKCS11Token, "pkcs11-token", "",
		"PKCS#11 token label for the pkcs11 strategy")
}

// initBarrierPKCS11 saves the token the --pkcs11-* flags name into the xkey
// config, reads the token PIN and seals it to this host's TPM, so every later
// unseal logs in to the token without asking again. A no-op for every other
// strategy.
func initBarrierPKCS11(ctx context.Context, out io.Writer, strategyFlag, dataDir string) error {
	if strategyFlag != "pkcs11" {
		return nil
	}
	cfg := GetConfig()
	if cfg == nil {
		return ErrBarrierConfigNotLoaded
	}
	pkcs11Cfg := &config.BarrierPKCS11Config{Library: barrierPKCS11Library, Token: barrierPKCS11Token}
	if err := pkcs11Cfg.Validate(); err != nil {
		return err
	}

	pin, err := readBarrierPassword(out, "PKCS#11 token PIN: ")
	if errors.Is(err, ErrBarrierPasswordEmpty) {
		return ErrBarrierPKCS11PINEmpty
	}
	if err != nil {
		return err
	}
	if err := sealBarrierPKCS11PIN(ctx, dataDir, barrierTPMDevice, barrierTPMSimulator, []byte(pin)); err != nil {
		return err
	}

	cfg.Barrier.PKCS11 = pkcs11Cfg
	if err := config.Save(cfg); err != nil {
		return &BarrierError{Operation: "save_config", Err: err}
	}
	return nil
}

// sealBarrierPKCS11PIN seals pin into the pre-barrier secret store under
// dataDir, replacing any PIN sealed before, and wipes pin.
func sealBarrierPKCS11PIN(ctx context.Context, dataDir, tpmDevice string, tpmSimulator bool, pin []byte) error {
	defer clear(pin)
	store, closeStore, err := openBarrierPreseal(dataDir, tpmDevice, tpmSimulator)
	if err != nil {
		return err
	}
	if err := errors.Join(store.Put(ctx, xkms.PresealPKCS11PIN, pin), closeStore()); err != nil {
		return &BarrierError{Operation: "seal_pkcs11_pin", Err: err}
	}
	return nil
}

// buildPKCS11BarrierStrategy releases the token PIN `xkey barrier init
// --strategy pkcs11` sealed to the TPM tpmDevice and tpmSimulator select,
// and logs in to the configured token with it.
func buildPKCS11BarrierStrategy(ctx context.Context, dataDir, tpmDevice string, tpmSimulator bool) (xkms.SealingStrategy, io.Closer, error) {
	cfg := GetConfig()
	if cfg == nil {
		return nil, nil, ErrBarrierConfigNotLoaded
	}
	pkcs11Cfg := cfg.Barrier.PKCS11
	if err := pkcs11Cfg.Validate(); err != nil {
		return nil, nil, err
	}

	store, closeStore, err := openBarrierPreseal(dataDir, tpmDevice, tpmSimulator)
	if err != nil {
		return nil, nil, err
	}
	strategy, closer, err := xkms.BuildPKCS11StrategyWithSealedPIN(ctx, store,
		barrierPKCS11CN, pkcs11Cfg.Library, pkcs11Cfg.Token)
	if closeErr := closeStore(); closeErr != nil {
		slog.Default().Warn("barrier: closing the pre-barrier secret store failed", "error", closeErr)
	}
	if err != nil {
		return nil, nil, &BarrierError{Operation: "assemble_strategy", Err: err}
	}
	return strategy, closer, nil
}

// openBarrierPreseal opens the TPM tpmDevice and tpmSimulator select and the
// pre-barrier secret store under dataDir. The returned func closes the store
// and then the TPM.
func openBarrierPreseal(dataDir, tpmDevice string, tpmSimulator bool) (*xkms.PresealStore, func() error, error) {
	logger := slog.Default()
	tpm, tpmCloser, err := openBarrierPresealTPM(logger, dataDir, tpmDevice, tpmSimulator)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "open_tpm", Err: err}
	}
	store, err := xkms.OpenPreseal(tpm, filepath.Join(dataDir, barrierPresealSubdir), logger)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "open_preseal", Err: errors.Join(err, tpmCloser.Close())}
	}
	closeAll := func() error {
		return errors.Join(store.Close(), tpmCloser.Close())
	}
	return store, closeAll, nil
}
