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

package embeddednode

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11strategy"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
)

// PresealSubdir is the fixed subdirectory, under the configured datastore
// path, holding the pre-barrier secrets (the PKCS#11 token PIN), each sealed
// under the PSRK with the platform PCR policy.
const PresealSubdir = "preseal"

// PKCS11NodeSealCN names the PKCS#11 wrapping key that seals the node
// barrier's root key.
const PKCS11NodeSealCN = "xkms-node-seal-pkcs11"

// ResolvePresealDir returns the pre-barrier secret store directory, derived
// from cfg.Datastore.Path so it never resolves relative to the process
// working directory.
func ResolvePresealDir(cfg *config.Config) (string, error) {
	if cfg.Datastore.Path == "" {
		return "", &ErrDatastorePathRequired{Reason: "the pre-barrier secret store"}
	}
	return filepath.Join(cfg.Datastore.Path, PresealSubdir), nil
}

// OpenPreseal opens the TPM backends.tpm2 configures and the pre-barrier
// secret store over it. ResolveNodeSeal releases the PKCS#11 token PIN
// through it at boot; `xkmsd seal-pkcs11-pin` seals the PIN through it. The
// returned func closes the store and then the TPM.
func OpenPreseal(cfg *config.Config, logger *slog.Logger) (*preseal.Store, func() error, error) {
	dir, err := ResolvePresealDir(cfg)
	if err != nil {
		return nil, nil, &NodeSealError{Reason: "resolving the pre-barrier secret store directory", Err: err}
	}
	res, err := openNodeTPM(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	backend, ok := res.Sealer.(*tpm2backend.Backend)
	if !ok {
		return nil, nil, &NodeSealError{
			Reason: "the seal autodetect returned an unexpected TPM sealer",
			Err:    res.Close(),
		}
	}
	store, err := preseal.Open(backend.TPM(), dir, logger)
	if err != nil {
		return nil, nil, &NodeSealError{
			Reason: "opening the pre-barrier secret store",
			Err:    errors.Join(err, res.Close()),
		}
	}
	closeAll := func() error {
		return errors.Join(store.Close(), res.Close())
	}
	return store, closeAll, nil
}

// resolvePKCS11NodeSeal builds the pkcs11 node seal: it releases the token
// PIN from the pre-barrier secret store, logs in to the configured token
// with it, and closes the store and the TPM (the strategy needs them no
// further). The result's Close releases the PKCS#11 session.
func resolvePKCS11NodeSeal(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error) {
	pkcs11Cfg := cfg.Backends.PKCS11
	if pkcs11Cfg == nil {
		return ResolvedNodeSeal{}, &NodeSealError{
			Reason: "strategy pkcs11 configured for the node seal but backends.pkcs11 is not set",
		}
	}
	store, closeStore, err := OpenPreseal(cfg, logger)
	if err != nil {
		return ResolvedNodeSeal{}, err
	}
	strategy, closer, err := pkcs11strategy.BuildWithSealedPIN(context.Background(), store,
		PKCS11NodeSealCN, pkcs11Cfg.Library, pkcs11Cfg.Token)
	if closeErr := closeStore(); closeErr != nil {
		logger.Warn("node barrier: closing the pre-barrier secret store failed", "error", closeErr)
	}
	if err != nil {
		return ResolvedNodeSeal{}, &NodeSealError{Reason: "building the PKCS#11 node seal", Err: err}
	}
	return ResolvedNodeSeal{Enabled: true, Strategy: strategy, Close: closer.Close}, nil
}
