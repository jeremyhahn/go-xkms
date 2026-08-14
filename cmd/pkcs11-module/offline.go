// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/localseal"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Offline (local) mode for the PKCS#11 module.
//
// By default the module dials a remote xkmsd for its cryptographic operations.
// In offline mode the .so instead embeds an in-process xkms service (a
// file-backed software backend wrapped in the SDK's embedded transport) and
// injects it as the module's transport client, so the token works with no
// network connectivity — the SoftHSM-like local mode.
//
// This is the composition root for that mode: it is the one place allowed to
// build the embedded service and set the global module (per the ownership
// model, composition roots do the wiring). The module itself stays
// transport-agnostic; it merely receives an injected client.
//
// At-rest protection of the local key material is NOT yet keyed here: the SDK's
// embedded service uses a plain file backend (strategy `none`, cleartext),
// matching SoftHSM's unencrypted default. Keying it under go-qrdb's barrier is
// the C9/L3 work — the module must consume qrdb's barrier, never build its own
// sealer (see docs/pkcs11/ROADMAP.md Decisions §C9).

const (
	// envMode selects the module's transport mode.
	envMode = "XKMS_PKCS11_MODE"

	// envLocalKeyDir overrides where offline mode stores its cryptographic key
	// material. Defaults to <StoragePath>/keys, or a standard dir when no
	// storage path is configured.
	envLocalKeyDir = "XKMS_PKCS11_LOCAL_KEYDIR"

	// modeLocal and its aliases request offline mode; anything else (including
	// the empty default) is remote mode.
	modeLocal   = "local"
	modeOffline = "offline"

	// envSealStrategy selects how offline key material is protected at rest.
	// "passphrase" (default, matches qrdb) keys it under the user PIN via
	// go-qrdb's barrier; "none" stores it in cleartext (dev/test, SoftHSM's
	// unencrypted default).
	envSealStrategy    = "XKMS_PKCS11_SEAL_STRATEGY"
	sealStrategyNone   = "none"
	sealStrategyPass   = "passphrase"
	offlineRootKeyPath = "pkcs11/token/root-key"
)

// offlineSealStrategy resolves the at-rest strategy for offline mode, defaulting
// to passphrase (secure, matches go-qrdb).
func offlineSealStrategy() string {
	if strings.ToLower(strings.TrimSpace(os.Getenv(envSealStrategy))) == sealStrategyNone {
		return sealStrategyNone
	}
	return sealStrategyPass
}

// offlineModeRequested reports whether the environment selects offline mode.
func offlineModeRequested() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envMode))) {
	case modeLocal, modeOffline:
		return true
	default:
		return false
	}
}

// localKeyDir resolves where the embedded service keeps key material.
func localKeyDir(cfg *module.Config) string {
	if dir := strings.TrimSpace(os.Getenv(envLocalKeyDir)); dir != "" {
		return dir
	}
	if cfg != nil && cfg.StoragePath != "" {
		return filepath.Join(cfg.StoragePath, "keys")
	}
	// A standard per-user location, mirroring how SoftHSM keeps a token dir.
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".xkms", "pkcs11", "keys")
	}
	return filepath.Join(os.TempDir(), "xkms-pkcs11-keys")
}

// buildOfflineModule constructs the embedded in-process xkms service and installs
// a module wired to it as the global module, so the cgo C_Initialize path uses
// the offline client with no network. It is idempotent-safe to call once before
// C_Initialize.
func buildOfflineModule() error {
	cfg := module.LoadFromEnv()

	// Offline mode persists token and object metadata locally. A memory default
	// would lose the token across process restarts, defeating the point of an
	// offline token, so promote the default to file storage rooted at the key
	// directory when the operator did not choose otherwise.
	keyDir := localKeyDir(cfg)
	if cfg.StorageType == "" || cfg.StorageType == module.StorageTypeMemory {
		cfg.StorageType = module.StorageTypeFile
		if cfg.StoragePath == "" {
			cfg.StoragePath = filepath.Join(filepath.Dir(keyDir), "state")
		}
	}

	// At-rest protection of the offline key material. Under the default
	// passphrase strategy, a go-qrdb barrier keyed by the user PIN encrypts the
	// software backend's key store; the module unseals it at C_Login(CKU_USER)
	// and reseals at logout/finalize through the injected SealController. Under
	// the `none` strategy the key store is plain (cleartext), matching SoftHSM's
	// unencrypted default.
	moduleOpts := []module.ModuleOption{module.WithConfig(cfg)}
	embeddedCfg := xkmssdk.EmbeddedServiceConfig{KeyDir: keyDir}

	if offlineSealStrategy() == sealStrategyPass {
		base, err := filestorage.New(keyDir)
		if err != nil {
			return err
		}
		controller, sealedStore, err := localseal.New(base, offlineRootKeyPath, nil)
		if err != nil {
			return err
		}
		embeddedCfg.KeyStorage = sealedStore
		moduleOpts = append(moduleOpts, module.WithSealController(controller))
	}

	client, err := xkmssdk.NewEmbeddedClient(embeddedCfg)
	if err != nil {
		return err
	}
	moduleOpts = append(moduleOpts, module.WithClient(client))

	m, err := module.New(moduleOpts...)
	if err != nil {
		return err
	}
	module.SetGlobalModule(m)
	return nil
}
