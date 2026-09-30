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

package server

import (
	"path/filepath"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
)

// vtpmStateSubdir and vtpmRunSubdir are the default vTPM state and socket
// directories under the configured storage path.
const (
	vtpmStateSubdir = "vtpm"
	vtpmRunSubdir   = "vtpm-run"
)

// resolveTPM2KeyDir resolves the directory where TPM2-sealed key material is
// persisted. It is always derived from the configured storage path and must
// never fall back to a directory resolved relative to the process's working
// directory: some callers of this package (embedded/programmatic
// construction of *config.Config) never run config.Config.Validate, so an
// empty Datastore.Path cannot be assumed to have already been rejected.
// Delegates to embeddednode.ResolveTPM2KeyDir so this backend and the TPM2
// node-barrier seal strategy always agree on one directory
// (embeddednode.KeyDirSubdir).
func (s *Server) resolveTPM2KeyDir() (string, error) {
	return embeddednode.ResolveTPM2KeyDir(s.config)
}

// initTPM2Backend initializes the TPM2 backend if enabled in configuration
func (s *Server) initTPM2Backend() error {
	if s.config.Backends.TPM2 == nil || !s.config.Backends.TPM2.Enabled {
		return nil
	}

	// Get device path with default
	devicePath := s.config.Backends.TPM2.DevicePath
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}

	// keyDir is the TPM2 node-barrier seal strategy's own key directory --
	// genuinely pre-datastore material (see docs/datastore/architecture.md),
	// resolved directly under Datastore.Path rather than through the shared
	// datastore itself. It is used ONLY below, as an optional ListKeys
	// enumeration hint when this backend shares an already-open TPM
	// connection with that strategy; it is never this backend's own key
	// storage (see keyStorage further down for that).
	keyDir, err := s.resolveTPM2KeyDir()
	if err != nil {
		return &ErrBackendCreate{Backend: "TPM2", Err: err}
	}

	// When an earlier step already opened this TPM -- the seal autodetect for
	// the node-barrier flip (s.nodeSealTPM), or the platform store's tpm2
	// credential strategy (s.platformStoreTPM, initializePlatformStore, which
	// runs before this) -- reuse that single open: build the general backend
	// over the SAME TPM connection via NewBackendWithTPM. A second independent
	// open hangs the simulator (and a real swtpm); sharing the connection also
	// keeps one PlatformKeyStore / policy state. Whichever field opened it owns
	// closing it (nodeSealClose at node shutdown, or platformStoreTPMClose at
	// server shutdown) -- not this backend (externalTPM).
	//
	// KeyBackend reuses shared.KeyBackend() -- the SAME store.KeyBackend the
	// earlier open built (tpm2backend.NewBackend) over this identical keyDir,
	// resolveTPM2KeyDir in both paths -- rather than opening a second file
	// store over the same directory. Key blobs created under the shared TPM
	// are parented to the same Platform SRK the barrier uses, so the barrier
	// and this backend read and write one on-disk key store and share one
	// parent key. The TCG Shared SRK is never used.
	shared, ok := s.nodeSealTPM.(*tpm2backend.Backend)
	sharedFrom := "the seal autodetect's single TPM open"
	if !ok {
		shared, ok = s.platformStoreTPM.(*tpm2backend.Backend)
		sharedFrom = "the platform store's tpm2 credential strategy TPM open"
	}
	if ok {
		tpmBackend, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
			TPM:        shared.TPM(),
			KeyBackend: shared.KeyBackend(),
			KeyDir:     keyDir,
			Logger:     s.logger,
		})
		if err != nil {
			return &ErrBackendCreate{Backend: "TPM2", Err: err}
		}
		s.keyProviders["tpm2"] = tpmBackend
		s.logger.Info("TPM2 backend reuses "+sharedFrom, "backend", "tpm2", "device", devicePath)
		return nil
	}

	// Not sharing a TPM connection: this backend's own key storage is a
	// key-prefixed view over the single shared datastore (createStorage),
	// never a private file engine -- pkg/backend/tpm2.Config has no KeyDir
	// path anymore (go-xkms#1345 batch 2).
	keyStorage, err := s.createStorage("tpm2")
	if err != nil {
		return &ErrBackendCreate{Backend: "TPM2", Err: err}
	}

	// Create TPM2 backend configuration
	tpmConfig := &tpm2backend.Config{
		Device:          devicePath,
		KeyStorage:      keyStorage,
		CN:              "xkms",
		UseSimulator:    s.config.Backends.TPM2.UseSimulator,
		SimulatorHost:   s.config.Backends.TPM2.SimulatorHost,
		SimulatorPort:   s.config.Backends.TPM2.SimulatorPort,
		SRKHandle:       s.config.Backends.TPM2.SRKHandle,
		PlatformPCR:     s.config.Backends.TPM2.PlatformPCR,
		PlatformPCRBank: s.config.Backends.TPM2.PlatformPCRBank,
	}

	// Create TPM2 backend
	tpmBackend, err := tpm2backend.NewBackend(tpmConfig)
	if err != nil {
		return &ErrBackendCreate{Backend: "TPM2", Err: err}
	}

	s.keyProviders["tpm2"] = tpmBackend
	s.logger.Info("TPM2 backend initialized", "backend", "tpm2", "device", devicePath)
	return nil
}

// initTPMPolicyService builds the TPM policy service (pkg/tpmpolicy) over
// the TPM2 key backend through compose.BuildTPMPolicyService -- the path an
// embedding host's module takes -- and installs it as the backend's scope
// provider, so every TPM2 key and seal runs in its tenant's TPM scope.
// Without a TPM2 backend the service stays off and the typed reason is
// logged.
func (s *Server) initTPMPolicyService() error {
	backend, ok := s.keyProviders["tpm2"].(*tpm2backend.Backend)
	if !ok {
		disabled := &compose.FeatureDisabledError{Feature: compose.FeatureTPMPolicies, Missing: "TPM2 backend (backends.tpm2 is not enabled)"}
		s.logger.Info("xkms feature off", "feature", compose.FeatureTPMPolicies, "reason", disabled.Error())
		return nil
	}
	svc, err := compose.BuildTPMPolicyService(compose.TPMPolicyParams{
		Backend: backend,
		Storage: s.createStorage,
		VTPM:    s.vtpmConfig(),
		Logger:  s.logger,
	})
	if err != nil {
		return err
	}
	s.tpmPolicies = svc
	s.logger.Info("xkms feature on", "feature", compose.FeatureTPMPolicies, "vtpm", s.vtpmConfig() != nil)
	return nil
}

// vtpmConfig resolves backends.tpm2.vtpm into the vTPM supervisor's
// configuration, applying the storage-path defaults. It is nil -- vtpm mode
// unavailable -- unless the section enables vTPMs.
func (s *Server) vtpmConfig() *vtpm.Config {
	tpmCfg := s.config.Backends.TPM2
	if tpmCfg == nil || tpmCfg.VTPM == nil || !tpmCfg.VTPM.Enabled {
		return nil
	}
	cfg := &vtpm.Config{
		Binary:   tpmCfg.VTPM.Binary,
		StateDir: tpmCfg.VTPM.StateDir,
		RunDir:   tpmCfg.VTPM.RunDir,
		Logger:   s.logger,
	}
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(s.config.Datastore.Path, vtpmStateSubdir)
	}
	if cfg.RunDir == "" {
		cfg.RunDir = filepath.Join(s.config.Datastore.Path, vtpmRunSubdir)
	}
	return cfg
}

// closeTPMPolicies closes the TPM policy service -- its open scopes and
// vTPMs -- before the TPM it runs over is closed. Idempotent.
func (s *Server) closeTPMPolicies() {
	if s.tpmPolicies == nil {
		return
	}
	svc := s.tpmPolicies
	s.tpmPolicies = nil
	if err := svc.Close(); err != nil {
		s.logger.Error("Error closing the TPM policy service", "error", err)
	}
}

// TPMPolicyService returns the TPM policy service, or nil when xkmsd has no
// TPM2 backend.
func (s *Server) TPMPolicyService() *tpmpolicy.Service {
	return s.tpmPolicies
}
