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

//go:build pkcs11

package server

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11strategy"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// initPKCS11Backend initializes the PKCS#11 backend if enabled in configuration
func (s *Server) initPKCS11Backend() error {
	if s.config.Backends.PKCS11 == nil || !s.config.Backends.PKCS11.Enabled {
		return nil
	}

	// The node transport key opened the token before the qrdb node
	// (openPreNodePKCS11Backend): register that one instance rather than
	// opening the token a second time.
	if _, ok := s.keyProviders["pkcs11"]; ok {
		s.logger.Info("PKCS#11 backend reuses the pre-node token open", "backend", "pkcs11")
		return nil
	}

	pin, err := s.pkcs11BackendPIN()
	if err != nil {
		return err
	}
	pkcs11Backend, err := s.openPKCS11Backend(pin)
	if err != nil {
		return err
	}
	s.keyProviders["pkcs11"] = pkcs11Backend
	s.logger.Info("PKCS#11 backend initialized", "backend", "pkcs11", "library", s.config.Backends.PKCS11.Library, "token", s.config.Backends.PKCS11.Token)
	return nil
}

// pkcs11BackendPIN returns the configured token PIN or, when none is
// configured, the PIN `xkmsd seal-pkcs11-pin` sealed into the pre-barrier
// store. A store holding no PIN yields nil, which the token login refuses as
// before; any other release failure is refused here.
func (s *Server) pkcs11BackendPIN() (*types.SecretValue, error) {
	if pin := s.config.Backends.PKCS11.Pin; pin != nil {
		return pin, nil
	}
	pin, err := s.releasePreNodePKCS11PIN()
	var notSealed *preseal.NotFoundError
	if errors.As(err, &notSealed) {
		return nil, nil
	}
	return pin, err
}

// openPKCS11Backend is the one construction of the configured PKCS#11
// backend, from backends.pkcs11 and the given token PIN. Its key and
// certificate metadata live in the shared datastore through
// sharedStorageView, so a token opened before the qrdb node stores behind
// the barrier like one opened after it.
func (s *Server) openPKCS11Backend(pin *types.SecretValue) (*pkcs11.Backend, error) {
	keyStorage, err := storage.NewPrefixBackend(sharedStorageView{s: s}, "pkcs11/keys/")
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "PKCS#11 key storage", Err: err}
	}
	certStorage, err := storage.NewPrefixBackend(sharedStorageView{s: s}, "pkcs11/certs/")
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "PKCS#11 cert storage", Err: err}
	}

	pkcs11Backend, err := pkcs11.NewBackend(&pkcs11.Config{
		CN:          "pkcs11-backend",
		Library:     s.config.Backends.PKCS11.Library,
		TokenLabel:  s.config.Backends.PKCS11.Token,
		PIN:         pin,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	})
	if err != nil {
		return nil, &ErrBackendCreate{Backend: "PKCS#11", Err: err}
	}

	// Establish the session pool against the (pre-initialized) token. Without
	// this the backend constructs but every operation fails with
	// ErrNotInitialized. Token SO-initialization is an operator action
	// (softhsm2-util / HSM tooling), NOT a boot action — Login only
	// authenticates with the configured user PIN.
	if err := pkcs11Backend.Login(); err != nil {
		return nil, &ErrBackendCreate{Backend: "PKCS#11", Err: errors.Join(err, pkcs11Backend.Close())}
	}
	return pkcs11Backend, nil
}

// openPreNodePKCS11Backend opens the configured PKCS#11 token before the qrdb
// node when the node transport key lives on it
// (cluster.raft_enrollment.key_backend: pkcs11): Raft mTLS is provisioned
// before the node starts, so the key's backend must exist first. The
// configured PIN is a credential reference behind the barrier this node has
// not opened yet, so the token unlocks with the PIN sealed to the TPM in
// the pre-barrier store (`xkmsd seal-pkcs11-pin`), as the PKCS#11 node seal
// does. initPKCS11Backend then registers this instance. Without
// backends.pkcs11 nothing opens and the node key is refused
// (clusterca.ErrNodeKeyBackendNotConfigured), never substituted.
func (s *Server) openPreNodePKCS11Backend() error {
	if !s.nodeKeyOnPKCS11() || s.config.Backends.PKCS11 == nil || !s.config.Backends.PKCS11.Enabled {
		return nil
	}
	pin, err := s.releasePreNodePKCS11PIN()
	if err != nil {
		return &ErrBackendInit{Backend: "PKCS#11 node key", Err: err}
	}
	return s.registerPreNodePKCS11Backend(pin)
}

// registerPreNodePKCS11Backend opens the token with the released PIN and
// registers it as this node's one PKCS#11 key provider.
func (s *Server) registerPreNodePKCS11Backend(pin *types.SecretValue) error {
	pkcs11Backend, err := s.openPKCS11Backend(pin)
	if err != nil {
		return &ErrBackendInit{Backend: "PKCS#11 node key", Err: err}
	}
	s.keyProviders["pkcs11"] = pkcs11Backend
	s.logger.Info("PKCS#11 backend opened before the node for the transport key",
		"backend", "pkcs11", "library", s.config.Backends.PKCS11.Library, "token", s.config.Backends.PKCS11.Token)
	return nil
}

// releasePreNodePKCS11PIN releases the sealed token PIN from the pre-barrier
// store, over the TPM the seal autodetect or the platform store already
// opened when there is one (a second open hangs a simulator), else over its
// own.
func (s *Server) releasePreNodePKCS11PIN() (*types.SecretValue, error) {
	var (
		store      *preseal.Store
		closeStore func() error
		err        error
	)
	shared, ok := s.nodeSealTPM.(*tpm2backend.Backend)
	if !ok {
		shared, ok = s.platformStoreTPM.(*tpm2backend.Backend)
	}
	if ok {
		dir, dirErr := embeddednode.ResolvePresealDir(s.config)
		if dirErr != nil {
			return nil, dirErr
		}
		store, err = preseal.Open(shared.TPM(), dir, s.logger)
		if err != nil {
			return nil, err
		}
		closeStore = store.Close
	} else {
		store, closeStore, err = embeddednode.OpenPreseal(s.config, s.logger)
		if err != nil {
			return nil, err
		}
	}
	pin, err := pkcs11strategy.ReleaseSealedPIN(s.ctx, store)
	if closeErr := closeStore(); closeErr != nil {
		s.logger.Warn("PKCS#11 node key: closing the pre-barrier secret store failed", "error", closeErr)
	}
	return pin, err
}

// nodeKeyOnPKCS11 reports whether this node provisions its Raft transport
// key on the PKCS#11 token: a multi-node cluster, auto-enrolled (no
// operator-supplied Raft TLS files), with key_backend pkcs11.
func (s *Server) nodeKeyOnPKCS11() bool {
	cluster := s.config.Cluster
	return cluster.Enabled && !cluster.RaftTLS.Enabled() &&
		cluster.RaftEnrollment.KeyBackend == string(xkms.BackendPKCS11)
}
