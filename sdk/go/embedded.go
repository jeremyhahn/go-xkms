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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/compose"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// EmbeddedServiceConfig configures an in-process XKMS service for embedded-mode
// clients (no network). It replaces the pkg/* bootstrap that xkmsctl and xkey
// previously assembled by hand, so client binaries depend only on sdk/go.
type EmbeddedServiceConfig struct {
	// KeyDir is the filesystem root for key and certificate storage. Key
	// material lives under KeyDir and certificates under KeyDir/certs.
	KeyDir string

	// BackendName registers the embedded software backend under this name and
	// makes it the default backend. Defaults to "software".
	BackendName string

	// KeyStorage optionally overrides where the software backend keeps key
	// material. When nil, a plain file backend under KeyDir is used. A caller
	// that wants the key material encrypted at rest passes a barrier-backed
	// storage.Backend here (e.g. from pkg/pkcs11/localseal), so the embedded
	// service consumes go-qrdb's barrier rather than any bespoke sealer.
	KeyStorage StorageBackend

	// CA optionally runs a Certificate Authority in the embedded service.
	// When set, NewEmbeddedService builds a TrustedCA from it on file stores
	// under KeyDir/ca (its certificate store in KeyDir/ca/certs), loading the
	// CA persisted there or initializing a new one, and wires it into the
	// service so the CA verbs are served in-process. Each CA key resolves its
	// keystore by its store type among the registered backends, so the
	// config's keys must use a store type that names a registered backend:
	// the default config's software keys need the default BackendName. Nil
	// leaves the service without a CA.
	CA *TrustedCAMultiIdentityConfig
}

// NewEmbeddedService builds and initializes the in-process XKMS service with a
// file-backed software backend, returning the servicer. Pass the result to
// NewEmbedded to obtain a Client, or use NewEmbeddedClient for the one-call
// form. This initializes the process-wide XKMS service singleton.
//
// The software backend is constructed via the existing SDK NewSoftwareBackend
// constructor; storage comes from the SDK file backend — no pkg/* imports are
// required of callers.
func NewEmbeddedService(cfg EmbeddedServiceConfig) (XKMSServicer, error) {
	keyStorage := cfg.KeyStorage
	if keyStorage == nil {
		var err error
		keyStorage, err = NewFileStorageBackend(cfg.KeyDir)
		if err != nil {
			return nil, err
		}
	}
	certStorage, err := NewFileStorageBackend(cfg.KeyDir + "/certs")
	if err != nil {
		return nil, err
	}

	backend, err := NewSoftwareBackend(&SoftwareBackendConfig{KeyStorage: keyStorage})
	if err != nil {
		return nil, err
	}

	keystore, err := pkgxkms.New(&pkgxkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		return nil, err
	}

	name := cfg.BackendName
	if name == "" {
		name = string(ServiceBackendSoftware)
	}

	// Reset any prior singleton, then initialize with the embedded backend.
	pkgxkms.Reset()
	if err := pkgxkms.Initialize(&pkgxkms.ServiceConfig{
		Backends:       map[string]pkgxkms.Backend{name: keystore},
		DefaultBackend: name,
	}); err != nil {
		return nil, err
	}

	svc, err := pkgxkms.Get()
	if err != nil {
		return nil, err
	}
	if cfg.CA != nil {
		if err := wireEmbeddedCA(svc, cfg.KeyDir, cfg.CA); err != nil {
			return nil, err
		}
	}
	return svc, nil
}

// wireEmbeddedCA builds the CA from caConfig on file stores under keyDir/ca
// and publishes it into svc.
func wireEmbeddedCA(svc *pkgxkms.XKMSService, keyDir string, caConfig *TrustedCAMultiIdentityConfig) error {
	caDir := keyDir + "/ca"
	certBackend, err := NewFileStorageBackend(caDir + "/certs")
	if err != nil {
		return err
	}
	kv, err := NewKVStoreAdapter(certBackend)
	if err != nil {
		return err
	}
	trustedCA, err := compose.BuildCA(context.Background(), compose.CAParams{
		Config: caConfig,
		DAOs:   NewStoreDAOFactory(kv),
		Storage: func(name string) (StorageBackend, error) {
			return NewFileStorageBackend(caDir + "/" + name)
		},
		BackendForStore: func(_ string, storeType StoreType) (pkgxkms.Backend, error) {
			return svc.LookupBackend(string(storeType))
		},
	})
	if err != nil {
		return err
	}
	(&compose.Stores{CA: trustedCA}).Wire(svc)
	return nil
}

// NewEmbeddedClient is a one-call convenience that builds the embedded service
// and returns a Client wired to the in-process transport.
func NewEmbeddedClient(cfg EmbeddedServiceConfig) (Client, error) {
	svc, err := NewEmbeddedService(cfg)
	if err != nil {
		return nil, err
	}
	return NewEmbedded(svc)
}
