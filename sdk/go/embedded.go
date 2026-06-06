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
	keyStorage, err := NewFileStorageBackend(cfg.KeyDir)
	if err != nil {
		return nil, err
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

	return pkgxkms.Get()
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
