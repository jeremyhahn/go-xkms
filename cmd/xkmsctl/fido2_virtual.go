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

//go:build integration && fido2

// This file exists only for the FIDO2 integration test harness
// (test/integration/fido2, tags "integration,fido2"), which execs a built
// xkmsctl binary and needs it to drive a software CTAP2 authenticator instead
// of physical hardware. It is compiled in only when xkmsctl is built with
// both the "integration" and "fido2" tags; the release binary (built with
// neither tag, see Makefile targets build-cli and release-*) never contains
// this file and has no path to a virtual authenticator. See go-xkms#807 and
// go-xkms#804.
package main

import (
	"os"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/virtualdevice"
)

// init overrides the production factory with one that also understands the
// FIDO2_USE_VIRTUAL test switch. This only takes effect in binaries built
// with the "integration,fido2" tags.
func init() {
	fido2HandlerFactory = virtualFIDO2HandlerFactory
}

// virtualFIDO2HandlerFactory builds a FIDO2 handler backed by a software
// CTAP2 authenticator when FIDO2_USE_VIRTUAL=true is set in the process
// environment, falling back to defaultFIDO2HandlerFactory (real hardware)
// otherwise.
//
// When FIDO2_VIRTUAL_STATE_DIR is also set, credential state is persisted to
// the filesystem so that credentials survive across CLI invocations. Without
// it, credentials are stored in memory and lost when the process exits.
func virtualFIDO2HandlerFactory(config *fido2.Config) (fido2.Handler, error) {
	if os.Getenv("FIDO2_USE_VIRTUAL") != "true" {
		return defaultFIDO2HandlerFactory(config)
	}

	// Build virtual device configuration
	deviceConfig := &virtualdevice.NativeVirtualDeviceConfig{
		SerialNumber:               "XKMSCTL-VFIDO",
		Manufacturer:               "go-xkms",
		Product:                    "xKey Virtual",
		EnablePIN:                  true,
		EnableHMACSecret:           true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
	}

	// Use file-based credential storage when a state directory is configured.
	// This allows credentials registered in one CLI invocation to persist
	// and be available for authentication in subsequent invocations.
	if stateDir := os.Getenv("FIDO2_VIRTUAL_STATE_DIR"); stateDir != "" {
		storage, err := newFileCredentialStorage(stateDir)
		if err != nil {
			return nil, err
		}
		deviceConfig.Storage = storage
	}

	device, err := virtualdevice.NewNativeVirtualDevice(deviceConfig)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateVirtualDeviceFailed, Err: err}
	}

	virtualEnumerator := virtualdevice.NewNativeVirtualDeviceEnumerator()
	if err := virtualEnumerator.RegisterDevice(device); err != nil {
		return nil, &WrappedError{Sentinel: ErrRegisterVirtualDeviceFailed, Err: err}
	}

	return fido2.NewHandler(config, virtualEnumerator)
}

// newFileCredentialStorage creates a file-backed StatefulCredentialStorage using
// the given directory as the root for file storage. This adapts the go-xkms
// file storage backend into the authenticator's credential storage interface.
func newFileCredentialStorage(stateDir string) (authenticator.StatefulCredentialStorage, error) {
	backend, err := client.NewFileStorageBackend(stateDir)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrVirtualStorageInit, Err: err}
	}

	storage, err := authenticator.NewBackendStorage(backend, "fido2/virtual/")
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrVirtualCredentialStorageInit, Err: err}
	}

	return storage, nil
}
