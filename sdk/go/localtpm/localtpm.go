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

// Package localtpm re-exports go-xkms pkg/localtpm: the TPM policy service
// a client runs in-process over the host's own TPM (named-policy registry,
// policy authority, NV indexes, approval counter), shared by xkey and
// xkmsctl.
package localtpm

import pkg "github.com/jeremyhahn/go-xkms/pkg/localtpm"

type (
	// Policies is the in-process TPM policy service over the host's TPM.
	Policies = pkg.Policies
	// Params are Open's dependencies.
	Params = pkg.Params
	// Host is the host's TPM, its key store and the policy service.
	Host = pkg.Host
	// Device is the host's TPM and its own key store.
	Device = pkg.Device
	// DeviceParams are OpenDevice's and OpenHost's parameters.
	DeviceParams = pkg.DeviceParams
	// BuildError reports a service that could not be built.
	BuildError = pkg.BuildError
	// DeviceError reports a TPM device that does not exist.
	DeviceError = pkg.DeviceError
)

var (
	// Open builds the service over an open TPM and its key store.
	Open = pkg.Open
	// OpenDevice opens the host's TPM with its key store.
	OpenDevice = pkg.OpenDevice
	// OpenHost opens the host's TPM, its key store and the service.
	OpenHost = pkg.OpenHost
)

var (
	ErrNoTPM              = pkg.ErrNoTPM
	ErrNoKeys             = pkg.ErrNoKeys
	ErrNoDataDir          = pkg.ErrNoDataDir
	ErrNoStoreOpener      = pkg.ErrNoStoreOpener
	ErrObjectNameRequired = pkg.ErrObjectNameRequired
)
