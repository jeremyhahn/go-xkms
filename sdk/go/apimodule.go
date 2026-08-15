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

import "github.com/jeremyhahn/go-xkms/pkg/apimodule"

// go-xkms's qrdb ServiceModule surface, re-exported so downstream hosts
// (go-quicbaas, go-trusted-platform) that embed a qrdb node can register the
// xkms hardware crypto + identity plane via qrdbsdk.WithModule without
// importing go-xkms/pkg. The stack-wide convention is one module per provider
// project, named after the project; xkms's registers as ModuleName ("xkms").

// ServiceModuleName is the unique name xkms's module registers under.
const ServiceModuleName = apimodule.ModuleName

// ServiceModule is go-xkms's hardware crypto + identity plane as a qrdb
// ServiceModule.
type ServiceModule = apimodule.Module

// ServiceModuleOption configures optional ServiceModule behavior at
// construction time.
type ServiceModuleOption = apimodule.Option

// ServiceModuleResolver returns the composed *XKMSService, or nil while the
// host is still composing it; the module binds lazily on the first RPC.
type ServiceModuleResolver = apimodule.ServiceResolver

// ServiceModuleSSHResolver returns the SSH SDK client for the module's SSH
// RPCs, or nil when the SSH subsystem is unavailable.
type ServiceModuleSSHResolver = apimodule.SSHClientResolver

// NewServiceModule builds go-xkms's ServiceModule around the XKMSService
// resolver. A nil resolver is a composition error and fails construction.
var NewServiceModule = apimodule.NewModule

// WithServiceModuleSSHClient wires the SSH SDK client resolver used by the
// module's SSH RPC handlers.
var WithServiceModuleSSHClient = apimodule.WithSSHClient
