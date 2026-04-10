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

package transport

import (
	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Service interfaces re-exported from pkg/transport.
type ConnectionService = pkgtransport.ConnectionService
type BackendService = pkgtransport.BackendService
type KeyService = pkgtransport.KeyService
type CryptoService = pkgtransport.CryptoService
type CertService = pkgtransport.CertService
type SealService = pkgtransport.SealService
type BarrierService = pkgtransport.BarrierService
type PIVService = pkgtransport.PIVService
type FIDO2Service = pkgtransport.FIDO2Service
type CAService = pkgtransport.CAService
type TCGCAService = pkgtransport.TCGCAService
type PINService = pkgtransport.PINService
type UserService = pkgtransport.UserService
type PasswordService = pkgtransport.PasswordService
type SealStoreService = pkgtransport.SealStoreService
type PolicyService = pkgtransport.PolicyService
type InitCeremonyService = pkgtransport.InitCeremonyService
type CredentialManagementService = pkgtransport.CredentialManagementService
type CustodianGroupService = pkgtransport.CustodianGroupService
type ShareService = pkgtransport.ShareService
type TenantService = pkgtransport.TenantService

// Client composes all service sub-interfaces into a unified client.
type Client = pkgtransport.Client
