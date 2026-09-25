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

package embedded

import (
	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// XKMSServicer is the full surface the embedded transport requires from its
// backing service. It composes pkgtransport.XKMSServicer with
// pkgtransport.EscrowServicer: external key escrow (go-xkms#692) is
// embedded-only until Escrow's RBAC model is decided, so this is the one
// place in the stack that still requires it. It is a genuine composed
// interface, not a re-export like the rest of this file, precisely because
// pkgtransport.XKMSServicer itself no longer carries Escrow.
type XKMSServicer interface {
	pkgtransport.XKMSServicer
	pkgtransport.EscrowServicer
}

// Servicer interfaces re-exported from pkg/transport.
type HealthServicer = pkgtransport.HealthServicer
type BackendServicer = pkgtransport.BackendServicer
type KeyServicer = pkgtransport.KeyServicer
type CryptoServicer = pkgtransport.CryptoServicer
type CertServicer = pkgtransport.CertServicer
type SealServicer = pkgtransport.SealServicer
type BarrierServicer = pkgtransport.BarrierServicer
type PIVServicer = pkgtransport.PIVServicer
type FIDO2Servicer = pkgtransport.FIDO2Servicer
type CAServicer = pkgtransport.CAServicer
type TCGCAServicer = pkgtransport.TCGCAServicer
type PINServicer = pkgtransport.PINServicer
type UserServicer = pkgtransport.UserServicer
type PasswordServicer = pkgtransport.PasswordServicer
type SealStoreServicer = pkgtransport.SealStoreServicer
type PolicyServicer = pkgtransport.PolicyServicer
type CustodianGroupServicer = pkgtransport.CustodianGroupServicer
type ShareServicer = pkgtransport.ShareServicer
type TenantServicer = pkgtransport.TenantServicer
type InitCeremonyServicer = pkgtransport.InitCeremonyServicer
type CredentialManagementServicer = pkgtransport.CredentialManagementServicer
type EscrowServicer = pkgtransport.EscrowServicer
