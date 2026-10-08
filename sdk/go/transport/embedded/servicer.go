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
	pkgembed "github.com/jeremyhahn/go-xkms/pkg/api/transport/embedded"
)

// XKMSServicer re-exports pkg/api/transport/embedded's XKMSServicer, NOT
// pkgtransport.XKMSServicer directly: the embedded transport requires
// EscrowServicer in addition to pkgtransport.XKMSServicer (go-xkms#692 —
// external key escrow is embedded-only), and this package's New/NewWithService
// pass their service argument straight through to pkgembed.New/NewWithService,
// so the two must stay the same type or every embedded-service caller through
// this SDK wrapper fails to compile.
type XKMSServicer = pkgembed.XKMSServicer

// Servicer interfaces re-exported from pkg/transport.
type HealthServicer = pkgtransport.HealthServicer
type BackendServicer = pkgtransport.BackendServicer
type KeyServicer = pkgtransport.KeyServicer
type KeyVersionServicer = pkgtransport.KeyVersionServicer
type CryptoServicer = pkgtransport.CryptoServicer
type CertServicer = pkgtransport.CertServicer
type SealServicer = pkgtransport.SealServicer
type PIVServicer = pkgtransport.PIVServicer
type FIDO2Servicer = pkgtransport.FIDO2Servicer
type CAServicer = pkgtransport.CAServicer
type TCGCAServicer = pkgtransport.TCGCAServicer
type PINServicer = pkgtransport.PINServicer
type UserServicer = pkgtransport.UserServicer
type PasswordServicer = pkgtransport.PasswordServicer
type SealStoreServicer = pkgtransport.SealStoreServicer
type TPMPolicyServicer = pkgtransport.TPMPolicyServicer
type TenantServicer = pkgtransport.TenantServicer
type CredentialManagementServicer = pkgtransport.CredentialManagementServicer
