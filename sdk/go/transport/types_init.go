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

// Init ceremony types.
type InitStatusResponse = pkgtransport.InitStatusResponse
type ClaimCertBeginRequest = pkgtransport.ClaimCertBeginRequest
type ClaimCertBeginResponse = pkgtransport.ClaimCertBeginResponse
type ClaimCertCompleteRequest = pkgtransport.ClaimCertCompleteRequest
type ClaimCertCompleteResponse = pkgtransport.ClaimCertCompleteResponse
type ClaimShareRequest = pkgtransport.ClaimShareRequest
type ClaimShareResponse = pkgtransport.ClaimShareResponse
type SignCSRInitRequest = pkgtransport.SignCSRInitRequest
type SignCSRInitResponse = pkgtransport.SignCSRInitResponse

// Credential management types.
type CredentialSubmitRequest = pkgtransport.CredentialSubmitRequest
type CredentialSubmitResponse = pkgtransport.CredentialSubmitResponse
type CredentialStrategyResponse = pkgtransport.CredentialStrategyResponse
