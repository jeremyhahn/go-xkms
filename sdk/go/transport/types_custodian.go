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

// Custodian group types.
type CustodianGroupInfo = pkgtransport.CustodianGroupInfo
type CustodianMemberInfo = pkgtransport.CustodianMemberInfo
type CreateCustodianGroupRequest = pkgtransport.CreateCustodianGroupRequest
type CreateCustodianGroupResponse = pkgtransport.CreateCustodianGroupResponse
type GetCustodianGroupResponse = pkgtransport.GetCustodianGroupResponse
type ListCustodianGroupsResponse = pkgtransport.ListCustodianGroupsResponse
type AddCustodianMemberRequest = pkgtransport.AddCustodianMemberRequest
type AddCustodianMemberResponse = pkgtransport.AddCustodianMemberResponse
type RemoveCustodianMemberRequest = pkgtransport.RemoveCustodianMemberRequest
type DistributeSharesRequest = pkgtransport.DistributeSharesRequest
type DistributeSharesResponse = pkgtransport.DistributeSharesResponse

// Share types.
type SubmitShareRequest = pkgtransport.SubmitShareRequest
type SubmitShareResponse = pkgtransport.SubmitShareResponse
type ShareInfo = pkgtransport.ShareInfo
type ListSharesResponse = pkgtransport.ListSharesResponse
type ShareCollectionStatus = pkgtransport.ShareCollectionStatus

// Tenant types.
type TenantInfo = pkgtransport.TenantInfo
type CreateTenantRequest = pkgtransport.CreateTenantRequest
type CreateTenantResponse = pkgtransport.CreateTenantResponse
type GetTenantResponse = pkgtransport.GetTenantResponse
type ListTenantsResponse = pkgtransport.ListTenantsResponse
type TenantBarrierInitRequest = pkgtransport.TenantBarrierInitRequest
type TenantBarrierUnsealRequest = pkgtransport.TenantBarrierUnsealRequest
