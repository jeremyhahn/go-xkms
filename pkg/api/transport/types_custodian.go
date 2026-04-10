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

import qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

// --- Custodian group types aliased from go-qrdb ---

// CustodianGroupInfo contains information about a custodian group.
type CustodianGroupInfo = qrdbtransport.CustodianGroupInfo

// CustodianMemberInfo contains information about a custodian group member.
type CustodianMemberInfo = qrdbtransport.CustodianMemberInfo

// CreateCustodianGroupRequest contains parameters for creating a custodian group.
type CreateCustodianGroupRequest = qrdbtransport.CreateCustodianGroupRequest

// CreateCustodianGroupResponse contains the created custodian group.
type CreateCustodianGroupResponse = qrdbtransport.CreateCustodianGroupResponse

// GetCustodianGroupResponse contains a custodian group.
type GetCustodianGroupResponse = qrdbtransport.GetCustodianGroupResponse

// ListCustodianGroupsResponse contains a list of custodian groups.
type ListCustodianGroupsResponse = qrdbtransport.ListCustodianGroupsResponse

// AddCustodianMemberRequest contains parameters for adding a member to a group.
type AddCustodianMemberRequest = qrdbtransport.AddCustodianMemberRequest

// AddCustodianMemberResponse contains the added member.
type AddCustodianMemberResponse = qrdbtransport.AddCustodianMemberResponse

// RemoveCustodianMemberRequest contains parameters for removing a member.
type RemoveCustodianMemberRequest = qrdbtransport.RemoveCustodianMemberRequest

// DistributeSharesRequest contains parameters for distributing shares.
type DistributeSharesRequest = qrdbtransport.DistributeSharesRequest

// DistributeSharesResponse contains the distribution result.
type DistributeSharesResponse = qrdbtransport.DistributeSharesResponse

// --- Share types aliased from go-qrdb ---

// SubmitShareRequest contains parameters for submitting a share.
type SubmitShareRequest = qrdbtransport.SubmitShareRequest

// SubmitShareResponse contains the share submission result.
type SubmitShareResponse = qrdbtransport.SubmitShareResponse

// ShareInfo contains information about a stored share.
type ShareInfo = qrdbtransport.ShareInfo

// ListSharesResponse contains a list of shares.
type ListSharesResponse = qrdbtransport.ListSharesResponse

// ShareCollectionStatus contains the status of share collection for a group.
type ShareCollectionStatus = qrdbtransport.ShareCollectionStatus

// --- Tenant types aliased from go-qrdb ---

// TenantInfo contains information about a tenant.
type TenantInfo = qrdbtransport.TenantInfo

// CreateTenantRequest contains parameters for creating a tenant.
type CreateTenantRequest = qrdbtransport.CreateTenantRequest

// CreateTenantResponse contains the created tenant.
type CreateTenantResponse = qrdbtransport.CreateTenantResponse

// GetTenantResponse contains a tenant.
type GetTenantResponse = qrdbtransport.GetTenantResponse

// ListTenantsResponse contains a list of tenants.
type ListTenantsResponse = qrdbtransport.ListTenantsResponse

// TenantBarrierInitRequest contains parameters for initializing a tenant barrier.
type TenantBarrierInitRequest = qrdbtransport.TenantBarrierInitRequest

// TenantBarrierUnsealRequest contains parameters for unsealing a tenant barrier.
type TenantBarrierUnsealRequest = qrdbtransport.TenantBarrierUnsealRequest
