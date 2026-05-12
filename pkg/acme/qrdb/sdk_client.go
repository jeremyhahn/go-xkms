// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package qrdb

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// Type aliases for convenience. These allow consumers of this package
// to reference QRDB SDK types without importing the SDK directly.
type (
	// SDKClient is the top-level QRDB SDK client.
	SDKClient = qrdbsdk.Client

	// KVClient provides data-plane key-value operations.
	KVClient = qrdbtransport.KVClient

	// AdminClient provides control-plane cluster management.
	AdminClient = qrdbtransport.AdminClient

	// WatchClient provides event streaming for key changes.
	WatchClient = qrdbtransport.WatchClient

	// LeaseClient provides distributed lease management.
	LeaseClient = qrdbtransport.LeaseClient

	// BatchClient provides atomic batch operation execution.
	BatchClient = qrdbtransport.BatchClient

	// TransactionClient provides atomic compare-and-swap transactions.
	TransactionClient = qrdbtransport.TransactionClient

	// IndexClient provides secondary index management and querying.
	IndexClient = qrdbtransport.IndexClient

	// UserClient provides user management operations.
	UserClient = qrdbtransport.UserClient

	// RoleClient provides role-based access control operations.
	RoleClient = qrdbtransport.RoleClient

	// CertClient provides certificate management operations.
	CertClient = qrdbtransport.CertClient

	// BarrierClient provides cryptographic barrier operations.
	BarrierClient = qrdbtransport.BarrierClient

	// CeremonyClient provides M-of-N initialization ceremony operations.
	CeremonyClient = qrdbtransport.CeremonyClient

	// CredentialClient provides named credential management.
	CredentialClient = qrdbtransport.CredentialClient

	// User represents a QRDB user entity.
	User = qrdbtransport.User

	// Role represents a QRDB role entity.
	Role = qrdbtransport.Role

	// CreateUserRequest is the request type for creating users.
	CreateUserRequest = qrdbtransport.CreateUserRequest

	// UpdateUserRequest is the request type for updating users.
	UpdateUserRequest = qrdbtransport.UpdateUserRequest

	// ListUsersRequest is the request for listing users.
	ListUsersRequest = qrdbtransport.ListUsersRequest

	// ListUsersResponse is the response for listing users.
	ListUsersResponse = qrdbtransport.ListUsersResponse

	// CreateRoleRequest is the request type for creating roles.
	CreateRoleRequest = qrdbtransport.CreateRoleRequest

	// UpdateRoleRequest is the request type for updating roles.
	UpdateRoleRequest = qrdbtransport.UpdateRoleRequest

	// ListRolesRequest is the request for listing roles.
	ListRolesRequest = qrdbtransport.ListRolesRequest

	// ListRolesResponse is the response for listing roles.
	ListRolesResponse = qrdbtransport.ListRolesResponse

	// ListPermissionsResponse is the response for listing permissions.
	ListPermissionsResponse = qrdbtransport.ListPermissionsResponse

	// PermissionCategory groups related permissions for UI rendering.
	PermissionCategory = qrdbtransport.PermissionCategory

	// BarrierStatusResponse is the barrier status response.
	BarrierStatusResponse = qrdbtransport.BarrierStatusResponse

	// BarrierInitializeRequest is the barrier init request.
	BarrierInitializeRequest = qrdbtransport.BarrierInitializeRequest

	// BarrierUnsealRequest is the barrier unseal request.
	BarrierUnsealRequest = qrdbtransport.BarrierUnsealRequest

	// BarrierInitializeShamirRequest is the Shamir init request.
	BarrierInitializeShamirRequest = qrdbtransport.BarrierInitializeShamirRequest

	// BarrierInitializeShamirResponse is the Shamir init response.
	BarrierInitializeShamirResponse = qrdbtransport.BarrierInitializeShamirResponse

	// CeremonyInitializeRequest is the ceremony init request.
	CeremonyInitializeRequest = qrdbtransport.CeremonyInitializeRequest

	// CeremonyInitializeResponse is the ceremony init response.
	CeremonyInitializeResponse = qrdbtransport.CeremonyInitializeResponse

	// CeremonyStatusResponse is the ceremony status response.
	CeremonyStatusResponse = qrdbtransport.CeremonyStatusResponse
)
