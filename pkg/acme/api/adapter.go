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

// Package api provides multi-protocol API adapters for go-trusted-ca services.
//
// Supported protocols:
//   - REST (HTTP/HTTPS) - Port 8443
//   - gRPC (TCP) - Port 9443
//   - gRPC (Unix) - /run/trusted-ca-grpc.sock
//   - QUIC (UDP) - Port 9444
//   - MCP (stdio/HTTP) - Port 9445
//
// All services MUST be exposed via ALL protocols for maximum interoperability.
package api

import (
	"context"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
)

// Protocol represents a communication protocol.
type Protocol string

const (
	// ProtocolREST is the REST/HTTP protocol.
	ProtocolREST Protocol = "rest"
	// ProtocolGRPC is the gRPC protocol.
	ProtocolGRPC Protocol = "grpc"
	// ProtocolQUIC is the QUIC protocol.
	ProtocolQUIC Protocol = "quic"
	// ProtocolMCP is the MCP (Model Context Protocol) protocol.
	ProtocolMCP Protocol = "mcp"
	// ProtocolUnix is the Unix domain socket protocol (via gRPC-over-UDS).
	ProtocolUnix Protocol = "unix"
)

// AllProtocols returns all supported protocols.
func AllProtocols() []Protocol {
	return []Protocol{ProtocolREST, ProtocolGRPC, ProtocolQUIC, ProtocolMCP, ProtocolUnix}
}

// TenantAdapter provides a protocol-agnostic interface for tenant operations.
// All protocol implementations (REST, gRPC, QUIC, MCP, Unix) must implement this interface.
type TenantAdapter interface {
	// CreateTenant creates a new tenant.
	CreateTenant(ctx context.Context, req *admin.CreateTenantRequest) (*admin.TenantInfo, error)
	// GetTenant retrieves a tenant by ID.
	GetTenant(ctx context.Context, tenantID string) (*admin.TenantInfo, error)
	// UpdateTenant updates an existing tenant.
	UpdateTenant(ctx context.Context, tenantID string, req *admin.UpdateTenantRequest) (*admin.TenantInfo, error)
	// UpdateTenantStatus updates a tenant's status (enable/disable).
	UpdateTenantStatus(ctx context.Context, tenantID string, status string) error
	// DeleteTenant deletes a tenant.
	DeleteTenant(ctx context.Context, tenantID string) error
	// ListTenants lists all tenants.
	ListTenants(ctx context.Context, req *admin.ListTenantsRequest) ([]*admin.TenantInfo, *admin.Pagination, error)
}

// TenantCAAdapter provides a protocol-agnostic interface for tenant CA hierarchy operations.
type TenantCAAdapter interface {
	// CreateTenantRootCA creates a root CA for a tenant.
	CreateTenantRootCA(ctx context.Context, tenantID string, req *admin.CreateTenantRootCARequest) (*admin.TenantRootCAInfo, error)
	// GetTenantCAStatus retrieves the CA status for a tenant.
	GetTenantCAStatus(ctx context.Context, tenantID string) (*admin.TenantCAStatusInfo, error)
	// CreateTenantIntermediateCA creates an intermediate CA for a tenant.
	CreateTenantIntermediateCA(ctx context.Context, tenantID string, req *admin.CreateTenantIntermediateCARequest) (*admin.TenantIntCAInfo, error)
	// ListTenantIntermediateCAs lists all intermediate CAs for a tenant.
	ListTenantIntermediateCAs(ctx context.Context, tenantID string) ([]*admin.TenantIntCAInfo, error)
	// GetTenantIntermediateCA retrieves a specific intermediate CA.
	GetTenantIntermediateCA(ctx context.Context, tenantID string, caID string) (*admin.TenantIntCAInfo, error)
	// UpdateTenantIntermediateCAStatus updates an intermediate CA's status.
	UpdateTenantIntermediateCAStatus(ctx context.Context, tenantID string, caID string, status string) error
}

// OrderAdapter provides a protocol-agnostic interface for order operations.
type OrderAdapter interface {
	// ListOrders lists orders with optional filtering.
	ListOrders(ctx context.Context, req *admin.ListOrdersRequest) ([]*admin.OrderInfo, *admin.Pagination, error)
	// GetOrder retrieves an order by ID.
	GetOrder(ctx context.Context, orderID uint64, accountID uint64) (*admin.OrderInfo, error)
}

// EABAdapter provides a protocol-agnostic interface for EAB operations.
type EABAdapter interface {
	// CreateEAB creates a new External Account Binding.
	CreateEAB(ctx context.Context, tenantID string, req *admin.CreateEABRequest) (*admin.CreateEABResponse, error)
	// GetEAB retrieves an EAB by ID.
	GetEAB(ctx context.Context, tenantID, kid string) (*admin.EABInfo, error)
	// DeleteEAB deletes an EAB.
	DeleteEAB(ctx context.Context, tenantID, kid string) error
	// ListEABs lists all EABs for a tenant.
	ListEABs(ctx context.Context, tenantID string, req *admin.ListEABRequest) ([]*admin.EABInfo, *admin.Pagination, error)
}

// RoleAdapter provides a protocol-agnostic interface for tenant role operations.
type RoleAdapter interface {
	// CreateTenantRole creates a new role within a tenant.
	CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error)
	// GetTenantRole retrieves a role by ID.
	GetTenantRole(ctx context.Context, tenantID, roleID string) (*db.Role, error)
	// UpdateTenantRole updates an existing role.
	UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error)
	// DeleteTenantRole deletes a role.
	DeleteTenantRole(ctx context.Context, tenantID, roleID string) error
	// ListTenantRoles lists all roles for a tenant.
	ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error)
}

// UserAdapter provides a protocol-agnostic interface for tenant user operations.
type UserAdapter interface {
	// CreateTenantUser creates a new user within a tenant.
	CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error)
	// GetTenantUser retrieves a user by ID.
	GetTenantUser(ctx context.Context, tenantID, userID string) (*db.User, error)
	// UpdateTenantUser updates an existing user.
	UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error)
	// DeleteTenantUser deletes a user.
	DeleteTenantUser(ctx context.Context, tenantID, userID string) error
	// ListTenantUsers lists all users for a tenant.
	ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error)
}

// CertificateAdapter provides a protocol-agnostic interface for certificate operations.
type CertificateAdapter interface {
	// ListCertificates lists certificates with optional filtering.
	ListCertificates(ctx context.Context, req *admin.ListCertificatesRequest) ([]*admin.CertificateInfo, *admin.Pagination, error)
	// GetCertificate retrieves a certificate by serial number.
	GetCertificate(ctx context.Context, serial string) (*admin.CertificateInfo, error)
	// RevokeCertificate revokes a certificate.
	RevokeCertificate(ctx context.Context, serial, reason string) error
}

// AccountAdapter provides a protocol-agnostic interface for ACME account operations.
type AccountAdapter interface {
	// ListAccounts lists ACME accounts with optional filtering.
	ListAccounts(ctx context.Context, req *admin.ListAccountsRequest) ([]*admin.AccountInfo, *admin.Pagination, error)
	// GetAccount retrieves an ACME account by ID.
	GetAccount(ctx context.Context, accountID uint64) (*admin.AccountInfo, error)
	// DisableAccount disables an ACME account.
	DisableAccount(ctx context.Context, accountID uint64) error
}

// StatusAdapter provides a protocol-agnostic interface for status operations.
type StatusAdapter interface {
	// GetStatus returns the CA status.
	GetStatus(ctx context.Context) (*admin.CAStatus, error)
	// GetStats returns CA statistics.
	GetStats(ctx context.Context) (*admin.CAStats, error)
}

// AdminAdapter combines all admin API adapters.
type AdminAdapter interface {
	TenantAdapter
	TenantCAAdapter
	EABAdapter
	RoleAdapter
	UserAdapter
	CertificateAdapter
	AccountAdapter
	OrderAdapter
	StatusAdapter

	// Protocol returns the protocol this adapter uses.
	Protocol() Protocol
	// Close closes any connections held by the adapter.
	Close() error
}

// ACMEAdapter provides a protocol-agnostic interface for ACME operations.
// Note: ACME protocol is REST-only per RFC 8555, but we expose admin operations
// via all protocols.
type ACMEAdapter interface {
	// GetDirectory returns the ACME directory.
	GetDirectory(ctx context.Context) (map[string]interface{}, error)
	// GetNonce returns a fresh nonce.
	GetNonce(ctx context.Context) (string, error)
	// CreateAccount creates a new ACME account.
	CreateAccount(ctx context.Context, jwsBody []byte) (map[string]interface{}, string, error)
	// CreateOrder creates a new certificate order.
	CreateOrder(ctx context.Context, accountURL string, jwsBody []byte) (map[string]interface{}, string, error)

	// Protocol returns the protocol this adapter uses.
	Protocol() Protocol
	// Close closes any connections held by the adapter.
	Close() error
}

// AdapterFactory creates protocol adapters.
type AdapterFactory interface {
	// NewAdminAdapter creates a new admin adapter for the specified protocol.
	NewAdminAdapter(protocol Protocol, config *AdapterConfig) (AdminAdapter, error)
	// NewACMEAdapter creates a new ACME adapter for the specified protocol.
	NewACMEAdapter(protocol Protocol, config *AdapterConfig) (ACMEAdapter, error)
}

// AdapterConfig contains configuration for protocol adapters.
type AdapterConfig struct {
	// BaseURL is the base URL for REST/HTTP connections.
	BaseURL string
	// GRPCAddr is the address for gRPC TCP connections.
	GRPCAddr string
	// GRPCUnixPath is the path for gRPC Unix socket connections (gRPC-over-UDS).
	GRPCUnixPath string
	// QUICAddr is the address for QUIC connections.
	QUICAddr string
	// MCPAddr is the address for MCP connections.
	MCPAddr string
	// AuthToken is the authentication token (if required).
	AuthToken string
	// TLSConfig contains TLS configuration.
	TLSConfig *TLSConfig
}

// TLSConfig contains TLS configuration for secure connections.
type TLSConfig struct {
	// CertFile is the path to the client certificate.
	CertFile string
	// KeyFile is the path to the client key.
	KeyFile string
	// CAFile is the path to the CA certificate.
	CAFile string
	// InsecureSkipVerify disables server certificate verification.
	//
	// Deprecated: Use a properly issued certificate or pin the server's SPKI via
	// pkg/crypto/spki. This field is retained for integration testing with
	// self-signed certificates; production code paths must leave it false.
	InsecureSkipVerify bool
}
