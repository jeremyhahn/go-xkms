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

package admin

import (
	"sync"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// Client provides admin operations for the Trusted CA server.
type Client interface {
	// Tenant returns the tenant management sub-client.
	Tenant() TenantClient

	// TenantCA returns the tenant CA hierarchy management sub-client.
	TenantCA() TenantCAClient

	// EAB returns the EAB management sub-client.
	EAB() EABClient

	// Role returns the role management sub-client.
	Role() RoleClient

	// User returns the user management sub-client.
	User() UserClient

	// Certificate returns the admin certificate management sub-client.
	Certificate() CertificateClient

	// Account returns the admin account management sub-client.
	Account() AdminAccountClient

	// Order returns the admin order management sub-client.
	Order() OrderClient

	// Status returns the status sub-client.
	Status() StatusClient
}

type adminClient struct {
	transport transport.Transport

	mu                sync.RWMutex
	tenantClient      TenantClient
	tenantCAClient    TenantCAClient
	eabClient         EABClient
	roleClient        RoleClient
	userClient        UserClient
	certificateClient CertificateClient
	accountClient     AdminAccountClient
	orderClient       OrderClient
	statusClient      StatusClient
}

// NewClient creates a new admin client with the given transport.
func NewClient(t transport.Transport) Client {
	return &adminClient{transport: t}
}

func (c *adminClient) Tenant() TenantClient {
	c.mu.RLock()
	if c.tenantClient != nil {
		c.mu.RUnlock()
		return c.tenantClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tenantClient == nil {
		c.tenantClient = newTenantClient(c.transport)
	}
	return c.tenantClient
}

func (c *adminClient) TenantCA() TenantCAClient {
	c.mu.RLock()
	if c.tenantCAClient != nil {
		c.mu.RUnlock()
		return c.tenantCAClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tenantCAClient == nil {
		c.tenantCAClient = newTenantCAClient(c.transport)
	}
	return c.tenantCAClient
}

func (c *adminClient) EAB() EABClient {
	c.mu.RLock()
	if c.eabClient != nil {
		c.mu.RUnlock()
		return c.eabClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.eabClient == nil {
		c.eabClient = newEABClient(c.transport)
	}
	return c.eabClient
}

func (c *adminClient) Role() RoleClient {
	c.mu.RLock()
	if c.roleClient != nil {
		c.mu.RUnlock()
		return c.roleClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.roleClient == nil {
		c.roleClient = newRoleClient(c.transport)
	}
	return c.roleClient
}

func (c *adminClient) User() UserClient {
	c.mu.RLock()
	if c.userClient != nil {
		c.mu.RUnlock()
		return c.userClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.userClient == nil {
		c.userClient = newUserClient(c.transport)
	}
	return c.userClient
}

func (c *adminClient) Certificate() CertificateClient {
	c.mu.RLock()
	if c.certificateClient != nil {
		c.mu.RUnlock()
		return c.certificateClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.certificateClient == nil {
		c.certificateClient = newCertificateClient(c.transport)
	}
	return c.certificateClient
}

func (c *adminClient) Account() AdminAccountClient {
	c.mu.RLock()
	if c.accountClient != nil {
		c.mu.RUnlock()
		return c.accountClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accountClient == nil {
		c.accountClient = newAdminAccountClient(c.transport)
	}
	return c.accountClient
}

func (c *adminClient) Order() OrderClient {
	c.mu.RLock()
	if c.orderClient != nil {
		c.mu.RUnlock()
		return c.orderClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.orderClient == nil {
		c.orderClient = newOrderClient(c.transport)
	}
	return c.orderClient
}

func (c *adminClient) Status() StatusClient {
	c.mu.RLock()
	if c.statusClient != nil {
		c.mu.RUnlock()
		return c.statusClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.statusClient == nil {
		c.statusClient = newStatusClient(c.transport)
	}
	return c.statusClient
}
