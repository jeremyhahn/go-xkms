// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build vault

package vault

import (
	"context"

	vault "github.com/hashicorp/vault/api"
)

// VaultClient is an interface for Vault operations to enable testing with mocks.
type VaultClient interface {
	// Logical returns the logical secrets client
	Logical() *vault.Logical

	// SetToken sets the authentication token
	SetToken(token string)

	// Token returns the current authentication token
	Token() string

	// NewRequest creates a new Vault API request
	NewRequest(method, requestPath string) *vault.Request

	// RawRequestWithContext performs a raw request to Vault
	RawRequestWithContext(ctx context.Context, r *vault.Request) (*vault.Response, error)

	// Address returns the Vault server address
	Address() string
}

// defaultVaultClient wraps the standard Vault client to implement VaultClient interface.
type defaultVaultClient struct {
	client *vault.Client
}

// newDefaultVaultClient creates a new default Vault client.
func newDefaultVaultClient(client *vault.Client) VaultClient {
	return &defaultVaultClient{client: client}
}

func (c *defaultVaultClient) Logical() *vault.Logical {
	return c.client.Logical()
}

func (c *defaultVaultClient) SetToken(token string) {
	c.client.SetToken(token)
}

func (c *defaultVaultClient) Token() string {
	return c.client.Token()
}

func (c *defaultVaultClient) NewRequest(method, requestPath string) *vault.Request {
	return c.client.NewRequest(method, requestPath)
}

func (c *defaultVaultClient) RawRequestWithContext(ctx context.Context, r *vault.Request) (*vault.Response, error) {
	return c.client.RawRequestWithContext(ctx, r)
}

func (c *defaultVaultClient) Address() string {
	return c.client.Address()
}
