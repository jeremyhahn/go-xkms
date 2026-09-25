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

//go:build vault

package vault

import (
	vault "github.com/hashicorp/vault/api"
)

// VaultClient is an interface for Vault operations to enable testing with mocks.
// It lists exactly the operations Backend calls; Token, NewRequest,
// RawRequestWithContext and Address were removed (go-xkms#705) because no
// Backend method ever called them -- an unused interface method can only be
// covered by a test that calls it directly with no Backend behavior to
// assert, which is coverage padding, not a real test.
type VaultClient interface {
	// Logical returns the logical secrets client
	Logical() *vault.Logical

	// SetToken sets the authentication token
	SetToken(token string)
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
