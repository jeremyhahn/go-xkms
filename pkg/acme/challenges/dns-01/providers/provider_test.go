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

package providers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// providerTestMock implements the Provider interface for testing.
// Uses a different name to avoid collision with factory_test.go's mockProvider.
type providerTestMock struct {
	presentCalled bool
	cleanupCalled bool
	presentErr    error
	cleanupErr    error
}

func (m *providerTestMock) Present(ctx context.Context, domain, fqdn, value string) error {
	m.presentCalled = true
	return m.presentErr
}

func (m *providerTestMock) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	m.cleanupCalled = true
	return m.cleanupErr
}

func TestRegisterAndGet(t *testing.T) {
	// Clean up registry after test
	defer func() {
		registryMu.Lock()
		delete(registry, "test-provider")
		registryMu.Unlock()
	}()

	// Register a test provider
	factory := func(ctx context.Context, config interface{}) (Provider, error) {
		return &providerTestMock{}, nil
	}
	Register("test-provider", factory)

	// Verify it can be retrieved
	retrieved := Get("test-provider")
	assert.NotNil(t, retrieved)

	// Verify unknown provider returns nil
	unknown := Get("unknown-provider")
	assert.Nil(t, unknown)
}

func TestRegistered(t *testing.T) {
	// Clean up registry after test
	defer func() {
		registryMu.Lock()
		delete(registry, "test-provider-2")
		registryMu.Unlock()
	}()

	// Verify unregistered provider
	assert.False(t, Registered("test-provider-2"))

	// Register provider
	Register("test-provider-2", func(ctx context.Context, config interface{}) (Provider, error) {
		return &providerTestMock{}, nil
	})

	// Verify registered provider
	assert.True(t, Registered("test-provider-2"))
}

func TestList(t *testing.T) {
	// Clean up registry after test
	defer func() {
		registryMu.Lock()
		delete(registry, "list-test-1")
		delete(registry, "list-test-2")
		registryMu.Unlock()
	}()

	// Get initial count
	initialList := List()
	initialCount := len(initialList)

	// Register test providers
	Register("list-test-1", func(ctx context.Context, config interface{}) (Provider, error) {
		return &providerTestMock{}, nil
	})
	Register("list-test-2", func(ctx context.Context, config interface{}) (Provider, error) {
		return &providerTestMock{}, nil
	})

	// Verify count increased
	newList := List()
	assert.Len(t, newList, initialCount+2)

	// Verify our providers are in the list
	found1, found2 := false, false
	for _, name := range newList {
		if name == "list-test-1" {
			found1 = true
		}
		if name == "list-test-2" {
			found2 = true
		}
	}
	assert.True(t, found1, "list-test-1 not found in list")
	assert.True(t, found2, "list-test-2 not found in list")
}
