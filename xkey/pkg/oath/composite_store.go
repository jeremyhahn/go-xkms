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

package oath

import (
	"errors"
	"sort"
	"strings"
	"sync"
)

// CompositeStore errors.
var (
	ErrStoreNotFound = errors.New("oath: store not found for backend")
)

// Compile-time interface check.
var _ Store = (*CompositeStore)(nil)

// CompositeStore aggregates multiple OATH stores and routes operations
// by Credential.BackendID. List operations merge results from all stores.
type CompositeStore struct {
	mu           sync.RWMutex
	stores       map[string]Store // backendID -> store
	defaultStore string           // used for Add when BackendID is empty
}

// NewCompositeStore creates a CompositeStore with the given default store ID.
func NewCompositeStore(defaultStore string) *CompositeStore {
	return &CompositeStore{
		stores:       make(map[string]Store),
		defaultStore: defaultStore,
	}
}

// Register adds a store for a backend ID.
func (c *CompositeStore) Register(backendID string, store Store) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stores[backendID] = store
}

// Unregister removes a store for a backend ID.
func (c *CompositeStore) Unregister(backendID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.stores, backendID)
}

// SetDefault changes the default store used when a credential has no BackendID.
func (c *CompositeStore) SetDefault(backendID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.defaultStore = backendID
}

// Add routes the credential to the store identified by cred.BackendID.
// If BackendID is empty, the default store is used and BackendID is set
// on the credential before delegating.
func (c *CompositeStore) Add(cred *Credential) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	backendID := cred.BackendID
	if backendID == "" {
		backendID = c.defaultStore
		cred.BackendID = backendID
	}

	store, ok := c.stores[backendID]
	if !ok {
		return ErrStoreNotFound
	}

	return store.Add(cred)
}

// Get searches all registered stores for a credential matching the given
// ID or name. The first match is returned with its BackendID populated.
func (c *CompositeStore) Get(idOrName string) (*Credential, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for backendID, store := range c.stores {
		cred, err := store.Get(idOrName)
		if err != nil {
			if errors.Is(err, ErrCredentialNotFound) {
				continue
			}
			return nil, err
		}
		if cred.BackendID == "" {
			cred.BackendID = backendID
		}
		return cred, nil
	}

	return nil, ErrCredentialNotFound
}

// List merges credentials from all registered stores, sorted by name.
// BackendID is populated on each credential based on which store it came from.
func (c *CompositeStore) List() ([]*Credential, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var all []*Credential

	for backendID, store := range c.stores {
		creds, err := store.List()
		if err != nil {
			return nil, err
		}
		for _, cred := range creds {
			if cred.BackendID == "" {
				cred.BackendID = backendID
			}
			all = append(all, cred)
		}
	}

	sort.Slice(all, func(i, j int) bool {
		return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name)
	})

	return all, nil
}

// Update routes the credential to the store identified by cred.BackendID.
// If BackendID is empty, it searches all stores to find the credential first,
// then delegates the update to the store that owns it.
func (c *CompositeStore) Update(cred *Credential) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	backendID := cred.BackendID
	if backendID == "" {
		// Find which store owns this credential.
		found, err := c.findOwner(cred.ID)
		if err != nil {
			return err
		}
		backendID = found
		cred.BackendID = backendID
	}

	store, ok := c.stores[backendID]
	if !ok {
		return ErrStoreNotFound
	}

	return store.Update(cred)
}

// Delete searches all registered stores and deletes the first credential
// matching the given ID or name. Returns ErrCredentialNotFound if no
// store contains the credential.
func (c *CompositeStore) Delete(idOrName string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, store := range c.stores {
		err := store.Delete(idOrName)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrCredentialNotFound) {
			return err
		}
	}

	return ErrCredentialNotFound
}

// Close closes all registered stores. All errors are collected; the first
// error encountered is returned.
func (c *CompositeStore) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	for _, store := range c.stores {
		if err := store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// findOwner searches all stores for a credential with the given ID and returns
// the backendID that owns it. Must be called with at least a read lock held.
func (c *CompositeStore) findOwner(idOrName string) (string, error) {
	for backendID, store := range c.stores {
		_, err := store.Get(idOrName)
		if err == nil {
			return backendID, nil
		}
		if !errors.Is(err, ErrCredentialNotFound) {
			return "", err
		}
	}
	return "", ErrCredentialNotFound
}
