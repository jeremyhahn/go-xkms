// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Compile-time interface check.
var _ PolicyStore = (*BackendPolicyStore)(nil)

// StoreError reports a failure of the storage backend underneath a
// BackendPolicyStore, naming the operation and the policy it was for.
type StoreError struct {
	// Op is the store operation that failed ("save", "load", "delete",
	// "list").
	Op string

	// Name is the policy the operation addressed; empty for "list".
	Name string

	// Err is the underlying storage or decoding error.
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	if e.Name == "" {
		return "policy: store " + e.Op + " failed: " + e.Err.Error()
	}
	return "policy: store " + e.Op + " of \"" + e.Name + "\" failed: " + e.Err.Error()
}

// Unwrap exposes the underlying error for errors.Is/errors.As.
func (e *StoreError) Unwrap() error { return e.Err }

// BackendPolicyStore is a durable PolicyStore over a storage.Backend. Each
// policy definition is one JSON record keyed by its name, so the policies
// inherit the backend's durability, replication and at-rest protection —
// the same seam every other xkms store persists through.
type BackendPolicyStore struct {
	backend storage.Backend
}

// NewBackendPolicyStore returns a PolicyStore persisting into backend. The
// caller owns backend and scopes it (typically a prefixed view); the store
// never closes it.
func NewBackendPolicyStore(backend storage.Backend) (*BackendPolicyStore, error) {
	if backend == nil {
		return nil, ErrNilStorageBackend
	}
	return &BackendPolicyStore{backend: backend}, nil
}

// SavePolicy persists def under name, overwriting any existing definition.
func (s *BackendPolicyStore) SavePolicy(name string, def *PolicyDefinition) error {
	if strings.TrimSpace(name) == "" {
		return ErrInvalidName
	}
	if def == nil {
		return ErrNilPolicyDefinition
	}
	data, err := json.Marshal(def)
	if err != nil {
		return &StoreError{Op: "save", Name: name, Err: err}
	}
	if err := s.backend.Put(context.Background(), name, data); err != nil {
		return &StoreError{Op: "save", Name: name, Err: err}
	}
	return nil
}

// LoadPolicy returns the definition stored under name, or ErrPolicyNotFound.
func (s *BackendPolicyStore) LoadPolicy(name string) (*PolicyDefinition, error) {
	data, err := s.backend.Get(context.Background(), name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrPolicyNotFound
		}
		return nil, &StoreError{Op: "load", Name: name, Err: err}
	}
	def := &PolicyDefinition{}
	if err := json.Unmarshal(data, def); err != nil {
		return nil, &StoreError{Op: "load", Name: name, Err: err}
	}
	return def, nil
}

// DeletePolicy removes the definition stored under name, or returns
// ErrPolicyNotFound when there is none.
func (s *BackendPolicyStore) DeletePolicy(name string) error {
	ctx := context.Background()
	exists, err := s.backend.Exists(ctx, name)
	if err != nil {
		return &StoreError{Op: "delete", Name: name, Err: err}
	}
	if !exists {
		return ErrPolicyNotFound
	}
	if err := s.backend.Delete(ctx, name); err != nil {
		return &StoreError{Op: "delete", Name: name, Err: err}
	}
	return nil
}

// ListPolicies returns every stored definition.
func (s *BackendPolicyStore) ListPolicies() ([]*PolicyDefinition, error) {
	var defs []*PolicyDefinition
	err := s.backend.Scan(context.Background(), "", func(key string, value []byte) error {
		def := &PolicyDefinition{}
		if err := json.Unmarshal(value, def); err != nil {
			return &StoreError{Op: "list", Name: key, Err: err}
		}
		defs = append(defs, def)
		return nil
	})
	if err != nil {
		var storeErr *StoreError
		if errors.As(err, &storeErr) {
			return nil, err
		}
		return nil, &StoreError{Op: "list", Err: err}
	}
	if defs == nil {
		defs = []*PolicyDefinition{}
	}
	return defs, nil
}
