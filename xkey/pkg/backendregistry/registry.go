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

package backendregistry

import (
	"sort"
	"sync"
	"sync/atomic"
)

// EventType represents the kind of event emitted by the registry.
type EventType string

const (
	// EventRegistered is emitted when a backend is registered.
	EventRegistered EventType = "registered"

	// EventUnregistered is emitted when a backend is unregistered.
	EventUnregistered EventType = "unregistered"

	// EventStateChanged is emitted when a backend's state changes.
	EventStateChanged EventType = "state_changed"

	// EventDisplayNameChanged is emitted when a backend's display name changes.
	EventDisplayNameChanged EventType = "display_name_changed"
)

// Event represents a registry event sent to subscribers.
type Event struct {
	// Type is the kind of event.
	Type EventType

	// BackendID is the ID of the backend involved.
	BackendID string

	// OldState is the previous state (only meaningful for EventStateChanged).
	OldState BackendState

	// NewState is the new state (only meaningful for EventStateChanged).
	NewState BackendState
}

// EventHandler is a callback function invoked when a registry event occurs.
type EventHandler func(Event)

// Registry defines the interface for managing registered cryptographic backends.
type Registry interface {
	// Register adds a backend to the registry.
	Register(backend *RegisteredBackend) error

	// Unregister removes a backend from the registry by its ID.
	Unregister(id string) error

	// Get retrieves a backend by its ID.
	Get(id string) (*RegisteredBackend, error)

	// List returns all registered backends, sorted by ID.
	List() []*RegisteredBackend

	// ListByCapability returns all backends that support the given capability.
	ListByCapability(cap Capability) []*RegisteredBackend

	// ListByCategory returns all backends matching the given category.
	ListByCategory(cat BackendCategory) []*RegisteredBackend

	// ListByLocation returns all backends matching the given location.
	ListByLocation(loc BackendLocation) []*RegisteredBackend

	// GetDefault returns the default backend for the given capability.
	GetDefault(feature Capability) (*RegisteredBackend, error)

	// SetDefault sets the default backend for the given capability.
	SetDefault(feature Capability, id string) error

	// UpdateDisplayName changes the display name of a registered backend.
	UpdateDisplayName(id string, displayName string) error

	// Subscribe registers an event handler and returns a subscription ID.
	Subscribe(handler EventHandler) int

	// Unsubscribe removes an event handler by its subscription ID.
	Unsubscribe(id int)

	// Close shuts down the registry, rejecting further operations.
	Close() error
}

// MemoryRegistry is an in-memory, concurrent-safe implementation of Registry.
type MemoryRegistry struct {
	backends    sync.Map
	defaults    sync.Map
	closed      atomic.Bool
	subscribers map[int]EventHandler
	subMu       sync.RWMutex
	nextSubID   atomic.Int32
}

// NewMemoryRegistry creates a new in-memory registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{
		subscribers: make(map[int]EventHandler),
	}
}

// Register adds a backend to the registry. It validates the backend fields and
// returns an error if the backend is nil, has an empty ID, an invalid category,
// an invalid location, or is already registered.
func (r *MemoryRegistry) Register(backend *RegisteredBackend) error {
	if r.closed.Load() {
		return ErrRegistryClosed
	}
	if backend == nil {
		return ErrNilBackend
	}
	if backend.ID == "" {
		return ErrEmptyBackendID
	}
	if _, ok := ValidCategories[backend.Category]; !ok {
		return ErrInvalidCategory
	}
	if _, ok := ValidLocations[backend.Location]; !ok {
		return ErrInvalidLocation
	}

	if _, loaded := r.backends.LoadOrStore(backend.ID, backend); loaded {
		return ErrBackendAlreadyExists
	}

	r.emit(Event{
		Type:      EventRegistered,
		BackendID: backend.ID,
		NewState:  backend.State(),
	})

	return nil
}

// Unregister removes a backend from the registry by its ID.
func (r *MemoryRegistry) Unregister(id string) error {
	if r.closed.Load() {
		return ErrRegistryClosed
	}

	val, loaded := r.backends.LoadAndDelete(id)
	if !loaded {
		return ErrBackendNotFound
	}

	backend := val.(*RegisteredBackend)
	r.emit(Event{
		Type:      EventUnregistered,
		BackendID: id,
		OldState:  backend.State(),
	})

	return nil
}

// Get retrieves a backend by its ID.
func (r *MemoryRegistry) Get(id string) (*RegisteredBackend, error) {
	if r.closed.Load() {
		return nil, ErrRegistryClosed
	}

	val, ok := r.backends.Load(id)
	if !ok {
		return nil, ErrBackendNotFound
	}
	return val.(*RegisteredBackend), nil
}

// List returns all registered backends, sorted by ID for deterministic output.
func (r *MemoryRegistry) List() []*RegisteredBackend {
	var result []*RegisteredBackend
	r.backends.Range(func(_, value any) bool {
		result = append(result, value.(*RegisteredBackend))
		return true
	})
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	// Return empty slice instead of nil for consistent API behavior.
	if result == nil {
		result = make([]*RegisteredBackend, 0)
	}
	return result
}

// ListByCapability returns all backends that support the given capability,
// sorted by ID.
func (r *MemoryRegistry) ListByCapability(cap Capability) []*RegisteredBackend {
	all := r.List()
	result := make([]*RegisteredBackend, 0)
	for _, b := range all {
		if b.HasCapability(cap) {
			result = append(result, b)
		}
	}
	return result
}

// ListByCategory returns all backends matching the given category, sorted by ID.
func (r *MemoryRegistry) ListByCategory(cat BackendCategory) []*RegisteredBackend {
	all := r.List()
	result := make([]*RegisteredBackend, 0)
	for _, b := range all {
		if b.Category == cat {
			result = append(result, b)
		}
	}
	return result
}

// ListByLocation returns all backends matching the given location, sorted by ID.
func (r *MemoryRegistry) ListByLocation(loc BackendLocation) []*RegisteredBackend {
	all := r.List()
	result := make([]*RegisteredBackend, 0)
	for _, b := range all {
		if b.Location == loc {
			result = append(result, b)
		}
	}
	return result
}

// UpdateDisplayName changes the display name of a registered backend. The
// new name must be non-empty. An event is emitted to notify subscribers.
func (r *MemoryRegistry) UpdateDisplayName(id string, displayName string) error {
	if r.closed.Load() {
		return ErrRegistryClosed
	}
	if displayName == "" {
		return ErrEmptyDisplayName
	}

	val, ok := r.backends.Load(id)
	if !ok {
		return ErrBackendNotFound
	}

	backend := val.(*RegisteredBackend)
	backend.DisplayName = displayName

	r.emit(Event{
		Type:      EventDisplayNameChanged,
		BackendID: id,
	})

	return nil
}

// GetDefault returns the default backend for the given capability.
func (r *MemoryRegistry) GetDefault(feature Capability) (*RegisteredBackend, error) {
	if r.closed.Load() {
		return nil, ErrRegistryClosed
	}

	val, ok := r.defaults.Load(feature)
	if !ok {
		return nil, ErrNoDefaultSet
	}

	backendID := val.(string)
	backendVal, ok := r.backends.Load(backendID)
	if !ok {
		return nil, ErrDefaultBackendNotFound
	}

	return backendVal.(*RegisteredBackend), nil
}

// SetDefault sets the default backend for the given capability. The backend
// must already be registered.
func (r *MemoryRegistry) SetDefault(feature Capability, id string) error {
	if r.closed.Load() {
		return ErrRegistryClosed
	}

	if _, ok := r.backends.Load(id); !ok {
		return ErrBackendNotFound
	}

	r.defaults.Store(feature, id)
	return nil
}

// Subscribe registers an event handler and returns a subscription ID that can
// be used to unsubscribe later.
func (r *MemoryRegistry) Subscribe(handler EventHandler) int {
	id := int(r.nextSubID.Add(1))
	r.subMu.Lock()
	r.subscribers[id] = handler
	r.subMu.Unlock()
	return id
}

// Unsubscribe removes an event handler by its subscription ID.
func (r *MemoryRegistry) Unsubscribe(id int) {
	r.subMu.Lock()
	delete(r.subscribers, id)
	r.subMu.Unlock()
}

// Close shuts down the registry. After Close is called, all mutation operations
// will return ErrRegistryClosed. Close is idempotent.
func (r *MemoryRegistry) Close() error {
	r.closed.Store(true)
	return nil
}

// emit sends an event to all registered subscribers. Panics in individual
// handlers are recovered so that one misbehaving handler does not prevent
// other handlers from receiving the event.
func (r *MemoryRegistry) emit(event Event) {
	r.subMu.RLock()
	// Copy handlers under read lock to minimize lock hold time.
	handlers := make([]EventHandler, 0, len(r.subscribers))
	for _, h := range r.subscribers {
		handlers = append(handlers, h)
	}
	r.subMu.RUnlock()

	for _, h := range handlers {
		func(handler EventHandler) {
			defer func() {
				_ = recover()
			}()
			handler(event)
		}(h)
	}
}
