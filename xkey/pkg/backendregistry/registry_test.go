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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBackend creates a valid RegisteredBackend for testing with sensible defaults.
func newTestBackend(id string, category BackendCategory, location BackendLocation, caps ...Capability) *RegisteredBackend {
	capMap := make(map[Capability]bool, len(caps))
	for _, c := range caps {
		capMap[c] = true
	}
	return &RegisteredBackend{
		ID:           id,
		Category:     category,
		Location:     location,
		DisplayName:  id,
		Capabilities: capMap,
		Metadata:     map[string]string{"test": "true"},
	}
}

func TestNewMemoryRegistry(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NotNil(t, reg)
	require.NotNil(t, reg.subscribers)
}

func TestNewMemoryRegistry_ImplementsInterface(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	var _ Registry = reg
}

// --- Register ---

func TestRegister_Success(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("software-default", CategorySoftware, LocationLocal, CapSigning, CapEncryption)

	err := reg.Register(backend)
	require.NoError(t, err)

	got, err := reg.Get("software-default")
	require.NoError(t, err)
	assert.Equal(t, backend.ID, got.ID)
	assert.Equal(t, backend.Category, got.Category)
	assert.Equal(t, backend.Location, got.Location)
	assert.Equal(t, backend.DisplayName, got.DisplayName)
	assert.True(t, got.HasCapability(CapSigning))
	assert.True(t, got.HasCapability(CapEncryption))
}

func TestRegister_NilBackend(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	err := reg.Register(nil)
	assert.True(t, errors.Is(err, ErrNilBackend))
}

func TestRegister_EmptyID(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := &RegisteredBackend{
		ID:       "",
		Category: CategorySoftware,
		Location: LocationLocal,
	}
	err := reg.Register(backend)
	assert.True(t, errors.Is(err, ErrEmptyBackendID))
}

func TestRegister_InvalidCategory(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := &RegisteredBackend{
		ID:       "bad-category",
		Category: BackendCategory("imaginary"),
		Location: LocationLocal,
	}
	err := reg.Register(backend)
	assert.True(t, errors.Is(err, ErrInvalidCategory))
}

func TestRegister_InvalidLocation(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := &RegisteredBackend{
		ID:       "bad-location",
		Category: CategorySoftware,
		Location: BackendLocation("mars"),
	}
	err := reg.Register(backend)
	assert.True(t, errors.Is(err, ErrInvalidLocation))
}

func TestRegister_Duplicate(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("dup-test", CategorySoftware, LocationLocal)

	err := reg.Register(backend)
	require.NoError(t, err)

	err = reg.Register(backend)
	assert.True(t, errors.Is(err, ErrBackendAlreadyExists))
}

func TestRegister_AfterClose(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Close())

	backend := newTestBackend("closed-reg", CategorySoftware, LocationLocal)
	err := reg.Register(backend)
	assert.True(t, errors.Is(err, ErrRegistryClosed))
}

// --- Unregister ---

func TestUnregister_Success(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("unreg-test", CategoryTPM2, LocationLocal)

	require.NoError(t, reg.Register(backend))
	err := reg.Unregister("unreg-test")
	require.NoError(t, err)

	_, err = reg.Get("unreg-test")
	assert.True(t, errors.Is(err, ErrBackendNotFound))
}

func TestUnregister_NotFound(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	err := reg.Unregister("nonexistent")
	assert.True(t, errors.Is(err, ErrBackendNotFound))
}

func TestUnregister_AfterClose(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("close-unreg", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))
	require.NoError(t, reg.Close())

	err := reg.Unregister("close-unreg")
	assert.True(t, errors.Is(err, ErrRegistryClosed))
}

// --- Get ---

func TestGet_Success(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("get-test", CategoryPKCS11, LocationLocal, CapPIV)

	require.NoError(t, reg.Register(backend))

	got, err := reg.Get("get-test")
	require.NoError(t, err)
	assert.Equal(t, "get-test", got.ID)
	assert.Equal(t, CategoryPKCS11, got.Category)
	assert.True(t, got.HasCapability(CapPIV))
}

func TestGet_NotFound(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	_, err := reg.Get("does-not-exist")
	assert.True(t, errors.Is(err, ErrBackendNotFound))
}

func TestGet_AfterClose(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("close-get", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))
	require.NoError(t, reg.Close())

	_, err := reg.Get("close-get")
	assert.True(t, errors.Is(err, ErrRegistryClosed))
}

// --- List ---

func TestList_Empty(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	result := reg.List()
	require.NotNil(t, result, "List should return empty slice, not nil")
	assert.Empty(t, result)
}

func TestList_Multiple(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("charlie", CategorySoftware, LocationLocal)))
	require.NoError(t, reg.Register(newTestBackend("alpha", CategoryTPM2, LocationLocal)))
	require.NoError(t, reg.Register(newTestBackend("bravo", CategoryPKCS11, LocationRemote)))

	result := reg.List()
	require.Len(t, result, 3)
	assert.Equal(t, "alpha", result[0].ID, "results should be sorted by ID")
	assert.Equal(t, "bravo", result[1].ID)
	assert.Equal(t, "charlie", result[2].ID)
}

func TestList_ReturnsCopy(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("copy-test", CategorySoftware, LocationLocal)))

	list1 := reg.List()
	list2 := reg.List()

	// Modifying one returned slice should not affect another.
	list1[0] = nil
	assert.NotNil(t, list2[0])
}

// --- ListByCapability ---

func TestListByCapability(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("signer", CategorySoftware, LocationLocal, CapSigning)))
	require.NoError(t, reg.Register(newTestBackend("encryptor", CategorySoftware, LocationLocal, CapEncryption)))
	require.NoError(t, reg.Register(newTestBackend("both", CategoryTPM2, LocationLocal, CapSigning, CapEncryption)))

	signers := reg.ListByCapability(CapSigning)
	require.Len(t, signers, 2)
	assert.Equal(t, "both", signers[0].ID)
	assert.Equal(t, "signer", signers[1].ID)

	encryptors := reg.ListByCapability(CapEncryption)
	require.Len(t, encryptors, 2)
	assert.Equal(t, "both", encryptors[0].ID)
	assert.Equal(t, "encryptor", encryptors[1].ID)
}

func TestListByCapability_None(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("no-fido", CategorySoftware, LocationLocal, CapSigning)))

	result := reg.ListByCapability(CapFIDO2)
	require.NotNil(t, result)
	assert.Empty(t, result)
}

func TestListByCapability_EmptyRegistry(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	result := reg.ListByCapability(CapSigning)
	require.NotNil(t, result)
	assert.Empty(t, result)
}

// --- ListByCategory ---

func TestListByCategory(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("sw1", CategorySoftware, LocationLocal)))
	require.NoError(t, reg.Register(newTestBackend("sw2", CategorySoftware, LocationLocal)))
	require.NoError(t, reg.Register(newTestBackend("tpm", CategoryTPM2, LocationLocal)))

	software := reg.ListByCategory(CategorySoftware)
	require.Len(t, software, 2)
	assert.Equal(t, "sw1", software[0].ID)
	assert.Equal(t, "sw2", software[1].ID)

	tpm := reg.ListByCategory(CategoryTPM2)
	require.Len(t, tpm, 1)
	assert.Equal(t, "tpm", tpm[0].ID)
}

func TestListByCategory_None(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("sw", CategorySoftware, LocationLocal)))

	result := reg.ListByCategory(CategoryPhone)
	require.NotNil(t, result)
	assert.Empty(t, result)
}

// --- ListByLocation ---

func TestListByLocation(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("local1", CategorySoftware, LocationLocal)))
	require.NoError(t, reg.Register(newTestBackend("remote1", CategoryXKMS, LocationRemote)))
	require.NoError(t, reg.Register(newTestBackend("local2", CategoryTPM2, LocationLocal)))

	locals := reg.ListByLocation(LocationLocal)
	require.Len(t, locals, 2)
	assert.Equal(t, "local1", locals[0].ID)
	assert.Equal(t, "local2", locals[1].ID)

	remotes := reg.ListByLocation(LocationRemote)
	require.Len(t, remotes, 1)
	assert.Equal(t, "remote1", remotes[0].ID)
}

func TestListByLocation_None(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("local-only", CategorySoftware, LocationLocal)))

	result := reg.ListByLocation(LocationRemote)
	require.NotNil(t, result)
	assert.Empty(t, result)
}

// --- SetDefault / GetDefault ---

func TestSetDefault_Success(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("default-signer", CategorySoftware, LocationLocal, CapSigning)
	require.NoError(t, reg.Register(backend))

	err := reg.SetDefault(CapSigning, "default-signer")
	require.NoError(t, err)

	got, err := reg.GetDefault(CapSigning)
	require.NoError(t, err)
	assert.Equal(t, "default-signer", got.ID)
}

func TestSetDefault_BackendNotFound(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	err := reg.SetDefault(CapSigning, "ghost-backend")
	assert.True(t, errors.Is(err, ErrBackendNotFound))
}

func TestSetDefault_OverwritesPrevious(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	require.NoError(t, reg.Register(newTestBackend("first", CategorySoftware, LocationLocal)))
	require.NoError(t, reg.Register(newTestBackend("second", CategoryTPM2, LocationLocal)))

	require.NoError(t, reg.SetDefault(CapSigning, "first"))
	require.NoError(t, reg.SetDefault(CapSigning, "second"))

	got, err := reg.GetDefault(CapSigning)
	require.NoError(t, err)
	assert.Equal(t, "second", got.ID)
}

func TestSetDefault_AfterClose(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("close-default", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))
	require.NoError(t, reg.Close())

	err := reg.SetDefault(CapSigning, "close-default")
	assert.True(t, errors.Is(err, ErrRegistryClosed))
}

func TestGetDefault_NotSet(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	_, err := reg.GetDefault(CapFIDO2)
	assert.True(t, errors.Is(err, ErrNoDefaultSet))
}

func TestGetDefault_BackendRemoved(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("ephemeral", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))
	require.NoError(t, reg.SetDefault(CapSigning, "ephemeral"))

	// Remove the backend.
	require.NoError(t, reg.Unregister("ephemeral"))

	_, err := reg.GetDefault(CapSigning)
	assert.True(t, errors.Is(err, ErrDefaultBackendNotFound))
}

func TestGetDefault_AfterClose(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("close-getdef", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))
	require.NoError(t, reg.SetDefault(CapSigning, "close-getdef"))
	require.NoError(t, reg.Close())

	_, err := reg.GetDefault(CapSigning)
	assert.True(t, errors.Is(err, ErrRegistryClosed))
}

// --- Subscribe / Unsubscribe / Events ---

func TestSubscribe_ReceivesEvents(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()

	var received []Event
	var mu sync.Mutex
	reg.Subscribe(func(e Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	backend := newTestBackend("event-test", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1)
	assert.Equal(t, EventRegistered, received[0].Type)
	assert.Equal(t, "event-test", received[0].BackendID)
}

func TestSubscribe_UnregisterEvent(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()

	var received []Event
	var mu sync.Mutex
	reg.Subscribe(func(e Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	backend := newTestBackend("unreg-event", CategorySoftware, LocationLocal)
	backend.SetState(StateReady)
	require.NoError(t, reg.Register(backend))
	require.NoError(t, reg.Unregister("unreg-event"))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 2)
	assert.Equal(t, EventRegistered, received[0].Type)
	assert.Equal(t, EventUnregistered, received[1].Type)
	assert.Equal(t, "unreg-event", received[1].BackendID)
	assert.Equal(t, StateReady, received[1].OldState)
}

func TestSubscribe_StateChangeEvent(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("state-change", CategoryTPM2, LocationLocal)
	require.NoError(t, reg.Register(backend))

	var received []Event
	var mu sync.Mutex
	// Subscribe after registration so we only see the state change event.
	reg.Subscribe(func(e Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	// Emit a state change event manually (the registry doesn't auto-detect
	// state changes on the backend; the caller emits these).
	oldState := backend.State()
	backend.SetState(StateReady)

	// Manually emit since SetState on the backend doesn't go through the registry.
	reg.emit(Event{
		Type:      EventStateChanged,
		BackendID: backend.ID,
		OldState:  oldState,
		NewState:  StateReady,
	})

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1)
	assert.Equal(t, EventStateChanged, received[0].Type)
	assert.Equal(t, "state-change", received[0].BackendID)
	assert.Equal(t, StateUninitialized, received[0].OldState)
	assert.Equal(t, StateReady, received[0].NewState)
}

func TestSubscribe_MultipleSubscribers(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()

	var count1, count2 atomic.Int32

	reg.Subscribe(func(_ Event) {
		count1.Add(1)
	})
	reg.Subscribe(func(_ Event) {
		count2.Add(1)
	})

	require.NoError(t, reg.Register(newTestBackend("multi-sub", CategorySoftware, LocationLocal)))

	assert.Equal(t, int32(1), count1.Load())
	assert.Equal(t, int32(1), count2.Load())
}

func TestUnsubscribe(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()

	var callCount atomic.Int32
	subID := reg.Subscribe(func(_ Event) {
		callCount.Add(1)
	})

	require.NoError(t, reg.Register(newTestBackend("unsub1", CategorySoftware, LocationLocal)))
	assert.Equal(t, int32(1), callCount.Load())

	reg.Unsubscribe(subID)

	require.NoError(t, reg.Register(newTestBackend("unsub2", CategorySoftware, LocationLocal)))
	assert.Equal(t, int32(1), callCount.Load(), "handler should not be called after unsubscribe")
}

func TestUnsubscribe_InvalidID(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	// Should not panic when unsubscribing with an ID that was never subscribed.
	reg.Unsubscribe(9999)
}

func TestSubscribe_PanicRecovery(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()

	var safeHandlerCalled atomic.Bool

	// First subscriber panics.
	reg.Subscribe(func(_ Event) {
		panic("intentional test panic")
	})

	// Second subscriber should still be called.
	reg.Subscribe(func(_ Event) {
		safeHandlerCalled.Store(true)
	})

	// This should not panic.
	require.NoError(t, reg.Register(newTestBackend("panic-test", CategorySoftware, LocationLocal)))

	assert.True(t, safeHandlerCalled.Load(),
		"safe handler should be called even when another handler panics")
}

// --- Close ---

func TestClose(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	err := reg.Close()
	require.NoError(t, err)

	err = reg.Register(newTestBackend("post-close", CategorySoftware, LocationLocal))
	assert.True(t, errors.Is(err, ErrRegistryClosed))

	err = reg.Unregister("anything")
	assert.True(t, errors.Is(err, ErrRegistryClosed))

	_, err = reg.Get("anything")
	assert.True(t, errors.Is(err, ErrRegistryClosed))

	_, err = reg.GetDefault(CapSigning)
	assert.True(t, errors.Is(err, ErrRegistryClosed))

	err = reg.SetDefault(CapSigning, "anything")
	assert.True(t, errors.Is(err, ErrRegistryClosed))
}

func TestClose_Idempotent(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	err := reg.Close()
	require.NoError(t, err)

	err = reg.Close()
	require.NoError(t, err)
}

// --- Concurrency ---

func TestConcurrent_RegisterGet(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	const goroutines = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Register goroutines.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("backend-%03d", idx)
			backend := newTestBackend(id, CategorySoftware, LocationLocal, CapSigning)
			_ = reg.Register(backend)
		}(i)
	}

	// Get goroutines (some may hit not-found, which is expected).
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("backend-%03d", idx)
			_, _ = reg.Get(id)
		}(i)
	}

	wg.Wait()

	// Verify all backends were registered.
	list := reg.List()
	assert.Len(t, list, goroutines)
}

func TestConcurrent_ListWhileRegistering(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines + goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("concurrent-%03d", idx)
			_ = reg.Register(newTestBackend(id, CategorySoftware, LocationLocal, CapSigning))
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = reg.List()
			_ = reg.ListByCapability(CapSigning)
			_ = reg.ListByCategory(CategorySoftware)
			_ = reg.ListByLocation(LocationLocal)
		}()
	}

	wg.Wait()
}

func TestConcurrent_SubscribeEmit(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	const subscribers = 20
	const registrations = 50

	var totalEvents atomic.Int32

	var wg sync.WaitGroup
	wg.Add(subscribers)
	for i := 0; i < subscribers; i++ {
		go func() {
			defer wg.Done()
			reg.Subscribe(func(_ Event) {
				totalEvents.Add(1)
			})
		}()
	}
	wg.Wait()

	wg.Add(registrations)
	for i := 0; i < registrations; i++ {
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("sub-emit-%03d", idx)
			_ = reg.Register(newTestBackend(id, CategorySoftware, LocationLocal))
		}(i)
	}
	wg.Wait()

	// Each registration emits 1 event to each of the subscribers.
	assert.Equal(t, int32(subscribers*registrations), totalEvents.Load())
}

// --- Metadata ---

func TestRegister_WithMetadata(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := &RegisteredBackend{
		ID:          "metadata-test",
		Category:    CategoryPKCS11,
		Location:    LocationLocal,
		DisplayName: "YubiKey #0",
		Capabilities: map[Capability]bool{
			CapPIV:     true,
			CapFIDO2:   true,
			CapSigning: true,
		},
		Metadata: map[string]string{
			"serial":       "12345678",
			"firmware":     "5.4.3",
			"manufacturer": "Yubico",
		},
	}

	require.NoError(t, reg.Register(backend))

	got, err := reg.Get("metadata-test")
	require.NoError(t, err)
	assert.Equal(t, "12345678", got.Metadata["serial"])
	assert.Equal(t, "5.4.3", got.Metadata["firmware"])
	assert.Equal(t, "Yubico", got.Metadata["manufacturer"])
	assert.Equal(t, "YubiKey #0", got.DisplayName)
}

// --- UpdateDisplayName ---

func TestUpdateDisplayName_Success(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("rename-test", CategoryPKCS11, LocationLocal, CapSigning)
	backend.DisplayName = "Old Name"
	require.NoError(t, reg.Register(backend))

	err := reg.UpdateDisplayName("rename-test", "New HSM Name")
	require.NoError(t, err)

	got, err := reg.Get("rename-test")
	require.NoError(t, err)
	assert.Equal(t, "New HSM Name", got.DisplayName)
}

func TestUpdateDisplayName_NotFound(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	err := reg.UpdateDisplayName("nonexistent", "Some Name")
	assert.True(t, errors.Is(err, ErrBackendNotFound))
}

func TestUpdateDisplayName_EmptyName(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("empty-name-test", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))

	err := reg.UpdateDisplayName("empty-name-test", "")
	assert.True(t, errors.Is(err, ErrEmptyDisplayName))
}

func TestUpdateDisplayName_AfterClose(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("close-rename", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))
	require.NoError(t, reg.Close())

	err := reg.UpdateDisplayName("close-rename", "New Name")
	assert.True(t, errors.Is(err, ErrRegistryClosed))
}

func TestUpdateDisplayName_EmitsEvent(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	backend := newTestBackend("event-rename", CategorySoftware, LocationLocal)
	require.NoError(t, reg.Register(backend))

	var received []Event
	var mu sync.Mutex
	reg.Subscribe(func(e Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	err := reg.UpdateDisplayName("event-rename", "Updated Name")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1)
	assert.Equal(t, EventDisplayNameChanged, received[0].Type)
	assert.Equal(t, "event-rename", received[0].BackendID)
}

// --- Edge cases ---

func TestRegister_AllCategories(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	categories := []BackendCategory{
		CategorySoftware, CategoryTPM2, CategoryPKCS11, CategoryXKMS, CategoryPhone,
	}

	for _, cat := range categories {
		id := fmt.Sprintf("cat-%s", cat)
		err := reg.Register(newTestBackend(id, cat, LocationLocal))
		require.NoError(t, err, "should register category %s", cat)
	}

	list := reg.List()
	assert.Len(t, list, len(categories))
}

func TestRegister_AllLocations(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	locations := []BackendLocation{LocationLocal, LocationRemote}

	for i, loc := range locations {
		id := fmt.Sprintf("loc-%d", i)
		err := reg.Register(newTestBackend(id, CategorySoftware, loc))
		require.NoError(t, err, "should register location %s", loc)
	}

	list := reg.List()
	assert.Len(t, list, len(locations))
}

func TestGetDefault_MultipleCapabilities(t *testing.T) {
	t.Parallel()

	reg := NewMemoryRegistry()
	signer := newTestBackend("signer-default", CategorySoftware, LocationLocal, CapSigning)
	encryptor := newTestBackend("encryptor-default", CategoryTPM2, LocationLocal, CapEncryption)

	require.NoError(t, reg.Register(signer))
	require.NoError(t, reg.Register(encryptor))
	require.NoError(t, reg.SetDefault(CapSigning, "signer-default"))
	require.NoError(t, reg.SetDefault(CapEncryption, "encryptor-default"))

	gotSigner, err := reg.GetDefault(CapSigning)
	require.NoError(t, err)
	assert.Equal(t, "signer-default", gotSigner.ID)

	gotEncryptor, err := reg.GetDefault(CapEncryption)
	require.NoError(t, err)
	assert.Equal(t, "encryptor-default", gotEncryptor.ID)
}
