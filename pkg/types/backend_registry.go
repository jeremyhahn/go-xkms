package types

import (
	"errors"
	"fmt"
	"maps"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/validation"
)

var (
	// ErrInvalidBackendTypeName is returned when a backend type registered
	// from outside go-xkms has a name the Key ID format cannot carry: empty,
	// longer than 64 characters, or anything other than a-z, 0-9 and '-'.
	ErrInvalidBackendTypeName = errors.New("types: invalid backend type name")

	// ErrBackendTypeRegistered is returned when a backend type is registered
	// under a name a built-in backend or store type, or an earlier
	// registration, already holds.
	ErrBackendTypeRegistered = errors.New("types: backend type already registered")

	// ErrNilBackendFactory is returned when a backend type is registered
	// without a factory.
	ErrNilBackendFactory = errors.New("types: backend factory is nil")
)

// BackendFactory creates a KeyProvider from a backend's configuration map.
type BackendFactory func(config map[string]interface{}) (KeyProvider, error)

// BackendTypeRegistrationError reports a refused backend type registration.
// Err is ErrInvalidBackendTypeName, ErrBackendTypeRegistered, or a sentinel
// of the registering layer; Cause, when set, carries the underlying detail.
type BackendTypeRegistrationError struct {
	Type  BackendType
	Err   error
	Cause error
}

// Error names the refused type and the reason.
func (e *BackendTypeRegistrationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %q: %s", e.Err, string(e.Type), e.Cause)
	}
	return fmt.Sprintf("%s: %q", e.Err, string(e.Type))
}

// Unwrap exposes both the sentinel and the cause to errors.Is and errors.As.
func (e *BackendTypeRegistrationError) Unwrap() []error {
	if e.Cause != nil {
		return []error{e.Err, e.Cause}
	}
	return []error{e.Err}
}

// builtinBackendTypes is the closed set of backend types go-xkms itself
// defines. A registered backend type may never shadow one of them.
var builtinBackendTypes = map[BackendType]struct{}{
	BackendTypeSymmetric:    {},
	BackendTypeSoftware:     {},
	BackendTypePKCS11:       {},
	BackendTypeTPM2:         {},
	BackendTypeAWSKMS:       {},
	BackendTypeGCPKMS:       {},
	BackendTypeAzureKV:      {},
	BackendTypeVault:        {},
	BackendTypeQuantum:      {},
	BackendTypeFrost:        {},
	BackendTypePhone:        {},
	BackendTypeSmartCardHSM: {},
	BackendTypeYubiKey:      {},
	BackendTypeSoftHSM:      {},
	BackendTypeAVR:          {},
}

// registeredBackendTypes maps each backend type registered from outside
// go-xkms to the factory that builds it. It is the single source of truth for
// registered backends: a name and its factory are published in one immutable
// map behind one atomic pointer, so every reader sees both or neither.
// Lookups never lock and concurrent registrations never lose an entry.
var registeredBackendTypes atomic.Pointer[map[BackendType]BackendFactory]

// RegisterBackendType claims bt as a backend type and the identically named
// StoreType, built by factory, so keys the backend holds are labelled
// StoreType(bt) and a registered type is valid everywhere a built-in one is
// (StoreType.IsValid, ParseStoreType, the Key ID backend segment). The name
// and its factory become visible together, in one atomic step.
//
// External modules register through xkms.RegisterExternalBackend, which also
// refuses the backend names only pkg/xkms defines.
// Like the phone package's RegisterPlatform, registration is accepted at any
// time, typically from an init function, and is permanent for the process.
// A refused registration registers nothing.
func RegisterBackendType(bt BackendType, factory BackendFactory) error {
	if factory == nil {
		return &BackendTypeRegistrationError{Type: bt, Err: ErrNilBackendFactory}
	}
	if err := validation.ValidateBackendName(string(bt)); err != nil {
		return &BackendTypeRegistrationError{Type: bt, Err: ErrInvalidBackendTypeName, Cause: err}
	}
	if IsBuiltinBackendType(bt) {
		return &BackendTypeRegistrationError{Type: bt, Err: ErrBackendTypeRegistered}
	}
	for {
		current := registeredBackendTypes.Load()
		updated := make(map[BackendType]BackendFactory, 1)
		if current != nil {
			if _, exists := (*current)[bt]; exists {
				return &BackendTypeRegistrationError{Type: bt, Err: ErrBackendTypeRegistered}
			}
			maps.Copy(updated, *current)
		}
		updated[bt] = factory
		if registeredBackendTypes.CompareAndSwap(current, &updated) {
			return nil
		}
	}
}

// IsBuiltinBackendType reports whether bt names a backend or store type
// go-xkms defines itself.
func IsBuiltinBackendType(bt BackendType) bool {
	if _, ok := builtinBackendTypes[bt]; ok {
		return true
	}
	st := StoreType(bt)
	return st == StoreUnknown || isBuiltinStoreType(st)
}

// IsRegisteredBackendType reports whether bt was registered through
// RegisterBackendType.
func IsRegisteredBackendType(bt BackendType) bool {
	_, ok := RegisteredBackendFactory(bt)
	return ok
}

// RegisteredBackendFactory returns the factory bt was registered with by
// RegisterBackendType, and false when bt was never registered.
func RegisteredBackendFactory(bt BackendType) (BackendFactory, bool) {
	current := registeredBackendTypes.Load()
	if current == nil {
		return nil, false
	}
	factory, ok := (*current)[bt]
	return factory, ok
}

// RegisteredBackends returns every backend type added by RegisterBackendType
// with its factory, read from one snapshot. The caller owns the returned map.
func RegisteredBackends() map[BackendType]BackendFactory {
	current := registeredBackendTypes.Load()
	if current == nil {
		return map[BackendType]BackendFactory{}
	}
	return maps.Clone(*current)
}
