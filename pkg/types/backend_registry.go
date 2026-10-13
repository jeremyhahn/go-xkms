package types

import (
	"errors"
	"fmt"
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
)

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

// registeredBackendTypes holds the backend types registered from outside
// go-xkms. It is copy-on-write behind an atomic pointer, so lookups never
// lock and concurrent registrations never lose an entry.
var registeredBackendTypes atomic.Pointer[map[BackendType]struct{}]

// RegisterBackendType claims bt as a backend type and the identically named
// StoreType, so keys the backend holds are labelled StoreType(bt) and a
// registered type is valid everywhere a built-in one is (StoreType.IsValid,
// ParseStoreType, the Key ID backend segment).
//
// External modules register through xkms.RegisterExternalBackend, which also
// installs the backend's factory; this function is the name claim beneath it.
// Like the phone package's RegisterPlatform, registration is accepted at any
// time, typically from an init function, and is permanent for the process.
func RegisterBackendType(bt BackendType) error {
	if err := validation.ValidateBackendName(string(bt)); err != nil {
		return &BackendTypeRegistrationError{Type: bt, Err: ErrInvalidBackendTypeName, Cause: err}
	}
	if IsBuiltinBackendType(bt) {
		return &BackendTypeRegistrationError{Type: bt, Err: ErrBackendTypeRegistered}
	}
	for {
		current := registeredBackendTypes.Load()
		updated := make(map[BackendType]struct{}, 1)
		if current != nil {
			if _, exists := (*current)[bt]; exists {
				return &BackendTypeRegistrationError{Type: bt, Err: ErrBackendTypeRegistered}
			}
			for k := range *current {
				updated[k] = struct{}{}
			}
		}
		updated[bt] = struct{}{}
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
	current := registeredBackendTypes.Load()
	if current == nil {
		return false
	}
	_, ok := (*current)[bt]
	return ok
}
