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

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// pinKeyPrefix is the storage key namespace for TOFU pins.
// The full key for a given host:port is pinKeyPrefix + net.JoinHostPort(host, port).
// IPv6 addresses are unambiguous because net.JoinHostPort brackets them:
// "trust/tofu/pins/[::1]:8443".
const pinKeyPrefix = "trust/tofu/pins/"

// StoragePinStore implements truststrap.PinStore over a storage.Backend.
// Any Backend implementation works: in-memory, file, PebbleDB, or a
// Raft-replicated qrdb cluster — when the backend is a clustered qrdb every
// pin write replicates through the Raft log.
type StoragePinStore struct {
	backend storage.Backend
}

// Compile-time interface compliance check.
var _ truststrap.PinStore = (*StoragePinStore)(nil)

// NilBackendError is returned by NewStoragePinStore when backend is nil.
type NilBackendError struct{}

// Error returns a human-readable description of the error.
func (e NilBackendError) Error() string {
	return "bootstrap: StoragePinStore backend must not be nil"
}

// PinStoreGetError wraps a backend Get failure that is not a not-found condition.
type PinStoreGetError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the failure.
func (e *PinStoreGetError) Error() string {
	return "bootstrap: pin store get " + e.Key + ": " + e.Err.Error()
}

// Unwrap exposes the underlying error for errors.Is / errors.As.
func (e *PinStoreGetError) Unwrap() error { return e.Err }

// PinStorePutError wraps a backend Put failure.
type PinStorePutError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the failure.
func (e *PinStorePutError) Error() string {
	return "bootstrap: pin store put " + e.Key + ": " + e.Err.Error()
}

// Unwrap exposes the underlying error for errors.Is / errors.As.
func (e *PinStorePutError) Unwrap() error { return e.Err }

// PinStoreDeleteError wraps a backend Delete failure.
type PinStoreDeleteError struct {
	Key string
	Err error
}

// Error returns a human-readable description of the failure.
func (e *PinStoreDeleteError) Error() string {
	return "bootstrap: pin store delete " + e.Key + ": " + e.Err.Error()
}

// Unwrap exposes the underlying error for errors.Is / errors.As.
func (e *PinStoreDeleteError) Unwrap() error { return e.Err }

// PinStoreListError wraps a backend Scan failure during List.
type PinStoreListError struct {
	Err error
}

// Error returns a human-readable description of the failure.
func (e *PinStoreListError) Error() string {
	return "bootstrap: pin store list: " + e.Err.Error()
}

// Unwrap exposes the underlying error for errors.Is / errors.As.
func (e *PinStoreListError) Unwrap() error { return e.Err }

// NewStoragePinStore creates a StoragePinStore backed by the given storage.Backend.
// Returns NilBackendError when backend is nil.
func NewStoragePinStore(backend storage.Backend) (*StoragePinStore, error) {
	if backend == nil {
		return nil, NilBackendError{}
	}
	return &StoragePinStore{backend: backend}, nil
}

// pinStoreKey returns the storage key for a host:port pair using
// net.JoinHostPort, which brackets IPv6 addresses to prevent ambiguity.
func pinStoreKey(host string, port int) string {
	return pinKeyPrefix + net.JoinHostPort(host, itoa(port))
}

// Get retrieves the pin for the given host and port.
// Returns truststrap.ErrPinNotFound when no pin has been recorded.
func (s *StoragePinStore) Get(ctx context.Context, host string, port int) (*truststrap.Pin, error) {
	key := pinStoreKey(host, port)
	data, err := s.backend.Get(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, truststrap.ErrPinNotFound{Host: host, Port: port}
		}
		return nil, &PinStoreGetError{Key: key, Err: err}
	}
	var pin truststrap.Pin
	if err := json.Unmarshal(data, &pin); err != nil {
		return nil, &PinStoreGetError{Key: key, Err: err}
	}
	return &pin, nil
}

// Put validates and persists a pin. Returns truststrap.ErrNilPin when pin is
// nil; validation errors from truststrap propagate unchanged.
func (s *StoragePinStore) Put(ctx context.Context, pin *truststrap.Pin) error {
	if pin == nil {
		return truststrap.ErrNilPin{}
	}
	key := pinStoreKey(pin.Host, pin.Port)
	data, err := json.Marshal(pin)
	if err != nil {
		return &PinStorePutError{Key: key, Err: err}
	}
	if err := s.backend.Put(ctx, key, data); err != nil {
		return &PinStorePutError{Key: key, Err: err}
	}
	return nil
}

// Delete removes the pin for the given host and port.
// Returns nil when no pin exists (idempotent, matching storage.Backend.Delete semantics).
func (s *StoragePinStore) Delete(ctx context.Context, host string, port int) error {
	key := pinStoreKey(host, port)
	if err := s.backend.Delete(ctx, key); err != nil {
		// Backend.Delete is required to be idempotent; any remaining error
		// is a genuine transport or engine failure.
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return &PinStoreDeleteError{Key: key, Err: err}
	}
	return nil
}

// List returns all stored pins. The returned slice is nil when empty.
// Values are unmarshaled from JSON; entries that fail to unmarshal are skipped
// with no error so a single corrupt record does not block all other pins.
func (s *StoragePinStore) List(ctx context.Context) ([]*truststrap.Pin, error) {
	var pins []*truststrap.Pin
	err := s.backend.Scan(ctx, pinKeyPrefix, func(_ string, value []byte) error {
		var pin truststrap.Pin
		if jsonErr := json.Unmarshal(value, &pin); jsonErr != nil {
			// Skip corrupt records rather than aborting the scan.
			return nil
		}
		cp := pin
		pins = append(pins, &cp)
		return nil
	})
	if err != nil {
		return nil, &PinStoreListError{Err: err}
	}
	return pins, nil
}

// itoa converts a non-negative integer to its decimal string representation
// without importing strconv in the call-sites above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
