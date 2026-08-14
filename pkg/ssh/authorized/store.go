// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package authorized

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// storagePrefix is the top-level namespace for authorized-entry
// envelopes. Changing this string is a disk-layout break.
const storagePrefix = "ssh/authorized_keys/"

// envelopeVersion is the current on-disk envelope format.
const envelopeVersion = 1

// Store is the persistence interface for authorized_keys Entries.
// Writes take an Entry — the parsed line — while reads return a Record,
// which pairs that Entry with the store metadata (scope, owner, name,
// add time) it was filed under. Implementations MUST be safe for
// concurrent use.
type Store interface {
	// Add persists entry under (scope, owner, name). Returns
	// *DuplicateError if a record already exists at that path;
	// non-idempotent by design.
	Add(ctx context.Context, sc scope.Scope, owner, name string, entry *Entry) error

	// Get loads the record at (scope, owner, name). Returns
	// *NotFoundError on miss. The returned Record carries the stored
	// coordinates, which are authoritative over the arguments.
	Get(ctx context.Context, sc scope.Scope, owner, name string) (*Record, error)

	// List enumerates records under (scope, owner). An empty scope
	// enumerates every scope; an empty owner every owner within scope.
	// Each Record carries the name it was stored under, so a listed
	// record can be fed straight back into Get or Remove.
	List(ctx context.Context, sc scope.Scope, owner string) ([]*Record, error)

	// Remove deletes the entry. Returns *NotFoundError on miss.
	Remove(ctx context.Context, sc scope.Scope, owner, name string) error
}

// BackendStore implements Store on top of a storage.Backend.
type BackendStore struct {
	backend storage.Backend
}

// NewBackendStore returns a BackendStore. Errors with *NilInputError if
// backend is nil.
func NewBackendStore(backend storage.Backend) (*BackendStore, error) {
	if backend == nil {
		return nil, &NilInputError{Field: "backend"}
	}
	return &BackendStore{backend: backend}, nil
}

// storedEnvelope is the on-disk JSON representation of an Entry. We
// store the emitted authorized_keys line verbatim — on read we re-parse
// it to reconstruct the Entry. This keeps the envelope small and
// removes a JSON migration path for every future field added to Entry.
type storedEnvelope struct {
	Version int       `json:"v"`
	Scope   string    `json:"scope"`
	Owner   string    `json:"owner"`
	Name    string    `json:"name"`
	AddedAt time.Time `json:"added"`
	Line    string    `json:"line"`
}

// Add implements Store.Add.
func (s *BackendStore) Add(ctx context.Context, sc scope.Scope, owner, name string, entry *Entry) error {
	path, err := buildPath(sc, owner, name)
	if err != nil {
		return err
	}
	if entry == nil {
		return &NilInputError{Field: "entry"}
	}

	present, existsErr := s.backend.Exists(ctx, path)
	if existsErr != nil {
		return &StorageError{Op: "exists", Err: existsErr}
	}
	if present {
		return &DuplicateError{Scope: string(sc), Owner: owner, Name: name}
	}

	line, emitErr := Emit(entry)
	if emitErr != nil {
		return emitErr
	}
	env := storedEnvelope{
		Version: envelopeVersion,
		Scope:   string(sc),
		Owner:   owner,
		Name:    name,
		AddedAt: time.Now().UTC(),
		Line:    line,
	}
	data, jerr := json.Marshal(&env)
	if jerr != nil {
		return &SerializationError{Op: "marshal envelope", Err: jerr}
	}
	if perr := s.backend.Put(ctx, path, data); perr != nil {
		return &StorageError{Op: "put", Err: perr}
	}
	return nil
}

// Get implements Store.Get.
func (s *BackendStore) Get(ctx context.Context, sc scope.Scope, owner, name string) (*Record, error) {
	path, err := buildPath(sc, owner, name)
	if err != nil {
		return nil, err
	}
	data, gerr := s.backend.Get(ctx, path)
	if gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			return nil, &NotFoundError{Scope: string(sc), Owner: owner, Name: name}
		}
		return nil, &StorageError{Op: "get", Err: gerr}
	}
	return decodeEnvelope(data)
}

// List implements Store.List.
func (s *BackendStore) List(ctx context.Context, sc scope.Scope, owner string) ([]*Record, error) {
	prefix := storagePrefix
	if sc != "" {
		if !sc.Valid() {
			return nil, &scope.ScopeInvalidError{Value: string(sc)}
		}
		prefix += string(sc) + "/"
		if owner != "" {
			if strings.ContainsRune(owner, '/') {
				return nil, &scope.KeyIDMalformedError{Field: "owner", Reason: "contains separator"}
			}
			prefix += owner + "/"
		}
	}
	var out []*Record
	err := s.backend.Scan(ctx, prefix, func(_ string, value []byte) error {
		rec, derr := decodeEnvelope(value)
		if derr != nil {
			return derr
		}
		out = append(out, rec)
		return nil
	})
	if err != nil {
		return nil, &StorageError{Op: "scan", Err: err}
	}
	return out, nil
}

// Remove implements Store.Remove.
func (s *BackendStore) Remove(ctx context.Context, sc scope.Scope, owner, name string) error {
	path, err := buildPath(sc, owner, name)
	if err != nil {
		return err
	}
	if derr := s.backend.Delete(ctx, path); derr != nil {
		if errors.Is(derr, storage.ErrNotFound) {
			return &NotFoundError{Scope: string(sc), Owner: owner, Name: name}
		}
		return &StorageError{Op: "delete", Err: derr}
	}
	return nil
}

// buildPath validates components and returns the full storage key
// "ssh/authorized_keys/<scope>/<owner>/<name>".
func buildPath(sc scope.Scope, owner, name string) (string, error) {
	if !sc.Valid() {
		return "", &scope.ScopeInvalidError{Value: string(sc)}
	}
	if owner == "" {
		return "", &scope.KeyIDMalformedError{Field: "owner", Reason: "empty"}
	}
	if strings.ContainsRune(owner, '/') {
		return "", &scope.KeyIDMalformedError{Field: "owner", Reason: "contains separator"}
	}
	if err := validateName(name); err != nil {
		return "", err
	}
	var b strings.Builder
	b.Grow(len(storagePrefix) + len(sc) + len(owner) + len(name) + 2)
	b.WriteString(storagePrefix)
	b.WriteString(string(sc))
	b.WriteByte('/')
	b.WriteString(owner)
	b.WriteByte('/')
	b.WriteString(name)
	return b.String(), nil
}

// validateName enforces the same rules used by buildPath: non-empty, no
// '/', no NUL.
func validateName(name string) error {
	if name == "" {
		return &InvalidNameError{Value: name, Reason: "empty"}
	}
	if strings.ContainsRune(name, '/') {
		return &InvalidNameError{Value: name, Reason: "contains path separator"}
	}
	if strings.ContainsRune(name, 0) {
		return &InvalidNameError{Value: name, Reason: "contains NUL byte"}
	}
	return nil
}

// decodeEnvelope reads a JSON envelope and rehydrates a *Record: the
// Entry comes from re-parsing the stored authorized_keys line, the
// coordinates from the envelope's own metadata fields. Every envelope
// ever written carries scope/owner/name, so this reads pre-existing
// data unchanged — no migration and no re-write required.
func decodeEnvelope(data []byte) (*Record, error) {
	var env storedEnvelope
	if jerr := json.Unmarshal(data, &env); jerr != nil {
		return nil, &SerializationError{Op: "unmarshal envelope", Err: jerr}
	}
	// Add stamps every envelope with the format version, but nothing read it
	// back, so a future bump would have been misparsed as v1 and silently
	// mishandled. Refuse a newer format instead: a binary that predates the
	// bump cannot know what changed. Versions at or below the current one stay
	// readable, which keeps every envelope written so far (v1, and a zero value
	// from any envelope written before the field existed) working untouched.
	if env.Version > envelopeVersion {
		return nil, &UnsupportedVersionError{Found: env.Version, Supported: envelopeVersion}
	}
	entry, err := ParseLine(env.Line)
	if err != nil {
		return nil, err
	}
	return &Record{
		Scope:   scope.Scope(env.Scope),
		Owner:   env.Owner,
		Name:    env.Name,
		AddedAt: env.AddedAt,
		Entry:   entry,
	}, nil
}
