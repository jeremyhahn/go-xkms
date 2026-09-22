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

package transport

// PKCS#11 remote-state DTOs.
//
// These carry the PKCS#11 module's durable token and object state — token
// metadata, PIN hashes, failed-attempt (lockout) counters, object metadata and
// the object-handle counter — to and from xkmsd when the module runs with
// StorageType "remote". The values are OPAQUE bytes to the transport and the
// server: the module serialises its own PersistentTokenState / PersistentObject
// records and the server stores them verbatim in the embedded qrdb node, so the
// wire contract never has to track the module's record schema.
//
// Records are namespaced by (TenantID, Token, Key): TenantID scopes to a tenant
// (empty is the system scope), Token is the token label, and Key is the module's
// own storage key (e.g. "pkcs11/tokens/0", "pkcs11/objects/<handle>"). This is
// the same shape the local file/memory backends key on, so the remote backend is
// a drop-in storage.Backend.

// PKCS11StatePutRequest stores a record.
type PKCS11StatePutRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Token    string `json:"token"`
	Key      string `json:"key"`
	Value    []byte `json:"value"`
}

// PKCS11StateGetRequest retrieves a record.
type PKCS11StateGetRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Token    string `json:"token"`
	Key      string `json:"key"`
}

// PKCS11StateGetResponse carries a retrieved record. Found distinguishes an
// absent key from a present empty value, which the module relies on to tell
// "no persisted state" from "state that happens to be empty".
type PKCS11StateGetResponse struct {
	Value []byte `json:"value"`
	Found bool   `json:"found"`
}

// PKCS11StateDeleteRequest removes a record.
type PKCS11StateDeleteRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Token    string `json:"token"`
	Key      string `json:"key"`
}

// PKCS11StateListRequest lists the keys under a prefix within a token's
// namespace. An empty Prefix lists every key for the token.
type PKCS11StateListRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Token    string `json:"token"`
	Prefix   string `json:"prefix,omitempty"`
}

// PKCS11StateListResponse carries the matched keys (namespace-relative).
type PKCS11StateListResponse struct {
	Keys []string `json:"keys"`
}

// PKCS11StatePutIfAbsentRequest atomically stores a record only if the key does
// not already exist. It backs the storage.Backend PutIfAbsent primitive, which
// the module uses for single-use markers and first-write races. The stricter
// multi-client lockout-counter value-CAS is served by PKCS11StateCAS below.
type PKCS11StatePutIfAbsentRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Token    string `json:"token"`
	Key      string `json:"key"`
	Value    []byte `json:"value"`
}

// PKCS11StatePutIfAbsentResponse reports whether the value was written (Stored
// true) or the key already held a value (Stored false, store unchanged).
type PKCS11StatePutIfAbsentResponse struct {
	Stored bool `json:"stored"`
}

// PKCS11StateCASRequest atomically stores New at the key only if the current
// value equals Expected exactly (#186: a swap cannot create, so this holds
// regardless of what Expected is — nil included). It backs the
// storage.CompareAndSwapper primitive over the remote backend so multiple
// clients sharing one remote token can update the failed-attempt (lockout)
// counter without losing writes: the counter is a read-modify-write, and only
// a value-CAS makes concurrent increments safe. The create-if-absent
// precondition is served by the dedicated PKCS11StatePutIfAbsent RPC.
type PKCS11StateCASRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Token    string `json:"token"`
	Key      string `json:"key"`
	Expected []byte `json:"expected,omitempty"`
	New      []byte `json:"new"`
}

// PKCS11StateCASResponse reports whether the swap occurred. When Swapped is
// false, Current carries the value actually present (nil/empty when absent) so
// the caller can recompute against it and retry.
type PKCS11StateCASResponse struct {
	Swapped bool   `json:"swapped"`
	Current []byte `json:"current,omitempty"`
}

// PKCS11StateCADRequest atomically removes the record only if its current value
// equals Expected. It backs the storage.CompareAndDeleter primitive over the
// remote backend: the guarded release that pairs with PKCS11StatePutIfAbsent's
// guarded create, evaluated where the server serialises writes rather than on
// the client, since the clients sharing one remote token are separate
// processes on separate hosts.
//
// Unlike PKCS11StateCASRequest there is no absent flag: a nil Expected is not
// a wildcard and does not mean "require absent". It is equivalent to an empty
// slice and matches a stored empty value only, exactly as
// storage.CompareAndDeleter specifies, so JSON's inability to tell a nil byte
// slice from an empty one changes nothing here.
type PKCS11StateCADRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Token    string `json:"token"`
	Key      string `json:"key"`
	Expected []byte `json:"expected,omitempty"`
}

// PKCS11StateCADResponse reports whether this call removed the record. Deleted
// is false, with a successful response, when the key was absent or held a
// different value; in both cases the store is unchanged. A transport error
// means the outcome is unknown.
type PKCS11StateCADResponse struct {
	Deleted bool `json:"deleted"`
}

// PKCS11StatePutResponse acknowledges a Put. It carries no payload today but
// exists so the RPC has a response message to evolve (e.g. a version token).
type PKCS11StatePutResponse struct{}

// PKCS11StateDeleteResponse acknowledges a Delete.
type PKCS11StateDeleteResponse struct{}
