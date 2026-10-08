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

package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/qrdbrole"
)

// QRDBFakeTransport is a minimal, correct, in-memory implementation of the
// qrdb SDK's Transport + KVClient + UserClient + RoleClient contract. It
// backs a real *qrdbsdk.Client (via qrdbsdk.NewClient) for tests that need
// a working qrdb identity plane without standing up an embedded node --
// e.g. go-xkms's host-composition path (pkg/api/rest NewHostServer,
// pkg/apimodule's self-built REST surface) and anything else that consumes
// a *qrdbsdk.Client's Users/KV/Roles clients.
//
// Every method has real (if simple) semantics rather than an unexercised
// stub return, so a test failure means the code under test actually broke.
type QRDBFakeTransport struct {
	mu sync.Mutex

	kv map[string][]byte

	users       map[uint64]*qrdbtransport.User
	usersByName map[string]uint64
	// usersByEmail is a SEPARATE index from usersByName, mirroring the store:
	// resolving an email through the name map would let this fake answer lookups
	// the real store refuses (go-qrdb #190).
	usersByEmail map[string]uint64
	usersByCert  map[string]uint64
	nextUserID   uint64

	roles       map[string]*qrdbtransport.Role
	rolesByName map[string]string
	nextRoleID  int

	backups      map[string]*qrdbtransport.BackupInfo
	nextBackupID uint64
}

// Conformance is asserted at compile time: without this, a method added to
// an upstream qrdb interface surfaces as a panic inside a test binary that
// type-asserts this fake, not as a build failure. It did exactly that once.
var (
	_ qrdbtransport.UserClient      = (*QRDBFakeTransport)(nil)
	_ qrdbtransport.GuardedKVClient = (*QRDBFakeTransport)(nil)
	_ qrdbtransport.BackupClient    = (*QRDBFakeTransport)(nil)
	_ qrdbtransport.IndexClient     = (*QRDBFakeTransport)(nil)
)

// NewQRDBFakeTransport constructs an empty in-memory fake transport.
func NewQRDBFakeTransport() *QRDBFakeTransport {
	return &QRDBFakeTransport{
		kv:           make(map[string][]byte),
		users:        make(map[uint64]*qrdbtransport.User),
		usersByName:  make(map[string]uint64),
		usersByEmail: make(map[string]uint64),
		usersByCert:  make(map[string]uint64),
		roles:        make(map[string]*qrdbtransport.Role),
		rolesByName:  make(map[string]string),
		backups:      make(map[string]*qrdbtransport.BackupInfo),
	}
}

// NewQRDBFakeClient builds a real *qrdbsdk.Client wrapping a fresh
// QRDBFakeTransport, and returns the transport too so callers can inspect
// or pre-seed its state.
func NewQRDBFakeClient() (*qrdbsdk.Client, *QRDBFakeTransport, error) {
	ft := NewQRDBFakeTransport()
	client, err := qrdbsdk.NewClient(ft)
	if err != nil {
		return nil, nil, err
	}
	return client, ft, nil
}

// --- transport.Transport ---

// Connect implements transport.Transport; the fake needs no handshake.
func (f *QRDBFakeTransport) Connect(ctx context.Context) error { return nil }

// Close implements transport.Transport.
func (f *QRDBFakeTransport) Close() error { return nil }

// Healthy implements transport.Transport.
func (f *QRDBFakeTransport) Healthy(ctx context.Context) bool { return true }

// Request implements transport.Transport's generic RPC escape hatch, unused
// by the KV/User/Role clients the fake serves.
func (f *QRDBFakeTransport) Request(ctx context.Context, method string, req, resp any) error {
	return nil
}

// --- transport.KVClient ---

// Put implements transport.KVClient.
func (f *QRDBFakeTransport) Put(ctx context.Context, key string, value []byte, opts ...qrdbtransport.WriteOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	f.kv[key] = cp
	return nil
}

// Get implements transport.KVClient.
func (f *QRDBFakeTransport) Get(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.kv[key]
	if !ok {
		return nil, &qrdbtransport.KeyNotFoundError{Key: key}
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

// Delete implements transport.KVClient.
func (f *QRDBFakeTransport) Delete(ctx context.Context, key string, opts ...qrdbtransport.WriteOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.kv, key)
	return nil
}

// List implements transport.KVClient.
func (f *QRDBFakeTransport) List(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.kv {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Scan implements transport.KVClient.
func (f *QRDBFakeTransport) Scan(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string][]byte)
	for k, v := range f.kv {
		if strings.HasPrefix(k, prefix) {
			cp := make([]byte, len(v))
			copy(cp, v)
			out[k] = cp
		}
	}
	return out, nil
}

// Exists implements transport.KVClient.
func (f *QRDBFakeTransport) Exists(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.kv[key]
	return ok, nil
}

// --- transport.IndexClient ---
//
// The fake keeps no secondary indexes. It answers every index verb the way a
// node whose state machine lacks them does -- CapabilityUnsupportedError,
// which the SDK's KVStore surfaces as kvstore.ErrIndexUnsupported -- so
// Client.KVStore() and the DAOs built on it work over the fake for keyed
// CRUD, and an index lookup fails loudly instead of returning nothing.

// errFakeNoIndexes is the fake's answer to every index verb.
var errFakeNoIndexes = &qrdbtransport.CapabilityUnsupportedError{Message: "the qrdb fake transport keeps no secondary indexes"}

// IndexCreate implements transport.IndexClient.
func (f *QRDBFakeTransport) IndexCreate(ctx context.Context, name, fieldName string, config qrdbtransport.IndexConfig) error {
	return errFakeNoIndexes
}

// IndexDrop implements transport.IndexClient.
func (f *QRDBFakeTransport) IndexDrop(ctx context.Context, name string) error {
	return errFakeNoIndexes
}

// IndexQuery implements transport.IndexClient.
func (f *QRDBFakeTransport) IndexQuery(ctx context.Context, indexName, value string) (*qrdbtransport.IndexQueryResponse, error) {
	return nil, errFakeNoIndexes
}

// IndexScan implements transport.IndexClient.
func (f *QRDBFakeTransport) IndexScan(ctx context.Context, indexName string, start, end *string) (*qrdbtransport.IndexScanResponse, error) {
	return nil, errFakeNoIndexes
}

// IndexList implements transport.IndexClient.
func (f *QRDBFakeTransport) IndexList(ctx context.Context) (*qrdbtransport.IndexListResponse, error) {
	return nil, errFakeNoIndexes
}

// PutIfAbsent implements transport.GuardedKVClient.
func (f *QRDBFakeTransport) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.kv[key]; ok {
		return false, nil
	}
	f.kv[key] = bytes.Clone(value)
	return true, nil
}

// CompareAndDelete implements transport.GuardedKVClient.
func (f *QRDBFakeTransport) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.kv[key]
	if !ok || !bytes.Equal(v, expected) {
		return false, nil
	}
	delete(f.kv, key)
	return true, nil
}

// CompareAndSwap implements transport.GuardedKVClient. An absent key is left
// absent, exactly as the real verb.
func (f *QRDBFakeTransport) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.kv[key]
	if !ok || !bytes.Equal(v, expected) {
		return false, nil
	}
	f.kv[key] = bytes.Clone(next)
	return true, nil
}

// --- transport.UserClient ---

// CreateUser implements transport.UserClient.
func (f *QRDBFakeTransport) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// ENFORCE the real store's contract. qrdb refuses a user that declares
	// neither an email login key nor WithoutEmailLoginKey; a fake that accepts
	// one is not a cheaper store, it is a different one — and it hid exactly
	// that: xkms provisioning sent no Email at all, every test passed, and
	// against a real node CreateUser would have been rejected outright.
	if qrdbsdk.NormalizeEmail(req.Email) == "" && !req.WithoutEmailLoginKey {
		return nil, qrdbsdk.NewValidationError("email", qrdbsdk.ValidationConstraintEmpty,
			"must not be empty; set WithoutEmailLoginKey to create a user with no email login key")
	}
	nameKey := req.TenantID + "/" + req.Username
	if _, exists := f.usersByName[nameKey]; exists {
		return nil, &qrdbtransport.UserExistsError{Username: req.Username}
	}
	email := qrdbsdk.NormalizeEmail(req.Email)
	emailKey := req.TenantID + "/" + email
	if email != "" {
		if _, exists := f.usersByEmail[emailKey]; exists {
			return nil, &qrdbtransport.UserExistsError{Username: req.Username}
		}
	}
	f.nextUserID++
	u := &qrdbtransport.User{
		ID:       f.nextUserID,
		Username: req.Username,
		Email:    email,
		Name:     req.Name,
		TenantID: req.TenantID,
		RoleIDs:  append([]string{}, req.RoleIDs...),
		// qrdb v0.20: Lifecycle is the only account state.
		Lifecycle: string(qrdbsdk.LifecycleActive),
	}
	f.users[u.ID] = u
	f.usersByName[nameKey] = u.ID
	if email != "" {
		f.usersByEmail[emailKey] = u.ID
	}
	return u, nil
}

// GetUserByEmail resolves the canonical tenant-scoped login key.
func (f *QRDBFakeTransport) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	normalized := qrdbsdk.NormalizeEmail(email)
	if normalized == "" {
		return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, email)}
	}
	id, ok := f.usersByEmail[tenantID+"/"+normalized]
	if !ok {
		return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, normalized)}
	}
	return f.users[id], nil
}

// GetUser implements transport.UserClient.
func (f *QRDBFakeTransport) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return nil, &qrdbtransport.UserNotFoundError{ID: id}
	}
	return u, nil
}

// GetUserByUsername implements transport.UserClient.
func (f *QRDBFakeTransport) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.usersByName[tenantID+"/"+username]
	if !ok {
		return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, username)}
	}
	return f.users[id], nil
}

// GetUserByCertThumbprint implements transport.UserClient.
func (f *QRDBFakeTransport) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.usersByCert[thumbprint]
	if !ok {
		return nil, &qrdbtransport.UserNotFoundError{Lookup: "cert_spki/" + thumbprint}
	}
	return f.users[id], nil
}

// AddCertBinding implements transport.UserClient.
func (f *QRDBFakeTransport) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return nil, &qrdbtransport.UserNotFoundError{ID: userID}
	}
	f.usersByCert[thumbprint] = userID
	return u, nil
}

// RemoveCertBinding implements transport.UserClient. It withdraws the
// thumbprint so GetUserByCertThumbprint stops resolving it.
//
// A withdrawal that matched nothing is REPORTED, never succeeded vacuously:
// the real store refuses it so an operator who mistypes a thumbprint is not
// told the key is withdrawn while the real binding stays live. The store's
// typed *user.CertBindingNotFoundError is not reachable from the SDK surface,
// and the REST transport deliberately collapses "no such user" and "no such
// binding" onto UserNotFoundError because they differ only in the server's
// message. This fake implements the transport, so it returns what the
// transport returns.
func (f *QRDBFakeTransport) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return nil, &qrdbtransport.UserNotFoundError{ID: userID}
	}
	if bound, ok := f.usersByCert[thumbprint]; !ok || bound != userID {
		return nil, &qrdbtransport.UserNotFoundError{ID: userID}
	}
	delete(f.usersByCert, thumbprint)
	return u, nil
}

// UpdateUser implements transport.UserClient.
func (f *QRDBFakeTransport) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[req.ID]
	if !ok {
		return nil, &qrdbtransport.UserNotFoundError{ID: req.ID}
	}
	if req.Username != "" {
		delete(f.usersByName, u.TenantID+"/"+u.Username)
		u.Username = req.Username
		f.usersByName[u.TenantID+"/"+u.Username] = u.ID
	}
	if newEmail := qrdbsdk.NormalizeEmail(req.Email); newEmail != "" && newEmail != u.Email {
		if _, taken := f.usersByEmail[u.TenantID+"/"+newEmail]; taken {
			return nil, &qrdbtransport.UserExistsError{Username: u.Username}
		}
		if u.Email != "" {
			delete(f.usersByEmail, u.TenantID+"/"+u.Email)
		}
		u.Email = newEmail
		f.usersByEmail[u.TenantID+"/"+u.Email] = u.ID
	}
	if req.Name != "" {
		u.Name = req.Name
	}
	if req.RoleIDs != nil {
		u.RoleIDs = req.RoleIDs
	}
	return u, nil
}

// DeleteUser implements transport.UserClient.
func (f *QRDBFakeTransport) DeleteUser(ctx context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return &qrdbtransport.UserNotFoundError{ID: id}
	}
	delete(f.usersByName, u.TenantID+"/"+u.Username)
	if u.Email != "" {
		delete(f.usersByEmail, u.TenantID+"/"+u.Email)
	}
	delete(f.users, id)
	return nil
}

// ListUsers implements transport.UserClient.
func (f *QRDBFakeTransport) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*qrdbtransport.User
	for _, u := range f.users {
		if req == nil || req.TenantID == "" || u.TenantID == req.TenantID {
			out = append(out, u)
		}
	}
	return &qrdbtransport.ListUsersResponse{Users: out, Total: len(out)}, nil
}

// EnableUser implements transport.UserClient.
func (f *QRDBFakeTransport) EnableUser(ctx context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return &qrdbtransport.UserNotFoundError{ID: id}
	}
	u.Lifecycle = string(qrdbsdk.LifecycleActive)
	return nil
}

// DisableUser implements transport.UserClient.
func (f *QRDBFakeTransport) DisableUser(ctx context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return &qrdbtransport.UserNotFoundError{ID: id}
	}
	u.Lifecycle = string(qrdbsdk.LifecycleDisabled)
	return nil
}

// --- transport.RoleClient ---

// CreateRole implements transport.RoleClient.
func (f *QRDBFakeTransport) CreateRole(ctx context.Context, req *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := req.ID
	if id == "" {
		f.nextRoleID++
		id = "role-" + idString(uint64(f.nextRoleID))
	}
	r := &qrdbtransport.Role{
		ID:          id,
		Name:        req.Name,
		TenantID:    req.TenantID,
		Permissions: req.Permissions,
	}
	f.roles[id] = r
	f.rolesByName[req.TenantID+"/"+req.Name] = id
	return r, nil
}

// GetRole implements transport.RoleClient.
func (f *QRDBFakeTransport) GetRole(ctx context.Context, id string) (*qrdbtransport.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.roles[id]
	if !ok {
		return nil, &qrdbtransport.RoleNotFoundError{ID: id}
	}
	return r, nil
}

// GetRoleByName implements transport.RoleClient.
func (f *QRDBFakeTransport) GetRoleByName(ctx context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.rolesByName[req.TenantID+"/"+req.Name]
	if !ok {
		return nil, &qrdbtransport.RoleNotFoundError{ID: req.Name}
	}
	return f.roles[id], nil
}

// UpdateRole implements transport.RoleClient.
func (f *QRDBFakeTransport) UpdateRole(ctx context.Context, req *qrdbtransport.UpdateRoleRequest) (*qrdbtransport.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.roles[req.ID]
	if !ok {
		return nil, &qrdbtransport.RoleNotFoundError{ID: req.ID}
	}
	if req.Name != "" {
		r.Name = req.Name
	}
	if req.Permissions != nil {
		r.Permissions = req.Permissions
	}
	return r, nil
}

// DeleteRole implements transport.RoleClient.
func (f *QRDBFakeTransport) DeleteRole(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.roles[id]
	if !ok {
		return &qrdbtransport.RoleNotFoundError{ID: id}
	}
	delete(f.rolesByName, r.TenantID+"/"+r.Name)
	delete(f.roles, id)
	return nil
}

// ListRoles implements transport.RoleClient.
func (f *QRDBFakeTransport) ListRoles(ctx context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*qrdbtransport.Role
	for _, r := range f.roles {
		out = append(out, r)
	}
	return &qrdbtransport.ListRolesResponse{Roles: out, Total: len(out)}, nil
}

// AssignRole implements transport.RoleClient.
func (f *QRDBFakeTransport) AssignRole(ctx context.Context, userID uint64, roleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return &qrdbtransport.UserNotFoundError{ID: userID}
	}
	u.RoleIDs = append(u.RoleIDs, roleID)
	return nil
}

// UnassignRole implements transport.RoleClient.
func (f *QRDBFakeTransport) UnassignRole(ctx context.Context, userID uint64, roleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return &qrdbtransport.UserNotFoundError{ID: userID}
	}
	kept := u.RoleIDs[:0]
	for _, id := range u.RoleIDs {
		if id != roleID {
			kept = append(kept, id)
		}
	}
	u.RoleIDs = kept
	return nil
}

// ListPermissions implements transport.RoleClient.
func (f *QRDBFakeTransport) ListPermissions(ctx context.Context) (*qrdbtransport.ListPermissionsResponse, error) {
	return &qrdbtransport.ListPermissionsResponse{}, nil
}

// ResolvePermissions implements transport.RoleClient.
func (f *QRDBFakeTransport) ResolvePermissions(ctx context.Context, req *qrdbtransport.ResolvePermissionsRequest) (*qrdbtransport.ResolvePermissionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var perms []string
	for _, id := range req.RoleIDs {
		r, ok := f.roles[id]
		if !ok {
			continue
		}
		for _, p := range r.Permissions {
			if !seen[p] {
				seen[p] = true
				perms = append(perms, p)
			}
		}
	}
	sort.Strings(perms)
	return &qrdbtransport.ResolvePermissionsResponse{Permissions: perms}, nil
}

// ReconcileBuiltInRoles implements transport.RoleClient. It converges the
// tenant's stored built-in roles onto the definitions the linked go-qrdb build
// publishes: permissions the build now grants are added, permissions it no
// longer grants are removed, custom roles are left untouched, and a tenant
// already in agreement performs zero writes.
//
// The convergence itself lives in pkg/qrdbrole so every in-memory RoleClient in
// this repository answers the verb identically.
func (f *QRDBFakeTransport) ReconcileBuiltInRoles(ctx context.Context, req *qrdbtransport.ReconcileRolesRequest) (*qrdbtransport.ReconcileRolesResponse, error) {
	return qrdbrole.Reconcile(ctx, f, req)
}

func idString(v uint64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// --- transport.BackupClient ---
//
// A real, minimal in-memory implementation: metadata only, no actual shard
// data or checksum computation (there is no node here to snapshot). Tests
// that need checksum/tamper semantics use pkg/xkms's own fakeBackupClient.

// CreateBackup implements transport.BackupClient.
func (f *QRDBFakeTransport) CreateBackup(_ context.Context, req *qrdbtransport.BackupRequest) (*qrdbtransport.BackupInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.Destination == "" {
		return nil, &qrdbtransport.BackupEmptyDestinationError{}
	}
	f.nextBackupID++
	info := &qrdbtransport.BackupInfo{
		ID:          idString(f.nextBackupID),
		Status:      qrdbtransport.BackupStatusComplete,
		Destination: req.Destination,
		Compression: req.Compression,
		Encryption:  req.Encryption,
		Metadata:    req.Metadata,
	}
	f.backups[info.ID] = info
	return info, nil
}

// ListBackups implements transport.BackupClient.
func (f *QRDBFakeTransport) ListBackups(_ context.Context) ([]qrdbtransport.BackupInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]qrdbtransport.BackupInfo, 0, len(f.backups))
	for _, info := range f.backups {
		out = append(out, *info)
	}
	return out, nil
}

// GetBackup implements transport.BackupClient.
func (f *QRDBFakeTransport) GetBackup(_ context.Context, id string) (*qrdbtransport.BackupInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == "" {
		return nil, &qrdbtransport.BackupEmptyIDError{}
	}
	info, ok := f.backups[id]
	if !ok {
		return nil, &qrdbtransport.BackupNotFoundError{ID: id}
	}
	cp := *info
	return &cp, nil
}

// DeleteBackup implements transport.BackupClient.
func (f *QRDBFakeTransport) DeleteBackup(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == "" {
		return &qrdbtransport.BackupEmptyIDError{}
	}
	if _, ok := f.backups[id]; !ok {
		return &qrdbtransport.BackupNotFoundError{ID: id}
	}
	delete(f.backups, id)
	return nil
}

// RestoreBackup implements transport.BackupClient.
func (f *QRDBFakeTransport) RestoreBackup(_ context.Context, req *qrdbtransport.RestoreRequest) (*qrdbtransport.RestoreResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.BackupID == "" {
		return nil, &qrdbtransport.BackupEmptyIDError{}
	}
	if _, ok := f.backups[req.BackupID]; !ok {
		return nil, &qrdbtransport.BackupNotFoundError{ID: req.BackupID}
	}
	return &qrdbtransport.RestoreResult{BackupID: req.BackupID}, nil
}

// VerifyBackup implements transport.BackupClient.
func (f *QRDBFakeTransport) VerifyBackup(_ context.Context, id string) (*qrdbtransport.VerifyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == "" {
		return nil, &qrdbtransport.BackupEmptyIDError{}
	}
	if _, ok := f.backups[id]; !ok {
		return nil, &qrdbtransport.BackupNotFoundError{ID: id}
	}
	return &qrdbtransport.VerifyResult{Valid: true, ChecksumMatch: true}, nil
}
