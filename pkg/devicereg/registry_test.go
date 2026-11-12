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

package devicereg

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// faultKV is a memory KV store whose reads or writes fail on demand.
type faultKV struct {
	*qrdbsdk.MemoryKVStore
	err        error
	failReads  bool
	failWrites bool
}

func newFaultKV() *faultKV {
	return &faultKV{MemoryKVStore: qrdbsdk.NewMemoryKVStore(), err: errors.New("store down")}
}

func (f *faultKV) Put(ctx context.Context, key string, value []byte) error {
	if f.failWrites {
		return f.err
	}
	return f.MemoryKVStore.Put(ctx, key, value)
}

func (f *faultKV) Delete(ctx context.Context, key string) error {
	if f.failWrites {
		return f.err
	}
	return f.MemoryKVStore.Delete(ctx, key)
}

func (f *faultKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if f.failWrites {
		return false, f.err
	}
	return f.MemoryKVStore.CompareAndSwap(ctx, key, expected, next)
}

func (f *faultKV) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if f.failWrites {
		return false, f.err
	}
	return f.MemoryKVStore.CompareAndDelete(ctx, key, expected)
}

func (f *faultKV) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if f.failWrites {
		return false, f.err
	}
	return f.MemoryKVStore.PutIfAbsent(ctx, key, value)
}

func (f *faultKV) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	if f.failWrites {
		return false, f.err
	}
	return f.MemoryKVStore.PutIfAllAbsent(ctx, key, value, fences...)
}

func (f *faultKV) Get(ctx context.Context, key string) ([]byte, error) {
	if f.failReads {
		return nil, f.err
	}
	return f.MemoryKVStore.Get(ctx, key)
}

func (f *faultKV) List(ctx context.Context, prefix string) ([]string, error) {
	if f.failReads {
		return nil, f.err
	}
	return f.MemoryKVStore.List(ctx, prefix)
}

func (f *faultKV) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	if f.failReads {
		return f.err
	}
	return f.MemoryKVStore.Scan(ctx, prefix, fn)
}

var pairedAt = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func newTestRegistry(t testing.TB) *Registry {
	t.Helper()
	r, err := NewRegistry(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func testDevice(id string) *Device {
	return &Device{
		ID:                         id,
		Name:                       "phone " + id,
		IdentityKey:                []byte{0x30, 0x59, 0x30, 0x13},
		AttestationProtocolVersion: 2,
		PairedAt:                   pairedAt,
		PairedBy:                   "alice",
	}
}

func TestNewRegistry(t *testing.T) {
	if r, err := NewRegistry(nil); r != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewRegistry(nil) = %v, %v; want ErrInvalidConfig", r, err)
	}
	newTestRegistry(t)
}

func TestPairAndGet(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	in := testDevice("pixel-8")
	if err := r.Pair(ctx, "acme", in); err != nil {
		t.Fatalf("Pair: %v", err)
	}
	got, err := r.Get(ctx, "acme", "pixel-8")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != in.ID || got.Name != in.Name || !bytes.Equal(got.IdentityKey, in.IdentityKey) ||
		got.AttestationProtocolVersion != 2 || !got.PairedAt.Equal(pairedAt) ||
		got.PairedBy != "alice" || got.RevokedAt != nil {
		t.Fatalf("Get = %+v; want %+v", got, in)
	}
	if !got.Active() {
		t.Fatal("a paired device is not active")
	}
}

func TestPairDuplicate(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	if err := r.Pair(ctx, "acme", testDevice("d1")); err != nil {
		t.Fatal(err)
	}
	other := testDevice("d1")
	other.Name = "impostor"
	if err := r.Pair(ctx, "acme", other); !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("duplicate Pair = %v; want ErrDeviceExists", err)
	}
	got, err := r.Get(ctx, "acme", "d1")
	if err != nil || got.Name != "phone d1" {
		t.Fatalf("Get after duplicate = %+v, %v; want the first record", got, err)
	}
	// The same ID in another tenant is a different device.
	if err := r.Pair(ctx, "globex", testDevice("d1")); err != nil {
		t.Fatalf("Pair in another tenant: %v", err)
	}
}

func TestPairRefusesInvalidInput(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	if err := r.Pair(ctx, "acme", nil); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("Pair(nil) = %v; want ErrInvalidDevice", err)
	}
	noKey := testDevice("d1")
	noKey.IdentityKey = nil
	if err := r.Pair(ctx, "acme", noKey); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("Pair without identity key = %v; want ErrInvalidDevice", err)
	}
	revoked := testDevice("d2")
	revoked.RevokedAt = &pairedAt
	if err := r.Pair(ctx, "acme", revoked); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("Pair of a revoked record = %v; want ErrInvalidDevice", err)
	}
	if err := r.Pair(ctx, "acme", testDevice("bad/id")); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("Pair with bad ID = %v; want ErrInvalidID", err)
	}
	if err := r.Pair(ctx, "", testDevice("d3")); !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("Pair with empty tenant = %v; want ErrInvalidTenant", err)
	}
}

func TestPairCopiesTheRecord(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	in := testDevice("d1")
	if err := r.Pair(ctx, "acme", in); err != nil {
		t.Fatal(err)
	}
	in.IdentityKey[0] = 0xff
	got, err := r.Get(ctx, "acme", "d1")
	if err != nil || got.IdentityKey[0] != 0x30 {
		t.Fatalf("stored key changed with the caller's slice: %v, %v", got, err)
	}
}

func TestGetNotFound(t *testing.T) {
	r := newTestRegistry(t)
	if _, err := r.Get(context.Background(), "acme", "missing"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("Get missing = %v; want ErrDeviceNotFound", err)
	}
}

func TestListOrderedByID(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	for _, id := range []string{"c", "a", "b"} {
		if err := r.Pair(ctx, "acme", testDevice(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Pair(ctx, "globex", testDevice("0")); err != nil {
		t.Fatal(err)
	}
	devices, err := r.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var ids []string
	for _, d := range devices {
		ids = append(ids, d.ID)
	}
	if strings.Join(ids, ",") != "a,b,c" {
		t.Fatalf("List IDs = %v; want a,b,c", ids)
	}
	empty, err := r.List(ctx, "initech")
	if err != nil || len(empty) != 0 {
		t.Fatalf("List of an empty tenant = %v, %v", empty, err)
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	if err := r.Pair(ctx, "acme", testDevice("d1")); err != nil {
		t.Fatal(err)
	}
	at := pairedAt.Add(time.Hour)
	if err := r.Revoke(ctx, "acme", "d1", at); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Idempotent: a second revoke succeeds and keeps the first time.
	if err := r.Revoke(ctx, "acme", "d1", at.Add(time.Hour)); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	got, err := r.Get(ctx, "acme", "d1")
	if err != nil {
		t.Fatalf("Get after revoke: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(at) || got.Active() {
		t.Fatalf("revoked record = %+v; want RevokedAt %v", got, at)
	}
	active, err := r.IsActive(ctx, "acme", "d1")
	if err != nil || active {
		t.Fatalf("IsActive after revoke = %v, %v; want false", active, err)
	}
	// A revoked ID stays taken: re-pairing needs a new ID.
	if err := r.Pair(ctx, "acme", testDevice("d1")); !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("Pair over a revoked device = %v; want ErrDeviceExists", err)
	}
	if err := r.Revoke(ctx, "acme", "missing", at); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("Revoke missing = %v; want ErrDeviceNotFound", err)
	}
	if err := r.Revoke(ctx, "acme", "d1", time.Time{}); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("Revoke at zero time = %v; want ErrInvalidDevice", err)
	}
}

func TestIsActive(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	if err := r.Pair(ctx, "acme", testDevice("d1")); err != nil {
		t.Fatal(err)
	}
	if active, err := r.IsActive(ctx, "acme", "d1"); err != nil || !active {
		t.Fatalf("IsActive = %v, %v; want true", active, err)
	}
	if active, err := r.IsActive(ctx, "acme", "missing"); active || !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("IsActive missing = %v, %v; want ErrDeviceNotFound", active, err)
	}
}

func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	if err := r.Pair(ctx, "tenant-b", testDevice("d1")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, "tenant-a", "d1"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("tenant A read tenant B's device: %v", err)
	}
	if err := r.Revoke(ctx, "tenant-a", "d1", pairedAt); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("tenant A revoked tenant B's device: %v", err)
	}
	if active, err := r.IsActive(ctx, "tenant-b", "d1"); err != nil || !active {
		t.Fatalf("tenant B's device after tenant A's revoke = %v, %v; want active", active, err)
	}
	devices, err := r.List(ctx, "tenant-a")
	if err != nil || len(devices) != 0 {
		t.Fatalf("tenant A lists %v, %v; want none", devices, err)
	}
}

func TestEmptyTenantRefused(t *testing.T) {
	ctx := context.Background()
	r := newTestRegistry(t)
	if _, err := r.Get(ctx, "", "d1"); !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("Get = %v", err)
	}
	if _, err := r.List(ctx, ""); !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("List = %v", err)
	}
	if err := r.Revoke(ctx, "", "d1", pairedAt); !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("Revoke = %v", err)
	}
	if _, err := r.IsActive(ctx, "", "d1"); !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("IsActive = %v", err)
	}
	if _, err := r.List(ctx, "bad/tenant"); !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("List with a malformed tenant = %v", err)
	}
}

func TestValidateID(t *testing.T) {
	for _, id := range []string{"a", "pixel-8", "A.b_c-9", strings.Repeat("x", maxIDLen)} {
		if err := ValidateID(id); err != nil {
			t.Errorf("ValidateID(%q) = %v; want nil", id, err)
		}
	}
	for _, id := range []string{"", ".", "..", "a/b", `a\b`, "a b", "a:b", "é", "a\x00", strings.Repeat("x", maxIDLen+1)} {
		if err := ValidateID(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("ValidateID(%q) = %v; want ErrInvalidID", id, err)
		}
	}
	r := newTestRegistry(t)
	if _, err := r.Get(context.Background(), "acme", ".."); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("Get with bad ID = %v", err)
	}
}

func TestStoreFailures(t *testing.T) {
	ctx := context.Background()
	kv := newFaultKV()
	r, err := NewRegistry(dao.NewStoreFactory(kv))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Pair(ctx, "acme", testDevice("d1")); err != nil {
		t.Fatal(err)
	}
	kv.failReads = true
	var storeErr *StoreError
	if _, err := r.Get(ctx, "acme", "d1"); !errors.As(err, &storeErr) || !errors.Is(err, kv.err) {
		t.Fatalf("Get on a failing store = %v; want a *StoreError", err)
	}
	if _, err := r.List(ctx, "acme"); !errors.As(err, &storeErr) {
		t.Fatalf("List on a failing store = %v; want a *StoreError", err)
	}
	if err := r.Pair(ctx, "acme", testDevice("d2")); !errors.As(err, &storeErr) {
		t.Fatalf("Pair on a failing read = %v; want a *StoreError", err)
	}
	kv.failReads = false
	kv.failWrites = true
	if err := r.Pair(ctx, "acme", testDevice("d2")); !errors.As(err, &storeErr) || storeErr.Op != "pair" {
		t.Fatalf("Pair on a failing write = %v; want a *StoreError", err)
	}
	if err := r.Revoke(ctx, "acme", "d1", pairedAt); !errors.As(err, &storeErr) || storeErr.Op != "revoke" {
		t.Fatalf("Revoke on a failing write = %v; want a *StoreError", err)
	}
	if storeErr.Error() == "" || storeErr.Unwrap() != kv.err {
		t.Fatalf("StoreError = %q, %v", storeErr.Error(), storeErr.Unwrap())
	}
}
