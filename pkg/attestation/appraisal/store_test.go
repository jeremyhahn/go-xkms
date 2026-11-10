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

package appraisal

import (
	"context"
	"errors"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// faultKV is an in-memory KV store whose reads or writes can be made to fail.
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

func newTestStore(t testing.TB) *Store {
	t.Helper()
	store, err := NewStore(StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestNewStore(t *testing.T) {
	if store, err := NewStore(StoreConfig{DAOs: testutil.NewMemoryDAOFactory()}); err != nil || store == nil {
		t.Fatalf("NewStore = %v, %v", store, err)
	}
	store, err := NewStore(StoreConfig{})
	var config *ConfigError
	if store != nil || !errors.As(err, &config) || config.Field != "DAOs" || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewStore with no DAOs = %v, %v; want a *ConfigError on DAOs", store, err)
	}
}

func TestValidateName(t *testing.T) {
	for _, name := range []string{"golden", "a.b-c_d", strings.Repeat("n", maxNameLen)} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", "a/b", "/", ".", "..", strings.Repeat("n", maxNameLen+1)} {
		err := ValidateName(name)
		var invalid *NameError
		if !errors.As(err, &invalid) || invalid.Name != name || !errors.Is(err, ErrInvalidName) {
			t.Errorf("ValidateName(%q) = %v, want a *NameError", name, err)
		}
	}
}

func TestStore_Endorsements(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	for _, name := range []string{"b", "a"} {
		if err := store.PutEndorsement(ctx, "acme", &Endorsement{Name: name, Kind: EndorsementAKRoot, CertificatePEM: []byte(name)}); err != nil {
			t.Fatalf("PutEndorsement %s: %v", name, err)
		}
	}
	// Putting a name again replaces its record.
	if err := store.PutEndorsement(ctx, "acme", &Endorsement{Name: "a", Kind: EndorsementReferenceSigner, PublicKeyPEM: []byte("key")}); err != nil {
		t.Fatalf("PutEndorsement replace: %v", err)
	}
	list, err := store.ListEndorsements(ctx, "acme")
	if err != nil || len(list) != 2 || list[0].Name != "a" || list[1].Name != "b" {
		t.Fatalf("ListEndorsements = %+v, %v; want a then b", list, err)
	}
	if list[0].Kind != EndorsementReferenceSigner || string(list[0].PublicKeyPEM) != "key" {
		t.Fatalf("replaced endorsement = %+v", list[0])
	}
	if err := store.DeleteEndorsement(ctx, "acme", "a"); err != nil {
		t.Fatalf("DeleteEndorsement: %v", err)
	}
	var missing *RecordNotFoundError
	if err := store.DeleteEndorsement(ctx, "acme", "a"); !errors.As(err, &missing) || missing.Kind != "endorsement" || !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("DeleteEndorsement twice = %v, want a *RecordNotFoundError", err)
	}
	if list, err := store.ListEndorsements(ctx, "acme"); err != nil || len(list) != 1 {
		t.Fatalf("ListEndorsements after delete = %+v, %v", list, err)
	}
}

func TestStore_ReferenceValues(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	for _, name := range []string{"golden", "baseline"} {
		if err := store.PutReferenceValues(ctx, "acme", &ReferenceValues{Name: name, SignedCoRIM: []byte(name)}); err != nil {
			t.Fatalf("PutReferenceValues %s: %v", name, err)
		}
	}
	got, err := store.GetReferenceValues(ctx, "acme", "golden")
	if err != nil || got.Name != "golden" || string(got.SignedCoRIM) != "golden" {
		t.Fatalf("GetReferenceValues = %+v, %v", got, err)
	}
	list, err := store.ListReferenceValues(ctx, "acme")
	if err != nil || len(list) != 2 || list[0].Name != "baseline" || list[1].Name != "golden" {
		t.Fatalf("ListReferenceValues = %+v, %v; want baseline then golden", list, err)
	}
	if err := store.DeleteReferenceValues(ctx, "acme", "golden"); err != nil {
		t.Fatalf("DeleteReferenceValues: %v", err)
	}
	var missing *RecordNotFoundError
	if _, err := store.GetReferenceValues(ctx, "acme", "golden"); !errors.As(err, &missing) || missing.Kind != "reference values" {
		t.Fatalf("GetReferenceValues after delete = %v, want a *RecordNotFoundError", err)
	}
	if err := store.DeleteReferenceValues(ctx, "acme", "golden"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("DeleteReferenceValues twice = %v, want ErrRecordNotFound", err)
	}
}

// seedStoredRecord saves record under name straight through the collection's
// DAO, keyed as put keys it, without the write rule: a record stored before
// that rule refused the name.
func seedStoredRecord[T any](t testing.TB, c collection[T], tenant, name string, record T) {
	t.Helper()
	prefix, err := c.prefix(tenant)
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	if err := c.records.Save(context.Background(), &recordEntity[T]{Key: prefix + name, Record: record}); err != nil {
		t.Fatalf("seed %q: %v", name, err)
	}
}

// TestStoreDeletesRecordsNamedBeforeTheDotRule is the upgrade regression: an
// endorsement or reference-values record named "." or ".." was accepted
// before ValidateName refused those names. It is still listed, so it must
// still be deletable, while a new write under such a name stays refused.
func TestStoreDeletesRecordsNamedBeforeTheDotRule(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{".", ".."} {
		t.Run(name, func(t *testing.T) {
			store := newTestStore(t)
			seedStoredRecord(t, store.endorsements, "acme", name, Endorsement{Name: name, Kind: EndorsementAKRoot, CertificatePEM: []byte("pem")})
			seedStoredRecord(t, store.referenceValues, "acme", name, ReferenceValues{Name: name, SignedCoRIM: []byte("corim")})

			if list, err := store.ListEndorsements(ctx, "acme"); err != nil || len(list) != 1 || list[0].Name != name {
				t.Fatalf("ListEndorsements = %+v, %v; want the stored %q", list, err, name)
			}
			if list, err := store.ListReferenceValues(ctx, "acme"); err != nil || len(list) != 1 || list[0].Name != name {
				t.Fatalf("ListReferenceValues = %+v, %v; want the stored %q", list, err, name)
			}

			if err := store.DeleteEndorsement(ctx, "acme", name); err != nil {
				t.Fatalf("DeleteEndorsement(%q) = %v, want the stored record deleted", name, err)
			}
			if err := store.DeleteReferenceValues(ctx, "acme", name); err != nil {
				t.Fatalf("DeleteReferenceValues(%q) = %v, want the stored record deleted", name, err)
			}
			if list, err := store.ListEndorsements(ctx, "acme"); err != nil || len(list) != 0 {
				t.Fatalf("ListEndorsements after delete = %+v, %v", list, err)
			}
			if list, err := store.ListReferenceValues(ctx, "acme"); err != nil || len(list) != 0 {
				t.Fatalf("ListReferenceValues after delete = %+v, %v", list, err)
			}

			// A new write under the name stays refused.
			if err := store.PutEndorsement(ctx, "acme", &Endorsement{Name: name}); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("PutEndorsement(%q) = %v, want ErrInvalidName", name, err)
			}
			if err := store.PutReferenceValues(ctx, "acme", &ReferenceValues{Name: name}); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("PutReferenceValues(%q) = %v, want ErrInvalidName", name, err)
			}
		})
	}
}

func TestStore_RefusesInvalidInput(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	if err := store.PutEndorsement(ctx, "acme", nil); !errors.Is(err, ErrNilRequest) {
		t.Errorf("PutEndorsement(nil) = %v", err)
	}
	if err := store.PutReferenceValues(ctx, "acme", nil); !errors.Is(err, ErrNilRequest) {
		t.Errorf("PutReferenceValues(nil) = %v", err)
	}
	if err := store.PutEndorsement(ctx, "acme", &Endorsement{Name: "a/b"}); !errors.Is(err, ErrInvalidName) {
		t.Errorf("PutEndorsement a/b = %v, want ErrInvalidName", err)
	}
	if _, err := store.GetReferenceValues(ctx, "acme", ""); !errors.Is(err, ErrInvalidName) {
		t.Errorf("GetReferenceValues empty name = %v, want ErrInvalidName", err)
	}
	for _, tenant := range []string{"a/b", "..", "a\x00b"} {
		checks := map[string]error{
			"PutEndorsement":        store.PutEndorsement(ctx, tenant, &Endorsement{Name: "n"}),
			"DeleteEndorsement":     store.DeleteEndorsement(ctx, tenant, "n"),
			"PutReferenceValues":    store.PutReferenceValues(ctx, tenant, &ReferenceValues{Name: "n"}),
			"DeleteReferenceValues": store.DeleteReferenceValues(ctx, tenant, "n"),
		}
		_, checks["ListEndorsements"] = store.ListEndorsements(ctx, tenant)
		_, checks["GetReferenceValues"] = store.GetReferenceValues(ctx, tenant, "n")
		_, checks["ListReferenceValues"] = store.ListReferenceValues(ctx, tenant)
		for op, err := range checks {
			var invalid *TenantError
			if !errors.As(err, &invalid) || invalid.Tenant != tenant || !errors.Is(err, ErrInvalidTenant) {
				t.Errorf("%s for tenant %q = %v, want a *TenantError", op, tenant, err)
			}
		}
	}
}

func TestStore_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	if err := store.PutReferenceValues(ctx, "acme", &ReferenceValues{Name: "golden"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutEndorsement(ctx, "acme", &Endorsement{Name: "root"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetReferenceValues(ctx, "globex", "golden"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("globex read acme's reference values: %v", err)
	}
	if err := store.DeleteEndorsement(ctx, "globex", "root"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("globex deleted acme's endorsement: %v", err)
	}
	if list, err := store.ListReferenceValues(ctx, "globex"); err != nil || len(list) != 0 {
		t.Fatalf("globex listed %+v, %v", list, err)
	}
	// The empty tenant is the system tenant, a scope of its own.
	if err := store.PutEndorsement(ctx, "", &Endorsement{Name: "root"}); err != nil {
		t.Fatal(err)
	}
	system, err := store.ListEndorsements(ctx, scope.SystemTenant)
	if err != nil || len(system) != 1 {
		t.Fatalf("system tenant endorsements = %+v, %v", system, err)
	}
	if list, err := store.ListEndorsements(ctx, "acme"); err != nil || len(list) != 1 {
		t.Fatalf("acme endorsements = %+v, %v", list, err)
	}
}

func TestStore_ReportsStoreFailures(t *testing.T) {
	ctx := context.Background()
	kv := newFaultKV()
	store, err := NewStore(StoreConfig{DAOs: dao.NewStoreFactory(kv)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutEndorsement(ctx, "acme", &Endorsement{Name: "root"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutReferenceValues(ctx, "acme", &ReferenceValues{Name: "golden"}); err != nil {
		t.Fatal(err)
	}

	kv.failWrites = true
	writes := map[string]error{
		"PutEndorsement":        store.PutEndorsement(ctx, "acme", &Endorsement{Name: "x"}),
		"PutReferenceValues":    store.PutReferenceValues(ctx, "acme", &ReferenceValues{Name: "x"}),
		"DeleteEndorsement":     store.DeleteEndorsement(ctx, "acme", "root"),
		"DeleteReferenceValues": store.DeleteReferenceValues(ctx, "acme", "golden"),
	}
	kv.failWrites, kv.failReads = false, true
	reads := map[string]error{}
	_, reads["ListEndorsements"] = store.ListEndorsements(ctx, "acme")
	_, reads["GetReferenceValues"] = store.GetReferenceValues(ctx, "acme", "golden")
	_, reads["ListReferenceValues"] = store.ListReferenceValues(ctx, "acme")
	reads["DeleteEndorsement"] = store.DeleteEndorsement(ctx, "acme", "root")
	for _, checks := range []map[string]error{writes, reads} {
		for op, err := range checks {
			var failed *StoreError
			if !errors.As(err, &failed) || !errors.Is(err, ErrStoreUnavailable) || !errors.Is(err, kv.err) {
				t.Errorf("%s against a failing store = %v, want a *StoreError", op, err)
			}
		}
	}
}
