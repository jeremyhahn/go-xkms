package webauthn

import (
	"context"
	"errors"
	"testing"

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// errCredentialTenantBound is what systemOnlyKV returns for a credential
// DAO call that carries a non-system tenant binding: production's
// Node.ServiceContext keeps the explicit binding while acting as the system
// service principal, and qrdb's ScopeSelf check refuses it.
var errCredentialTenantBound = errors.New("credential store called with a non-system tenant binding")

// systemOnlyKV is a credential KV store that refuses every call whose ctx
// binds a tenant other than system, as the production datastore does under
// RBAC.
type systemOnlyKV struct {
	qrdbsdk.KVStore
}

func (k systemOnlyKV) QueryIndex(ctx context.Context, name string, v []byte) ([][]byte, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.KVStore.QueryIndex(ctx, name, v)
}

func (k systemOnlyKV) ScanIndex(ctx context.Context, name string, start, end []byte) (map[string][][]byte, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.KVStore.ScanIndex(ctx, name, start, end)
}

func (k systemOnlyKV) check(ctx context.Context) error {
	if id, ok := qrdbtenant.IDFromContext(ctx); ok && id != "system" {
		return errCredentialTenantBound
	}
	return nil
}

func (k systemOnlyKV) Put(ctx context.Context, key string, v []byte) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.KVStore.Put(ctx, key, v)
}

func (k systemOnlyKV) Get(ctx context.Context, key string) ([]byte, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.KVStore.Get(ctx, key)
}

func (k systemOnlyKV) Delete(ctx context.Context, key string) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.KVStore.Delete(ctx, key)
}

func (k systemOnlyKV) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.KVStore.Scan(ctx, prefix, fn)
}

func (k systemOnlyKV) List(ctx context.Context, prefix string) ([]string, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.KVStore.List(ctx, prefix)
}

func (k systemOnlyKV) Exists(ctx context.Context, key string) (bool, error) {
	if err := k.check(ctx); err != nil {
		return false, err
	}
	return k.KVStore.Exists(ctx, key)
}

// TestQRDBAdapter_NonSystemTenant_CredentialCallsUnbound pins that the
// tenant the store binds for its user-service calls never reaches the
// credential store, which runs as the system service principal: a
// non-system store (or a caller-bound invite tenant) must still read and
// delete credentials (Codex P1 on #2296).
func TestQRDBAdapter_NonSystemTenant_CredentialCallsUnbound(t *testing.T) {
	kv := systemOnlyKV{KVStore: qrdbsdk.NewMemoryKVStore()}
	factory := qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return kv })

	for _, tc := range []struct {
		name      string
		storeTID  string
		callerTID string
	}{
		{name: "store tenant", storeTID: "acme"},
		{name: "caller-bound invite tenant", storeTID: "system", callerTID: "acme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			us, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
				Users: newFakeUserClient(), DAOFactory: factory, TenantID: tc.storeTID,
			})
			if err != nil {
				t.Fatalf("adapter: %v", err)
			}
			ctx := context.Background()
			if tc.callerTID != "" {
				ctx = qrdbtenant.WithTenantID(ctx, tc.callerTID)
			}
			u, err := us.Create(ctx, "user@acme.example", "User")
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if _, err := us.GetByID(ctx, u.WebAuthnID()); err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if _, err := us.GetByEmail(ctx, "user@acme.example"); err != nil {
				t.Fatalf("GetByEmail: %v", err)
			}
			if err := us.Delete(ctx, u.WebAuthnID()); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		})
	}
}
