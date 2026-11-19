package continuous

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func newTestStore(t testing.TB) *Store {
	t.Helper()
	store, err := NewStore(StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// TestStore_ListVerdictsNoDuplicatesUnderConcurrentAppends lists a device's
// history across a page boundary while another device's verdicts are
// appended; an append that lands before the boundary shifts records onto the
// next page, and none may be returned twice.
func TestStore_ListVerdictsNoDuplicatesUnderConcurrentAppends(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	const tenant, want = "acme", listPageSize
	for i := 0; i < want; i++ {
		v := Verdict{Tenant: tenant, DeviceID: "dev-1", At: base.Add(time.Duration(i) * time.Millisecond)}
		if err := store.SaveVerdict(ctx, v); err != nil {
			t.Fatalf("SaveVerdict %d: %v", i, err)
		}
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		defer close(done)
		for i := 0; i < 3*listPageSize; i++ {
			select {
			case <-stop:
				return
			default:
			}
			v := Verdict{Tenant: tenant, DeviceID: "dev-0", At: base.Add(time.Duration(i) * time.Microsecond)}
			if err := store.SaveVerdict(ctx, v); err != nil {
				done <- err
				return
			}
		}
	}()
	defer func() {
		close(stop)
		if err := <-done; err != nil {
			t.Errorf("concurrent SaveVerdict: %v", err)
		}
	}()
	for round := 0; round < 20; round++ {
		verdicts, err := store.ListVerdicts(ctx, tenant, "dev-1")
		if err != nil {
			t.Fatalf("round %d: ListVerdicts: %v", round, err)
		}
		seen := make(map[time.Time]bool, len(verdicts))
		for _, v := range verdicts {
			if seen[v.At] {
				t.Fatalf("round %d: verdict at %s returned twice", round, v.At)
			}
			seen[v.At] = true
		}
		if len(verdicts) != want {
			t.Fatalf("round %d: %d verdicts, want %d", round, len(verdicts), want)
		}
	}
}

func TestNewStore_RequiresDAOs(t *testing.T) {
	var ce *ConfigError
	if _, err := NewStore(StoreConfig{}); !errors.As(err, &ce) {
		t.Fatalf("NewStore(nil DAOs) = %v, want a *ConfigError", err)
	}
}

func TestStore_LatestAndList(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)
	for i, verified := range []bool{true, false, true} {
		v := Verdict{Tenant: "acme", DeviceID: "dev-1", Verified: verified, At: at.Add(time.Duration(i) * time.Minute)}
		if !verified {
			v.Cause = "pcr mismatch"
		}
		if err := store.SaveVerdict(ctx, v); err != nil {
			t.Fatalf("SaveVerdict %d: %v", i, err)
		}
	}
	list, err := store.ListVerdicts(ctx, "acme", "dev-1")
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	if len(list) != 3 || list[1].Cause != "pcr mismatch" || !list[0].At.Before(list[2].At) {
		t.Fatalf("ListVerdicts = %+v, want three verdicts oldest first", list)
	}
	latest, err := store.LatestVerdict(ctx, "acme", "dev-1")
	if err != nil {
		t.Fatalf("LatestVerdict: %v", err)
	}
	if !latest.At.Equal(at.Add(2 * time.Minute)) {
		t.Fatalf("LatestVerdict at %v, want the newest", latest.At)
	}
}

// noScanDAO refuses a collection-wide page scan, so a read that walks
// every tenant's verdicts fails.
type noScanDAO struct {
	qrdbsdk.GenericDAO[*verdictEntity]
}

func (noScanDAO) ForEachPage(context.Context, qrdbsdk.PageQuery, qrdbsdk.PagerFunc[*verdictEntity]) error {
	return errors.New("collection-wide scan")
}

// TestStore_ReadsUseDeviceIndex reads one device's verdicts through the
// device index, never by scanning every tenant's history (Codex P2, #2111).
func TestStore_ReadsUseDeviceIndex(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)
	for i, v := range []Verdict{
		{Tenant: "acme", DeviceID: "dev-1", Verified: true, At: at},
		{Tenant: "acme", DeviceID: "dev-2", Verified: true, At: at},
		{Tenant: "other", DeviceID: "dev-1", Verified: true, At: at},
		{Tenant: "acme", DeviceID: "dev-1", Verified: false, Cause: "pcr mismatch", At: at.Add(time.Minute)},
	} {
		if err := store.SaveVerdict(ctx, v); err != nil {
			t.Fatalf("SaveVerdict %d: %v", i, err)
		}
	}
	store.records = noScanDAO{store.records}
	list, err := store.ListVerdicts(ctx, "acme", "dev-1")
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	if len(list) != 2 || list[0].Tenant != "acme" || list[1].Cause != "pcr mismatch" {
		t.Fatalf("ListVerdicts = %+v, want acme/dev-1's two verdicts oldest first", list)
	}
	latest, err := store.LatestVerdict(ctx, "acme", "dev-1")
	if err != nil {
		t.Fatalf("LatestVerdict: %v", err)
	}
	if latest.Cause != "pcr mismatch" {
		t.Fatalf("LatestVerdict = %+v, want the newest", latest)
	}
}

func TestStore_TenantIsolation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)
	if err := store.SaveVerdict(ctx, Verdict{Tenant: "acme", DeviceID: "dev-1", Verified: true, At: at}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveVerdict(ctx, Verdict{Tenant: "acme", DeviceID: "dev-10", Verified: true, At: at}); err != nil {
		t.Fatal(err)
	}
	var nf *VerdictNotFoundError
	if _, err := store.LatestVerdict(ctx, "globex", "dev-1"); !errors.As(err, &nf) || nf.Error() == "" {
		t.Fatalf("other tenant LatestVerdict = %v, want *VerdictNotFoundError", err)
	}
	list, err := store.ListVerdicts(ctx, "globex", "dev-1")
	if err != nil || len(list) != 0 {
		t.Fatalf("other tenant ListVerdicts = %+v, %v; want none", list, err)
	}
	list, err = store.ListVerdicts(ctx, "acme", "dev-1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListVerdicts(dev-1) = %+v, %v; want only dev-1, not dev-10", list, err)
	}
}

func TestStore_RefusesInvalidInput(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	at := time.Now()
	if err := store.SaveVerdict(ctx, Verdict{Tenant: "", DeviceID: "dev-1", At: at}); err == nil {
		t.Fatal("empty tenant saved")
	}
	if err := store.SaveVerdict(ctx, Verdict{Tenant: "acme", DeviceID: "", At: at}); err == nil {
		t.Fatal("empty device saved")
	}
	if err := store.SaveVerdict(ctx, Verdict{Tenant: "acme", DeviceID: "dev-1"}); err == nil {
		t.Fatal("verdict without a time saved")
	}
	if _, err := store.LatestVerdict(ctx, "acme", "a/b"); err == nil {
		t.Fatal("device with a slash accepted")
	}
	if _, err := store.ListVerdicts(ctx, "", "dev-1"); err == nil {
		t.Fatal("empty tenant listed")
	}
	if _, err := store.ListVerdicts(ctx, "acme", strings.Repeat("d", maxDeviceIDLen+1)); err == nil {
		t.Fatal("over-long device ID accepted")
	}
	if _, err := store.ListVerdicts(ctx, "acme", "dev\x01"); err == nil {
		t.Fatal("device ID with a control character accepted")
	}
	if _, err := store.ListVerdicts(ctx, "a/b", "dev-1"); err == nil {
		t.Fatal("tenant with a slash accepted")
	}
}

func TestErrors_Messages(t *testing.T) {
	cause := errors.New("boom")
	for _, err := range []error{
		&ConfigError{Field: "Store", Reason: "is required"},
		&ConfigError{Field: "DAOs", Reason: "cannot open", Cause: cause},
		&StoreError{Op: "save", Key: "k", Err: cause},
		&VerdictNotFoundError{Tenant: "acme", DeviceID: "dev-1"},
		&InputError{Field: "tenant", Cause: cause},
	} {
		if err.Error() == "" {
			t.Fatalf("%T has an empty message", err)
		}
	}
	if !errors.Is(&ConfigError{Cause: cause}, cause) || !errors.Is(&StoreError{Err: cause}, cause) || !errors.Is(&InputError{Cause: cause}, cause) {
		t.Fatal("errors do not unwrap to their cause")
	}
}
