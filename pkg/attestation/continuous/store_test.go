package continuous

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
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
	const tenant, want = "acme", 1000
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
		for i := 0; i < 3*want; i++ {
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

// TestStore_ListVerdictsPage pages a device's history oldest first, caps the
// page at MaxVerdictPageSize and refuses a negative offset or limit.
func TestStore_ListVerdictsPage(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)
	const n = MaxVerdictPageSize + 7
	for i := range n {
		v := Verdict{Tenant: "acme", DeviceID: "dev-1", Verified: true, At: at.Add(time.Duration(i) * time.Second)}
		if err := store.SaveVerdict(ctx, v); err != nil {
			t.Fatalf("SaveVerdict %d: %v", i, err)
		}
	}

	def, err := store.ListVerdictsPage(ctx, "acme", "dev-1", 0, 0)
	if err != nil {
		t.Fatalf("default page: %v", err)
	}
	if len(def.Verdicts) != DefaultVerdictPageSize || def.Total != n || !def.Verdicts[0].At.Equal(at) {
		t.Fatalf("default page: %d verdicts, total %d, first %v", len(def.Verdicts), def.Total, def.Verdicts[0].At)
	}

	capped, err := store.ListVerdictsPage(ctx, "acme", "dev-1", 0, n*2)
	if err != nil {
		t.Fatalf("capped page: %v", err)
	}
	if len(capped.Verdicts) != MaxVerdictPageSize {
		t.Fatalf("capped page: %d verdicts, want %d", len(capped.Verdicts), MaxVerdictPageSize)
	}

	var seen int
	for offset := 0; offset < n; offset += 200 {
		page, err := store.ListVerdictsPage(ctx, "acme", "dev-1", offset, 200)
		if err != nil {
			t.Fatalf("page at %d: %v", offset, err)
		}
		for j, v := range page.Verdicts {
			if want := at.Add(time.Duration(offset+j) * time.Second); !v.At.Equal(want) {
				t.Fatalf("page at %d item %d at %v, want %v", offset, j, v.At, want)
			}
		}
		seen += len(page.Verdicts)
	}
	if seen != n {
		t.Fatalf("paged %d verdicts, want %d", seen, n)
	}

	past, err := store.ListVerdictsPage(ctx, "acme", "dev-1", n, 10)
	if err != nil || len(past.Verdicts) != 0 || past.Total != n {
		t.Fatalf("past the end: %+v, %v", past, err)
	}

	var inputErr *InputError
	if _, err := store.ListVerdictsPage(ctx, "acme", "dev-1", -1, 10); !errors.As(err, &inputErr) || inputErr.Field != "offset" {
		t.Fatalf("negative offset: %v, want InputError on offset", err)
	}
	if _, err := store.ListVerdictsPage(ctx, "acme", "dev-1", 0, -1); !errors.As(err, &inputErr) || inputErr.Field != "limit" {
		t.Fatalf("negative limit: %v, want InputError on limit", err)
	}
}

// countingRecords counts the stored records a read loads through the
// store's DAO seam.
type countingRecords struct {
	verdictRecords
	reads int
}

func (c *countingRecords) GetByNaturalKey(ctx context.Context, key string) (*verdictEntity, error) {
	c.reads++
	return c.verdictRecords.GetByNaturalKey(ctx, key)
}

func TestStore_PageAndLatestReadBoundedRecords(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)
	const n = 300
	for i := range n {
		v := Verdict{Tenant: "acme", DeviceID: "dev-1", Verified: true, At: at.Add(time.Duration(i) * time.Second)}
		if err := store.SaveVerdict(ctx, v); err != nil {
			t.Fatalf("SaveVerdict %d: %v", i, err)
		}
	}
	counter := &countingRecords{verdictRecords: store.records}
	store.records = counter

	const limit, offset = 10, 120
	page, err := store.ListVerdictsPage(ctx, "acme", "dev-1", offset, limit)
	if err != nil {
		t.Fatalf("ListVerdictsPage: %v", err)
	}
	if counter.reads > limit+1 {
		t.Fatalf("page read %d records, want at most %d", counter.reads, limit+1)
	}
	if page.Total != n || len(page.Verdicts) != limit {
		t.Fatalf("page: %d verdicts, total %d", len(page.Verdicts), page.Total)
	}
	for j, v := range page.Verdicts {
		if want := at.Add(time.Duration(offset+j) * time.Second); !v.At.Equal(want) {
			t.Fatalf("page item %d at %v, want %v", j, v.At, want)
		}
	}

	counter.reads = 0
	latest, err := store.LatestVerdict(ctx, "acme", "dev-1")
	if err != nil {
		t.Fatalf("LatestVerdict: %v", err)
	}
	if counter.reads > 2 {
		t.Fatalf("latest read %d records, want at most 2", counter.reads)
	}
	if want := at.Add((n - 1) * time.Second); !latest.At.Equal(want) {
		t.Fatalf("latest at %v, want %v", latest.At, want)
	}

	counter.reads = 0
	if _, err := store.LatestVerdict(ctx, "acme", "dev-2"); err == nil {
		t.Fatal("LatestVerdict of an unknown device: want VerdictNotFoundError")
	}
	if counter.reads > 1 {
		t.Fatalf("unknown device read %d records, want at most 1", counter.reads)
	}
}

// scanGuardKV is the backing store of a test that must not walk a
// collection: once armed, every Scan or List through it fails the test. It
// embeds the memory store so the index, atomic and batch capabilities the
// DAO asserts for stay visible.
type scanGuardKV struct {
	*qrdbsdk.MemoryKVStore
	t     testing.TB
	armed atomic.Bool
}

func (s *scanGuardKV) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	if s.armed.Load() {
		s.t.Errorf("collection-wide Scan(%q) after fixture setup", prefix)
	}
	return s.MemoryKVStore.Scan(ctx, prefix, fn)
}

func (s *scanGuardKV) List(ctx context.Context, prefix string) ([]string, error) {
	if s.armed.Load() {
		s.t.Errorf("collection-wide List(%q) after fixture setup", prefix)
	}
	return s.MemoryKVStore.List(ctx, prefix)
}

// TestStore_ReadsUseDeviceIndex reads one device's verdicts through the
// device index, never by scanning every tenant's history (Codex P2, #2111).
func TestStore_ReadsUseDeviceIndex(t *testing.T) {
	kv := &scanGuardKV{MemoryKVStore: qrdbsdk.NewMemoryKVStore(), t: t}
	store, err := NewStore(StoreConfig{DAOs: dao.NewStoreFactory(kv)})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
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
	kv.armed.Store(true)
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

func TestStore_ConcurrentStoresOverOneDatastoreKeepEveryVerdict(t *testing.T) {
	f := testutil.NewMemoryDAOFactory()
	newStore := func() *Store {
		s, err := NewStore(StoreConfig{DAOs: f})
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		return s
	}
	stores := []*Store{newStore(), newStore()}
	const perStore = 200
	ctx := context.Background()
	base := time.Unix(1_700_000_000, 0).UTC()
	at := func(g, i int) time.Time { return base.Add(time.Duration(g*perStore+i) * time.Second) }
	start := make(chan struct{})
	errs := make(chan error, len(stores)*perStore)
	var wg sync.WaitGroup
	for g, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := range perStore {
				errs <- s.SaveVerdict(ctx, Verdict{Tenant: "acme", DeviceID: "dev-1", Verified: true, At: at(g, i)})
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("SaveVerdict: %v", err)
		}
	}
	reader := newStore()
	list, err := reader.ListVerdicts(ctx, "acme", "dev-1")
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	want := len(stores) * perStore
	if len(list) != want {
		t.Fatalf("ListVerdicts returned %d verdicts, want %d", len(list), want)
	}
	seen := make(map[int64]bool, want)
	for _, v := range list {
		if seen[v.At.UnixNano()] {
			t.Fatalf("verdict at %v listed twice", v.At)
		}
		seen[v.At.UnixNano()] = true
	}
	for g := range stores {
		for i := range perStore {
			if !seen[at(g, i).UnixNano()] {
				t.Fatalf("verdict at %v lost", at(g, i))
			}
		}
	}
	page, err := reader.ListVerdictsPage(ctx, "acme", "dev-1", 0, 1)
	if err != nil || page.Total != want {
		t.Fatalf("ListVerdictsPage Total = %d, %v; want %d", page.Total, err, want)
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
