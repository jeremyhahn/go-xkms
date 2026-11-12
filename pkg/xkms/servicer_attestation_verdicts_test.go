package xkms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/continuous"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func newVerdictStore(t *testing.T) *continuous.Store {
	t.Helper()
	store, err := continuous.NewStore(continuous.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// verdictTenantContext returns a context whose caller belongs to tenant.
func verdictTenantContext(tenant string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{TenantID: tenant})
}

// verdictSource returns a fixed quote request for every device.
type verdictSource struct{}

func (verdictSource) Collect(_ context.Context, _, _ string, _ []byte) (*appraisal.AppraiseQuoteRequest, error) {
	return &appraisal.AppraiseQuoteRequest{}, nil
}

// verdictAppraiser verifies every quote while verified is true.
type verdictAppraiser struct{ verified bool }

func (a verdictAppraiser) AppraiseQuote(_ context.Context, _ string, _ *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error) {
	return &appraisal.AttestationResult{Verified: a.verified}, nil
}

// verdictClock hands out strictly increasing times.
type verdictClock struct{ now time.Time }

func (c *verdictClock) Now() time.Time {
	c.now = c.now.Add(time.Second)
	return c.now
}

func newVerdictService(t *testing.T, withEngine bool, verified bool) *XKMSService {
	t.Helper()
	store := newVerdictStore(t)
	var engine *continuous.Engine
	if withEngine {
		clock := &verdictClock{now: time.Unix(1_700_000_000, 0)}
		var err error
		engine, err = continuous.NewEngine(continuous.Config{
			Store:     store,
			Source:    verdictSource{},
			Appraiser: verdictAppraiser{verified: verified},
			Now:       clock.Now,
		})
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
	}
	svc := &XKMSService{}
	svc.SetContinuousAttestation(engine, store)
	return svc
}

func TestAttestationVerdicts_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	ctx := verdictTenantContext("tenant-a")
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	if _, err := svc.ListAttestationVerdicts(ctx, req); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("List: got %v, want ErrNotConfigured", err)
	}
	if _, err := svc.GetLatestAttestationVerdict(ctx, req); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Latest: got %v, want ErrNotConfigured", err)
	}
	if _, err := svc.ReattestDevice(ctx, req); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Reattest: got %v, want ErrNotConfigured", err)
	}
}

func TestAttestationVerdicts_StoreWithoutEngine(t *testing.T) {
	svc := newVerdictService(t, false, true)
	ctx := verdictTenantContext("tenant-a")
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	if _, err := svc.ReattestDevice(ctx, req); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Reattest: got %v, want ErrNotConfigured", err)
	}
	resp, err := svc.ListAttestationVerdicts(ctx, req)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Verdicts) != 0 {
		t.Fatalf("List: got %d verdicts, want 0", len(resp.Verdicts))
	}
}

func TestAttestationVerdicts_EmptyDeviceID(t *testing.T) {
	svc := newVerdictService(t, true, true)
	ctx := verdictTenantContext("tenant-a")
	req := &transport.AttestationVerdictRequest{}
	var inputErr *continuous.InputError
	if _, err := svc.ListAttestationVerdicts(ctx, req); !errors.As(err, &inputErr) {
		t.Fatalf("List: got %v, want InputError", err)
	}
	if _, err := svc.GetLatestAttestationVerdict(ctx, req); !errors.As(err, &inputErr) {
		t.Fatalf("Latest: got %v, want InputError", err)
	}
	if _, err := svc.ReattestDevice(ctx, req); !errors.As(err, &inputErr) {
		t.Fatalf("Reattest: got %v, want InputError", err)
	}
	if _, err := svc.ListAttestationVerdicts(ctx, nil); !errors.As(err, &inputErr) {
		t.Fatalf("List nil: got %v, want InputError", err)
	}
}

func TestAttestationVerdicts_ReattestAndLatest(t *testing.T) {
	svc := newVerdictService(t, true, true)
	ctx := verdictTenantContext("tenant-a")
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}

	var notFound *continuous.VerdictNotFoundError
	if _, err := svc.GetLatestAttestationVerdict(ctx, req); !errors.As(err, &notFound) {
		t.Fatalf("Latest before re-attest: got %v, want VerdictNotFoundError", err)
	}

	first, err := svc.ReattestDevice(ctx, req)
	if err != nil {
		t.Fatalf("Reattest 1: %v", err)
	}
	if !first.Verified || first.Tenant != "tenant-a" || first.DeviceID != "dev-1" {
		t.Fatalf("Reattest 1: got %+v", first)
	}
	second, err := svc.ReattestDevice(ctx, req)
	if err != nil {
		t.Fatalf("Reattest 2: %v", err)
	}
	if !second.At.After(first.At) {
		t.Fatalf("Reattest 2 at %v is not after %v", second.At, first.At)
	}

	latest, err := svc.GetLatestAttestationVerdict(ctx, req)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if !latest.At.Equal(second.At) {
		t.Fatalf("Latest at %v, want %v", latest.At, second.At)
	}
	list, err := svc.ListAttestationVerdicts(ctx, req)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Verdicts) != 2 {
		t.Fatalf("List: got %d verdicts, want 2", len(list.Verdicts))
	}
}

func TestAttestationVerdicts_UnverifiedDevice(t *testing.T) {
	svc := newVerdictService(t, true, false)
	ctx := verdictTenantContext("tenant-a")
	v, err := svc.ReattestDevice(ctx, &transport.AttestationVerdictRequest{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("Reattest: %v", err)
	}
	if v.Verified || v.Cause == "" {
		t.Fatalf("Reattest: got %+v, want an unverified verdict with a cause", v)
	}
}

func TestAttestationVerdicts_TenantIsolation(t *testing.T) {
	svc := newVerdictService(t, true, true)
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	if _, err := svc.ReattestDevice(verdictTenantContext("tenant-a"), req); err != nil {
		t.Fatalf("Reattest as tenant A: %v", err)
	}

	ctxB := verdictTenantContext("tenant-b")
	var notFound *continuous.VerdictNotFoundError
	if _, err := svc.GetLatestAttestationVerdict(ctxB, req); !errors.As(err, &notFound) {
		t.Fatalf("Latest as tenant B: got %v, want VerdictNotFoundError", err)
	}
	list, err := svc.ListAttestationVerdicts(ctxB, req)
	if err != nil {
		t.Fatalf("List as tenant B: %v", err)
	}
	if len(list.Verdicts) != 0 {
		t.Fatalf("List as tenant B: got %d verdicts, want 0", len(list.Verdicts))
	}
}
