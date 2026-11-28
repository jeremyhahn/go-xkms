package continuous

import (
	"context"
	"crypto/rand"
	"io"
	"sort"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// NonceSize is the length of the fresh nonce each re-attestation issues.
const NonceSize = 32

// EvidenceSource fetches fresh TPM quote evidence from a device, quoted
// over nonce.
type EvidenceSource interface {
	Collect(ctx context.Context, tenant, deviceID string, nonce []byte) (*appraisal.AppraiseQuoteRequest, error)
}

// Appraiser appraises quote evidence; *appraisal.Appraiser implements it.
type Appraiser interface {
	AppraiseQuote(ctx context.Context, tenant string, req *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error)
}

// Publisher receives every verdict the engine reaches.
type Publisher interface {
	Publish(ctx context.Context, v Verdict)
}

// Inventory lists the registered tenants and their enrolled devices.
type Inventory interface {
	Tenants(ctx context.Context) ([]string, error)
	Devices(ctx context.Context, tenant string) ([]string, error)
}

// Ticker drives the scheduled passes; time.Ticker is adapted to it.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// Verdict is the outcome of one re-attestation of one device.
type Verdict struct {
	Tenant   string `json:"tenant"`
	DeviceID string `json:"device_id"`

	// Result is the verifier's appraisal, nil when no evidence reached it.
	Result *appraisal.AttestationResult `json:"result,omitempty"`

	// Verified is true only when the evidence was collected and passed
	// appraisal.
	Verified bool `json:"verified"`

	// At is when the verdict was reached.
	At time.Time `json:"at"`

	// Cause says why Verified is false; empty when it is true.
	Cause string `json:"cause,omitempty"`
}

// Config configures an Engine.
type Config struct {
	// Source fetches evidence. Required.
	Source EvidenceSource
	// Appraiser appraises it. Required.
	Appraiser Appraiser
	// Store keeps the verdicts. Required.
	Store *Store
	// Publishers each receive every verdict. Optional.
	Publishers []Publisher
	// Inventory lists the devices a scheduled pass visits. Required by Run
	// and Pass.
	Inventory Inventory
	// Interval is the time between scheduled passes. Required by Run.
	Interval time.Duration
	// NewTicker makes the pass ticker; defaults to a time.Ticker.
	NewTicker func(time.Duration) Ticker
	// Now is the clock; defaults to time.Now.
	Now func() time.Time
	// Rand is the nonce source; defaults to crypto/rand.
	Rand io.Reader
}

// Engine re-attests devices on demand (Reattest) and on a schedule (Run).
type Engine struct {
	cfg Config
}

// NewEngine checks cfg and fills its defaults.
func NewEngine(cfg Config) (*Engine, error) {
	switch {
	case cfg.Source == nil:
		return nil, &ConfigError{Field: "Source", Reason: "is required"}
	case cfg.Appraiser == nil:
		return nil, &ConfigError{Field: "Appraiser", Reason: "is required"}
	case cfg.Store == nil:
		return nil, &ConfigError{Field: "Store", Reason: "is required"}
	case cfg.Interval < 0:
		return nil, &ConfigError{Field: "Interval", Reason: "must not be negative"}
	}
	if cfg.NewTicker == nil {
		cfg.NewTicker = newTimeTicker
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	return &Engine{cfg: cfg}, nil
}

// Reattest re-attests one device now under a fresh nonce, stores the
// verdict and publishes it. Evidence that cannot be collected or appraised
// is an unverified verdict, not an error; the error reports only unusable
// input, a nonce failure or a store failure.
func (e *Engine) Reattest(ctx context.Context, tenant, deviceID string) (Verdict, error) {
	if _, err := devicePrefix(tenant, deviceID); err != nil {
		return Verdict{}, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(e.cfg.Rand, nonce); err != nil {
		return Verdict{}, &ConfigError{Field: "Rand", Reason: "cannot supply a nonce", Cause: err}
	}
	v := Verdict{Tenant: tenant, DeviceID: deviceID}
	v.Result, v.Cause = e.appraise(ctx, tenant, deviceID, nonce)
	v.Verified = v.Cause == ""
	v.At = e.cfg.Now()
	if err := e.cfg.Store.SaveVerdict(ctx, v); err != nil {
		return v, err
	}
	for _, p := range e.cfg.Publishers {
		p.Publish(ctx, v)
	}
	return v, nil
}

// appraise collects and appraises evidence, returning the result and, when
// the device is not verified, the cause.
func (e *Engine) appraise(ctx context.Context, tenant, deviceID string, nonce []byte) (*appraisal.AttestationResult, string) {
	req, err := e.cfg.Source.Collect(ctx, tenant, deviceID, nonce)
	if err != nil {
		return nil, "collect: " + err.Error()
	}
	if req == nil {
		return nil, "collect: no evidence returned"
	}
	// The verifier issued the nonce; the device does not get to name it.
	issued := *req
	issued.Nonce = nonce
	result, err := e.cfg.Appraiser.AppraiseQuote(ctx, tenant, &issued)
	if err != nil {
		return nil, "appraise: " + err.Error()
	}
	switch {
	case result.Verified:
		return result, ""
	case result.CryptographicFailure:
		return result, "evidence failed appraisal: cryptographic failure"
	default:
		return result, "evidence failed appraisal: evidence absent"
	}
}

// Pass re-attests every enrolled device of every registered tenant once.
func (e *Engine) Pass(ctx context.Context) error {
	if e.cfg.Inventory == nil {
		return &ConfigError{Field: "Inventory", Reason: "is required for a scheduled pass"}
	}
	tenants, err := e.cfg.Inventory.Tenants(ctx)
	if err != nil {
		return err
	}
	sort.Strings(tenants)
	for _, tenant := range tenants {
		devices, err := e.cfg.Inventory.Devices(ctx, tenant)
		if err != nil {
			return err
		}
		for _, deviceID := range devices {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := e.Reattest(ctx, tenant, deviceID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Run makes one Pass per Interval tick until ctx ends, returning ctx's
// error, or the first Pass error.
func (e *Engine) Run(ctx context.Context) error {
	if e.cfg.Inventory == nil || e.cfg.Interval <= 0 {
		return &ConfigError{Field: "Inventory and Interval", Reason: "are required by Run"}
	}
	ticker := e.cfg.NewTicker(e.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C():
			if err := e.Pass(ctx); err != nil {
				return err
			}
		}
	}
}

type timeTicker struct{ t *time.Ticker }

func newTimeTicker(d time.Duration) Ticker { return timeTicker{t: time.NewTicker(d)} }

func (t timeTicker) C() <-chan time.Time { return t.t.C }

func (t timeTicker) Stop() { t.t.Stop() }
