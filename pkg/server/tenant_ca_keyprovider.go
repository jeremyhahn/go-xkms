package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/internal/keyslot"
	"github.com/jeremyhahn/go-xkms/internal/loginca"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tenantLoginCAKeyCN is the common name of a tenant's go-qrdb login CA key
// (Key B) and of its certificate record. One key per tenant: the name is the
// same under every tenant and the tenant scope tells the keys apart, so the
// key ID is the tenant, as cakey.ProviderFactory requires.
const tenantLoginCAKeyCN = loginca.KeyCN

// tenantLoginCAValidity is the lifetime of a tenant login CA certificate.
const tenantLoginCAValidity = 10 * 365 * 24 * time.Hour

// tenantLoginCAProvenanceID is the tenant-scoped certificate ID under which
// the provisioning path records that it made the tenant's login CA key.
const tenantLoginCAProvenanceID = tenantLoginCAKeyCN + ":provenance"

// tenantLoginCAIntentID names the record the provisioning path saves before
// it generates a tenant's login CA key. A key found without provenance but
// with this record is a pass that stopped between generation and provenance,
// which the next pass finishes over the same key; a key without either was
// not made by this path and stays a collision.
const tenantLoginCAIntentID = tenantLoginCAKeyCN + ":intent"

// tenantLoginCAProvenanceWait bounds how long adoption waits for another
// node's provisioning pass to record the provenance of a key it just made.
const tenantLoginCAProvenanceWait = 2 * time.Second

// tenantLoginCAClaimLease is how long a provisioning claim with no key behind
// it is honoured before another pass may take it over. A claim marked
// generating is taken over only once its holder has also stopped renewing it
// (see tenantLoginCAClaimRenew).
const tenantLoginCAClaimLease = 30 * time.Second

// tenantLoginCAClaimRenew is how often a pass renews its generating claim
// while its generate is in flight. A generating claim past its lease is taken
// over only when it stays unchanged for two renewal intervals: its holder is
// then gone, for a live holder renews it however long its generate takes.
const tenantLoginCAClaimRenew = time.Second

// errTenantLoginCAKeyCollision is returned when a tenant holds a login CA key
// that the provisioning path did not make. Such a key is never adopted; an
// existing one needs an explicit migration.
var errTenantLoginCAKeyCollision = errors.New("tenant login CA key factory: key collision: a " + tenantLoginCAKeyCN + " key exists without provisioning provenance")

// errTenantLoginCAClaimHeld reports that another pass holds the tenant's
// provisioning claim and its key did not appear in time; a later pass retries.
var errTenantLoginCAClaimHeld = errors.New("tenant login CA key factory: another pass holds the provisioning claim")

// errTenantCAKeyFactoryUnbound is returned while no backend is bound.
var errTenantCAKeyFactoryUnbound = errors.New("tenant login CA key factory: no backend bound")

// tenantCAKeyFactory is go-qrdb's cakey.ProviderFactory over go-xkms's
// tenant-scoped backend: every tenant's login CA (Key B) signature goes
// through that tenant's xkms key, and go-qrdb generates no software Key B.
type tenantCAKeyFactory struct {
	mu   sync.RWMutex
	base xkms.Backend
	// claims holds one provisioning claim per tenant. It must be the
	// storage every node shares: a PKCS#11 token does not refuse a second
	// key with the same label, so only a claim taken with PutIfAbsent
	// before generation keeps concurrent passes from each making a key.
	claims  storage.Backend
	tenants tenantLookup
}

// tenantLookup is the part of go-qrdb's tenant service the factory uses to
// tell a tenant the node knows from an arbitrary ID.
type tenantLookup interface {
	GetTenant(ctx context.Context, tenantID string) (*qrdbsdk.ServiceTenantInfo, error)
}

// TrackTenants makes the factory provision, on first request, the login CA of
// any tenant svc knows that has none yet. Without it such a tenant is refused.
func (f *tenantCAKeyFactory) TrackTenants(svc tenantLookup) {
	f.mu.Lock()
	f.tenants = svc
	f.mu.Unlock()
}

// knownTenant reports whether the tracked tenant service has tenantID.
func (f *tenantCAKeyFactory) knownTenant(ctx context.Context, tenantID string) bool {
	f.mu.RLock()
	svc := f.tenants
	f.mu.RUnlock()
	if svc == nil {
		return false
	}
	info, err := svc.GetTenant(ctx, tenantID)
	return err == nil && info != nil
}

// withdrawn reports a tenant whose login CA the node must no longer serve:
// the tenant service no longer knows it. A tenant deleted through go-qrdb's
// own service leaves its key behind, so the key alone never vouches for a
// tenant. The system tenant is never withdrawn, and a factory not yet
// tracking tenants (before the boot pass) withdraws none.
func (f *tenantCAKeyFactory) withdrawn(ctx context.Context, tenantID string) bool {
	if scope.TenantName(tenantID) == scope.TenantName(qrdbsdk.SystemTenantID) {
		return false
	}
	f.mu.RLock()
	tracked := f.tenants != nil
	f.mu.RUnlock()
	return tracked && !f.knownTenant(ctx, tenantID)
}

var _ qrdbsdk.CAKeyProviderFactory = (*tenantCAKeyFactory)(nil)

func newTenantCAKeyFactory() *tenantCAKeyFactory {
	return &tenantCAKeyFactory{}
}

// Bind makes base the backend that holds every tenant's login CA key.
func (f *tenantCAKeyFactory) Bind(base xkms.Backend, claims storage.Backend) error {
	if base == nil {
		return errors.New("tenant login CA key factory: nil backend")
	}
	if claims == nil {
		return errors.New("tenant login CA key factory: nil claim storage")
	}
	f.mu.Lock()
	f.base = base
	f.claims = claims
	f.mu.Unlock()
	return nil
}

// backend is the bound backend. The read takes only the factory's own lock,
// which Bind holds for one assignment, so a lookup never waits on, or fails
// for, a lock the server holds.
func (f *tenantCAKeyFactory) backend() (xkms.Backend, error) {
	f.mu.RLock()
	base := f.base
	f.mu.RUnlock()
	if base == nil {
		return nil, errTenantCAKeyFactoryUnbound
	}
	// One key per tenant needs a backend that stores a key per name. A
	// YubiKey PIV token configured with a slot puts every key in that slot,
	// so each tenant's generate would overwrite the last tenant's login CA.
	if keyslot.Fixed(base.KeyProvider()) {
		return nil, errTenantCAKeyFixedSlot
	}
	return base, nil
}

// errTenantCAKeyFixedSlot refuses a backend whose keys all share one slot.
var errTenantCAKeyFixedSlot = errors.New("tenant login CA key factory: the backend has a fixed key slot and cannot hold one login CA key per tenant")

// ProviderForTenant returns the provider of tenantID's login CA: the tenant's
// own xkms key and certificate. A tenant without a login CA key is
// provisioned if the tracked tenant service knows it, and refused otherwise;
// a provider is never shared between tenants.
func (f *tenantCAKeyFactory) ProviderForTenant(tenantID string) (qrdbsdk.CAKeyProvider, error) {
	if tenantID == "" {
		return nil, errors.New("tenant login CA key factory: empty tenant ID")
	}
	base, err := f.backend()
	if err != nil {
		return nil, err
	}
	if f.withdrawn(context.Background(), tenantID) {
		return nil, fmt.Errorf("tenant login CA key factory: tenant %q no longer exists", tenantID)
	}
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	attrs, err := tenantLoginCAKeyAttrs(context.Background(), base, tenantID)
	if err == nil {
		// A key without its provenance or its certificate is an earlier
		// pass that stopped after the key: EnsureTenant finishes it over the
		// same key, or refuses a key this path did not make.
		_, certErr := scoped.GetCert(context.Background(), tenantLoginCAKeyCN)
		if certErr != nil || !tenantLoginCAKeyProvisionedAttrs(context.Background(), scoped, attrs) {
			if err := f.EnsureTenant(context.Background(), tenantID); err != nil {
				return nil, err
			}
		}
	} else {
		// go-qrdb's native onboarding creates a tenant through the node's own
		// tenant service, which go-xkms cannot wrap, and then asks for its
		// login CA: provision a tenant the node knows on that first request.
		if !f.knownTenant(context.Background(), tenantID) {
			return nil, err
		}
		if err := f.EnsureTenant(context.Background(), tenantID); err != nil {
			return nil, err
		}
	}
	return qrdbsdk.CAKeyAdapter{
		SignerFunc: func(ctx context.Context) (crypto.Signer, error) {
			attrs, err := tenantLoginCAKeyAttrs(ctx, base, tenantID)
			if err != nil {
				return nil, err
			}
			return scoped.Signer(ctx, attrs)
		},
		CertificateFunc: func(ctx context.Context) (*x509.Certificate, error) {
			return scoped.GetCert(ctx, tenantLoginCAKeyCN)
		},
	}, nil
}

// TenantIDs lists, sorted, the tenants that hold a login CA key in the backend.
func (f *tenantCAKeyFactory) TenantIDs(ctx context.Context) ([]string, error) {
	base, err := f.backend()
	if err != nil {
		return nil, err
	}
	keys, err := base.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: list keys: %w", err)
	}
	seen := make(map[string]struct{})
	for _, attrs := range keys {
		id, ok := tenantLoginCAKeyTenant(attrs)
		if !ok {
			continue
		}
		if tenantLoginCAKeyProvisionedAttrs(ctx, xkms.NewTenantScopedBackend(base, id), attrs) {
			seen[id] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		if !f.withdrawn(ctx, id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// EnsureTenant provisions tenantID's login CA once: a P-256 signing key in the
// tenant's scope and a self-signed CA certificate over it, saved under the same
// name. An existing key is kept and its certificate validated, or issued if
// missing.
func (f *tenantCAKeyFactory) EnsureTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant login CA key factory: empty tenant ID")
	}
	base, err := f.backend()
	if err != nil {
		return err
	}
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	existing, err := tenantLoginCAKeyAttrs(ctx, base, tenantID)
	switch {
	case err == nil:
		// Keep the key, but a key alone is not a provisioned login CA: an
		// earlier pass may have stopped before its certificate was saved,
		// and a key this path did not make is never adopted.
		return adoptTenantLoginCAKey(ctx, scoped, tenantID, existing)
	case !errors.Is(err, errTenantLoginCAKeyNotFound):
		return err
	}
	owner, err := f.claimTenantLoginCAKey(ctx, base, tenantID)
	if err != nil {
		return err
	}
	if owner == "" {
		// Another pass holds the claim and makes the key: adopt it.
		return adoptOtherTenantLoginCAKey(ctx, base, scoped, tenantID)
	}
	attrs := &types.KeyAttributes{
		CN:            tenantLoginCAKeyName(tenantID),
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	if err := recordTenantLoginCAIntent(ctx, scoped, tenantID); err != nil {
		return err
	}
	generating, held, err := f.fenceTenantLoginCAClaim(ctx, tenantID, owner)
	if err != nil {
		return err
	}
	if !held {
		// The pass was delayed past its lease and another pass took the
		// claim over: that pass makes the key.
		return adoptOtherTenantLoginCAKey(ctx, base, scoped, tenantID)
	}
	// The claim now says a generate is in flight, and this pass renews it
	// however long the generate takes, so no pass takes it over: a backend
	// may ignore the context (PKCS#11 waits on the token's mutex without a
	// deadline), so no lease bounds when this pass can still make its key.
	stopRenew := f.renewTenantLoginCAGenerating(ctx, tenantID, owner, generating)
	_, err = scoped.GenerateECDSA(ctx, attrs)
	generating = stopRenew()
	if err != nil {
		if !errors.Is(err, backend.ErrKeyAlreadyExists) {
			// The generate returned, so it makes no key any more: put back
			// a plain claim, which a later pass may take over once its
			// lease runs out and no key is behind it.
			f.releaseTenantLoginCAGenerating(ctx, tenantID, owner, generating)
			return fmt.Errorf("tenant login CA key factory: generate key for tenant %q: %w", tenantID, err)
		}
		// Another node provisioned the key between the lookup and the
		// generate: converge on the persisted key.
		existing, lookupErr := tenantLoginCAKeyAttrs(ctx, base, tenantID)
		if lookupErr != nil {
			return fmt.Errorf("tenant login CA key factory: generate key for tenant %q: %w", tenantID, errors.Join(err, lookupErr))
		}
		return adoptTenantLoginCAKey(ctx, scoped, tenantID, existing)
	}
	signer, err := scoped.Signer(ctx, attrs)
	if err != nil {
		return fmt.Errorf("tenant login CA key factory: signer for tenant %q: %w", tenantID, err)
	}
	return finishTenantLoginCAKey(ctx, scoped, tenantID, signer)
}

// tenantLoginCAClaimKey is the shared-storage key of a tenant's provisioning
// claim.
func tenantLoginCAClaimKey(tenantID string) string {
	return "tenant-login-ca/claims/" + tenantLoginCAKeyName(tenantID)
}

// claimTenantLoginCAKey takes the tenant's provisioning claim with an atomic
// PutIfAbsent, so across nodes and concurrent requests one pass generates the
// key. It returns the pass's owner token, or "" when another pass holds the
// claim. A claim older than tenantLoginCAClaimLease with no key behind it may
// be left by a pass that stopped before generating; unless it is marked
// generating (see fenceTenantLoginCAClaim) and still renewed by a live
// owner, it is taken over with a
// compare-and-swap, so again only one pass wins it, and the earlier owner is
// fenced by fenceTenantLoginCAClaim. A storage or key lookup error fails
// closed.
func (f *tenantCAKeyFactory) claimTenantLoginCAKey(ctx context.Context, base xkms.Backend, tenantID string) (string, error) {
	claims, err := f.claimStorage()
	if err != nil {
		return "", err
	}
	owner, err := newTenantLoginCAClaimOwner()
	if err != nil {
		return "", err
	}
	key := tenantLoginCAClaimKey(tenantID)
	claim := tenantLoginCAClaim(owner, time.Now())
	stored, err := claims.PutIfAbsent(ctx, key, claim)
	if err != nil {
		return "", fmt.Errorf("tenant login CA key factory: claim tenant %q: %w", tenantID, err)
	}
	if stored {
		return owner, nil
	}
	held, err := claims.Get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("tenant login CA key factory: read claim of tenant %q: %w", tenantID, err)
	}
	if at, _, parseErr := parseTenantLoginCAClaim(held); parseErr == nil && time.Since(at) < tenantLoginCAClaimLease {
		return "", nil
	}
	if tenantLoginCAClaimGenerating(held) {
		// Its owner may still be inside a generate that no lease bounds,
		// and taking over could make a second key beside the one it makes;
		// but a live owner renews the claim. Watch it for two renewal
		// intervals: a claim still unchanged was left by a pass that died
		// before its key was made, and the compare-and-swap below fails if
		// the owner renewed it after all.
		timer := time.NewTimer(2 * tenantLoginCAClaimRenew)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	if _, lookupErr := tenantLoginCAKeyAttrs(ctx, base, tenantID); lookupErr == nil {
		return "", nil
	} else if !errors.Is(lookupErr, errTenantLoginCAKeyNotFound) {
		return "", lookupErr
	}
	swapper, ok := claims.(storage.CompareAndSwapper)
	if !ok {
		return "", nil
	}
	swapped, _, err := swapper.CompareAndSwap(ctx, key, held, claim)
	if err != nil {
		return "", fmt.Errorf("tenant login CA key factory: take over claim of tenant %q: %w", tenantID, err)
	}
	if !swapped {
		return "", nil
	}
	return owner, nil
}

// fenceTenantLoginCAClaim is the last step before generation: it confirms
// the pass still owns the tenant's claim and marks the claim generating, and
// returns the claim it wrote. A claim older than the lease does not prove
// its owner stopped: a pass delayed past the lease may have lost the claim
// to a takeover, and it must not generate beside the new owner's key. The
// mark is a compare-and-swap on the owner's own claim, so a takeover and the
// mark never both succeed; a generating claim is not taken over while its
// owner renews it (see renewTenantLoginCAGenerating).
func (f *tenantCAKeyFactory) fenceTenantLoginCAClaim(ctx context.Context, tenantID, owner string) ([]byte, bool, error) {
	claims, err := f.claimStorage()
	if err != nil {
		return nil, false, err
	}
	key := tenantLoginCAClaimKey(tenantID)
	held, err := claims.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("tenant login CA key factory: read claim of tenant %q: %w", tenantID, err)
	}
	if _, heldOwner, parseErr := parseTenantLoginCAClaim(held); parseErr != nil || heldOwner != owner {
		return nil, false, nil
	}
	swapper, ok := claims.(storage.CompareAndSwapper)
	if !ok {
		// Without compare-and-swap no pass takes a claim over, so the
		// owner still holding it is the whole fence.
		return held, true, nil
	}
	generating := tenantLoginCAGeneratingClaim(owner, time.Now())
	swapped, _, err := swapper.CompareAndSwap(ctx, key, held, generating)
	if err != nil {
		return nil, false, fmt.Errorf("tenant login CA key factory: mark claim of tenant %q generating: %w", tenantID, err)
	}
	return generating, swapped, nil
}

// releaseTenantLoginCAGenerating turns the pass's generating claim back
// into a plain one after a generate that failed, so a later pass may take it
// over once the lease runs out. A failed write leaves the claim generating,
// no longer renewed: a later pass takes it over once its lease runs out.
func (f *tenantCAKeyFactory) releaseTenantLoginCAGenerating(ctx context.Context, tenantID, owner string, generating []byte) {
	claims, err := f.claimStorage()
	if err != nil {
		return
	}
	if swapper, ok := claims.(storage.CompareAndSwapper); ok {
		_, _, _ = swapper.CompareAndSwap(ctx, tenantLoginCAClaimKey(tenantID), generating, tenantLoginCAClaim(owner, time.Now()))
	}
}

// renewTenantLoginCAGenerating renews the pass's generating claim every
// tenantLoginCAClaimRenew until the returned stop is called, so a pass whose
// generate is still in flight is told apart from one that died: only an
// unrenewed generating claim is taken over. The renewals outlive a cancelled
// context, for the generate may too. Stop returns the claim last written. A
// claim the pass no longer owns is left alone.
func (f *tenantCAKeyFactory) renewTenantLoginCAGenerating(ctx context.Context, tenantID, owner string, generating []byte) func() []byte {
	claims, err := f.claimStorage()
	if err != nil {
		return func() []byte { return generating }
	}
	swapper, ok := claims.(storage.CompareAndSwapper)
	if !ok {
		return func() []byte { return generating }
	}
	ctx = context.WithoutCancel(ctx)
	key := tenantLoginCAClaimKey(tenantID)
	stop := make(chan struct{})
	done := make(chan []byte, 1)
	go func() {
		current := generating
		ticker := time.NewTicker(tenantLoginCAClaimRenew)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				done <- current
				return
			case <-ticker.C:
			}
			held, err := claims.Get(ctx, key)
			if err != nil {
				continue
			}
			if _, heldOwner, parseErr := parseTenantLoginCAClaim(held); parseErr != nil || heldOwner != owner || !tenantLoginCAClaimGenerating(held) {
				continue
			}
			renewed := tenantLoginCAGeneratingClaim(owner, time.Now())
			if swapped, _, err := swapper.CompareAndSwap(ctx, key, held, renewed); err == nil && swapped {
				current = renewed
			}
		}
	}()
	return func() []byte {
		close(stop)
		return <-done
	}
}

// claimStorage returns the bound claim storage.
func (f *tenantCAKeyFactory) claimStorage() (storage.Backend, error) {
	f.mu.RLock()
	claims := f.claims
	f.mu.RUnlock()
	if claims == nil {
		return nil, errTenantCAKeyFactoryUnbound
	}
	return claims, nil
}

// newTenantLoginCAClaimOwner returns a random token that names one
// provisioning pass as a claim's owner.
func newTenantLoginCAClaimOwner() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("tenant login CA key factory: claim owner token: %w", err)
	}
	return fmt.Sprintf("%x", token), nil
}

// tenantLoginCAClaim is a claim value: the time it was taken or last
// renewed, then its owner's token.
func tenantLoginCAClaim(owner string, at time.Time) []byte {
	return []byte(at.UTC().Format(time.RFC3339Nano) + " " + owner)
}

// tenantLoginCAClaimGeneratingMark ends the claim of a pass that is about to
// generate, or is generating, the tenant's key.
const tenantLoginCAClaimGeneratingMark = "generating"

// tenantLoginCAGeneratingClaim is the claim of a pass with a generate in
// flight.
func tenantLoginCAGeneratingClaim(owner string, at time.Time) []byte {
	return append(tenantLoginCAClaim(owner, at), " "+tenantLoginCAClaimGeneratingMark...)
}

// tenantLoginCAClaimGenerating reports whether claim marks a generate in
// flight.
func tenantLoginCAClaimGenerating(claim []byte) bool {
	_, rest, _ := strings.Cut(string(claim), " ")
	_, mark, _ := strings.Cut(rest, " ")
	return mark == tenantLoginCAClaimGeneratingMark
}

// parseTenantLoginCAClaim splits a claim value into its time and owner.
func parseTenantLoginCAClaim(claim []byte) (time.Time, string, error) {
	stamp, rest, _ := strings.Cut(string(claim), " ")
	owner, _, _ := strings.Cut(rest, " ")
	at, err := time.Parse(time.RFC3339Nano, stamp)
	return at, owner, err
}

// waitTenantLoginCAKey waits for the pass holding the tenant's claim to make
// the key, and returns it.
// adoptOtherTenantLoginCAKey waits for the key the claim's owner makes and
// adopts it.
func adoptOtherTenantLoginCAKey(ctx context.Context, base xkms.Backend, scoped *xkms.TenantScopedBackend, tenantID string) error {
	existing, err := waitTenantLoginCAKey(ctx, base, tenantID)
	if err != nil {
		return err
	}
	return adoptTenantLoginCAKey(ctx, scoped, tenantID, existing)
}

func waitTenantLoginCAKey(ctx context.Context, base xkms.Backend, tenantID string) (*types.KeyAttributes, error) {
	waitCtx, cancel := context.WithTimeout(ctx, tenantLoginCAProvenanceWait)
	defer cancel()
	ticker := time.NewTicker(tenantLoginCAProvenanceWait / 40)
	defer ticker.Stop()
	for {
		attrs, err := tenantLoginCAKeyAttrs(ctx, base, tenantID)
		if err == nil {
			return attrs, nil
		}
		if !errors.Is(err, errTenantLoginCAKeyNotFound) {
			return nil, err
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("tenant %q: %w", tenantID, errTenantLoginCAClaimHeld)
		case <-ticker.C:
		}
	}
}

// finishTenantLoginCAKey records that this path made the key before anything
// else may use it, then saves the login CA certificate.
func finishTenantLoginCAKey(ctx context.Context, scoped *xkms.TenantScopedBackend, tenantID string, signer crypto.Signer) error {
	provenance, err := selfSignTenantLoginCA(tenantID, signer)
	if err != nil {
		return err
	}
	if err := scoped.SaveCert(ctx, tenantLoginCAProvenanceID, provenance); err != nil {
		return fmt.Errorf("tenant login CA key factory: record key provenance for tenant %q: %w", tenantID, err)
	}
	// The intent has served its purpose once provenance is durable; a stale
	// one left by a failed delete is harmless next to provenance.
	_ = scoped.DeleteCert(ctx, tenantLoginCAIntentID)
	return ensureTenantLoginCACert(ctx, scoped, tenantID, signer)
}

// recordTenantLoginCAIntent durably records, before the key exists, that
// this path is about to generate the tenant's login CA key. The certificate
// store holds certificates only, so the record is a throwaway self-signed
// certificate over an ephemeral key that is never kept.
func recordTenantLoginCAIntent(ctx context.Context, scoped *xkms.TenantScopedBackend, tenantID string) error {
	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tenant login CA key factory: intent key for tenant %q: %w", tenantID, err)
	}
	record, err := selfSignTenantLoginCA(tenantID, ephemeral)
	if err != nil {
		return err
	}
	if err := scoped.SaveCert(ctx, tenantLoginCAIntentID, record); err != nil {
		return fmt.Errorf("tenant login CA key factory: record provisioning intent for tenant %q: %w", tenantID, err)
	}
	return nil
}

// tenantLoginCAIntentRecorded reports whether a provisioning pass recorded
// its intent to generate the tenant's login CA key.
func tenantLoginCAIntentRecorded(ctx context.Context, scoped *xkms.TenantScopedBackend) bool {
	exists, err := scoped.CertExists(ctx, tenantLoginCAIntentID)
	return err == nil && exists
}

// adoptTenantLoginCAKey finishes the login CA over an existing key only when
// the provisioning path recorded its provenance. A key that another node is
// provisioning right now gets its provenance shortly after it is generated,
// so the check waits a bounded time, tied to ctx, before it reports a
// collision.
func adoptTenantLoginCAKey(ctx context.Context, scoped *xkms.TenantScopedBackend, tenantID string, attrs *types.KeyAttributes) error {
	signer, err := scoped.Signer(ctx, attrs)
	if err != nil {
		return fmt.Errorf("tenant login CA key factory: signer for tenant %q: %w", tenantID, err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, tenantLoginCAProvenanceWait)
	defer cancel()
	ticker := time.NewTicker(tenantLoginCAProvenanceWait / 40)
	defer ticker.Stop()
	for !tenantLoginCAKeyProvisioned(ctx, scoped, signer.Public()) {
		select {
		case <-waitCtx.Done():
			// No pass finished it in time. If this path recorded its intent
			// before generating, the key is an interrupted provisioning:
			// finish it over the same key. Otherwise it was not made here.
			if tenantLoginCAIntentRecorded(ctx, scoped) {
				return finishTenantLoginCAKey(ctx, scoped, tenantID, signer)
			}
			return fmt.Errorf("tenant %q: %w", tenantID, errTenantLoginCAKeyCollision)
		case <-ticker.C:
		}
	}
	return ensureTenantLoginCACert(ctx, scoped, tenantID, signer)
}

// tenantLoginCAKeyProvisioned reports whether the provenance record the
// provisioning path writes is present and covers the key with public key pub.
// Its certificate ID carries a single colon, which key-reference validation
// refuses, so no API caller can write it.
func tenantLoginCAKeyProvisioned(ctx context.Context, scoped *xkms.TenantScopedBackend, pub crypto.PublicKey) bool {
	cert, err := scoped.GetCert(ctx, tenantLoginCAProvenanceID)
	if err != nil || cert == nil {
		return false
	}
	certPub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && certPub.Equal(pub)
}

// tenantLoginCAKeyProvisionedAttrs reports whether attrs names a login CA key
// the provisioning path made.
func tenantLoginCAKeyProvisionedAttrs(ctx context.Context, scoped *xkms.TenantScopedBackend, attrs *types.KeyAttributes) bool {
	signer, err := scoped.Signer(ctx, attrs)
	if err != nil {
		return false
	}
	return tenantLoginCAKeyProvisioned(ctx, scoped, signer.Public())
}

// RemoveTenant deletes a tenant's login CA certificate and key. Tenant
// teardown calls it once the tenant is deleted; a tenant with neither is not
// an error.
func (f *tenantCAKeyFactory) RemoveTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant login CA key factory: empty tenant ID")
	}
	base, err := f.backend()
	if err != nil {
		return err
	}
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	var errs []error
	for _, certID := range []string{tenantLoginCAKeyCN, tenantLoginCAProvenanceID, tenantLoginCAIntentID} {
		exists, err := scoped.CertExists(ctx, certID)
		switch {
		case err != nil:
			errs = append(errs, err)
		case exists:
			if delErr := scoped.DeleteCert(ctx, certID); delErr != nil {
				errs = append(errs, delErr)
			}
		}
	}
	if attrs, lookupErr := tenantLoginCAKeyAttrs(ctx, base, tenantID); lookupErr == nil {
		if delErr := base.DeleteKey(ctx, attrs); delErr != nil {
			errs = append(errs, delErr)
		}
	} else if !errors.Is(lookupErr, errTenantLoginCAKeyNotFound) {
		// The key may remain: keep the claim.
		errs = append(errs, lookupErr)
	}
	if len(errs) > 0 {
		return fmt.Errorf("tenant login CA key factory: remove tenant %q: %w", tenantID, errors.Join(errs...))
	}
	// The claim goes last: while any key or certificate remains, a new
	// pass must not claim and generate beside it.
	f.mu.RLock()
	claims := f.claims
	f.mu.RUnlock()
	if err := claims.Delete(ctx, tenantLoginCAClaimKey(tenantID)); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("tenant login CA key factory: remove tenant %q: delete claim: %w", tenantID, err)
	}
	return nil
}

// ensureTenantLoginCACert makes sure the tenant's saved login CA certificate is
// a valid CA certificate over the key attrs names, issuing and saving one if it
// is missing or does not match. A certificate another node saved first wins.
func ensureTenantLoginCACert(ctx context.Context, scoped *xkms.TenantScopedBackend, tenantID string, signer crypto.Signer) error {
	if tenantLoginCACertValid(ctx, scoped, signer.Public()) {
		return nil
	}
	cert, err := selfSignTenantLoginCA(tenantID, signer)
	if err != nil {
		return err
	}
	if err := scoped.SaveCert(ctx, tenantLoginCAKeyCN, cert); err != nil {
		if tenantLoginCACertValid(ctx, scoped, signer.Public()) {
			return nil
		}
		return fmt.Errorf("tenant login CA key factory: save certificate for tenant %q: %w", tenantID, err)
	}
	return nil
}

// tenantLoginCACertValid reports whether the tenant's saved login CA
// certificate is a CA certificate, in its validity period, over pub.
func tenantLoginCACertValid(ctx context.Context, scoped *xkms.TenantScopedBackend, pub crypto.PublicKey) bool {
	cert, err := scoped.GetCert(ctx, tenantLoginCAKeyCN)
	if err != nil || cert == nil || !cert.IsCA {
		return false
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}
	certPub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && certPub.Equal(pub)
}

// tenantLoginCAKeyAttrs finds tenantID's login CA key among base's keys.
func tenantLoginCAKeyAttrs(ctx context.Context, base xkms.Backend, tenantID string) (*types.KeyAttributes, error) {
	keys, err := base.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: list keys: %w", err)
	}
	want := scope.TenantName(tenantID)
	for _, attrs := range keys {
		if id, ok := tenantLoginCAKeyTenant(attrs); ok && id == want {
			found := *attrs
			if found.TenantID == "" {
				found.TenantID = tenantID
			}
			return &found, nil
		}
	}
	return nil, errTenantLoginCAKeyNotFound
}

// errTenantLoginCAKeyNotFound is the only lookup result that proves the
// tenant has no login CA key: any other lookup error (a key store outage, a
// refused listing) leaves the key's presence unknown, and a pass must not
// claim, record intent or generate on it.
var errTenantLoginCAKeyNotFound = errors.New("tenant login CA key factory: the tenant has no login CA key")

// tenantLoginCAKeyTenant reports which tenant a listed key is the login CA
// key of. The tenant is in the key name: the AWS KMS, Azure Key Vault and GCP
// KMS providers list keys without the TenantID they were generated under.
// Scopes compare normalized, since a backend may also report a system key
// with an empty TenantID (tpm2 listSystemKeys) though it was made for
// "system"; a TenantID that disagrees with the name is not a match.
func tenantLoginCAKeyTenant(attrs *types.KeyAttributes) (string, bool) {
	if attrs == nil {
		return "", false
	}
	id, ok := strings.CutPrefix(attrs.CN, tenantLoginCAKeyCN+"-")
	if !ok || id == "" {
		return "", false
	}
	if attrs.TenantID != "" && scope.TenantName(attrs.TenantID) != id {
		return "", false
	}
	return id, true
}

// tenantLoginCAKeyName is the name a tenant's login CA key is generated
// under. It carries the tenant because the AWS KMS, Azure Key Vault and GCP
// KMS providers address a key by its name alone, without the tenant scope.
func tenantLoginCAKeyName(tenantID string) string {
	return tenantLoginCAKeyCN + "-" + scope.TenantName(tenantID)
}

// selfSignTenantLoginCA issues the tenant's self-signed login CA certificate,
// signed by the tenant's xkms key.
func selfSignTenantLoginCA(tenantID string, signer crypto.Signer) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "qrdb login CA " + tenantID,
			OrganizationalUnit: []string{tenantID},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(tenantLoginCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: sign certificate for tenant %q: %w", tenantID, err)
	}
	return x509.ParseCertificate(der)
}

// tenantCAKeyProviderOptions returns the node option that routes every
// tenant's login CA (Key B) through go-xkms (WithCertKeyProviderFactory),
// under the same condition as the cluster CA provider. The boot pass binds the
// factory to the server's default backend.
func (s *Server) tenantCAKeyProviderOptions() []qrdbnode.NodeOption {
	// An explicit opt-in: wiring the factory replaces the tenant login CAs
	// go-qrdb already persisted, which would strand the login certificates
	// they issued on an upgrade (see config.DatastoreConfig.TenantLoginCAKeys).
	if !s.config.Datastore.TenantLoginCAKeys || !s.trustedCAIsClusterCA() {
		return nil
	}
	f := newTenantCAKeyFactory()
	// Left unbound here: the node starts before the key backends exist, and
	// its background trust refresh would read s.backends while New writes
	// it. provisionTenantCAKeys binds the factory once they are ready.
	s.tenantCAKeys = f
	return []qrdbnode.NodeOption{qrdbnode.WithCertKeyProviderFactory(f)}
}

// tenantCAKeyBackend is the server's default backend, the one that holds the
// tenants' login CA keys; an error before the backends are loaded. Only the
// boot pass calls it, once, to bind the factory; the lookups go-qrdb makes
// afterwards read the bound backend and never take the server's lock.
func (s *Server) tenantCAKeyBackend() (xkms.Backend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	name := xkms.ResolveDefaultBackend(string(s.config.Default), s.backends)
	if name == "" {
		return nil, errTenantCAKeyFactoryUnbound
	}
	return s.backends[name], nil
}
