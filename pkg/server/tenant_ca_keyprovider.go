package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// tenantLoginCATeardownWait bounds how long teardown waits for a generate in
// flight on a live holder to return before it reports the claim held.
const tenantLoginCATeardownWait = 2 * time.Second

// tenantLoginCAClaimLease is how long a provisioning claim with no key behind
// it is honoured before another pass may take it over. A claim marked
// generating is never taken over on time: an unchanged claim does not prove
// its holder's generate stopped (a backend may ignore the generate's context,
// and a live holder may lose claim storage). Only proof that the holder's
// process ended lets a pass take it over (see tenantLoginCAHolderStopped).
const tenantLoginCAClaimLease = 30 * time.Second

// tenantLoginCAProcess names this process in the claims its passes take:
// a claim another process on this host left is that process's, and the
// process is gone once its PID no longer runs or is this process's own.
var tenantLoginCAProcess = func() string {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", nonce)
}()

// tenantLoginCALiveOwners holds the claim owners of this process's passes
// that are still running, so a claim of this process is known to be live.
var tenantLoginCALiveOwners sync.Map

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
	// fenced holds the claim owners whose hosts the operator fenced (see
	// FenceHolders).
	fenced map[string]struct{}
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
		// Each native onboarding also reclaims the material of tenants
		// deleted natively since, so tenant churn cannot fill the token. A
		// failure here does not fail this tenant's onboarding: the next
		// onboarding and the boot pass (which reports it) retry it.
		_ = f.ReclaimWithdrawnTenants(context.Background())
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

// ReclaimWithdrawnTenants removes the login CA material of every tenant that
// holds some but that the node's tenant service no longer knows. go-qrdb's
// native DELETE /v1/tenants/{id} deletes a tenant through the node's own
// service, which never reaches RemoveTenant, so its key and certificates
// would outlive it. Each removal goes through RemoveTenant's tombstone and
// cleanup lease, then ReviveTenant clears the tombstone so the ID can be
// created again. A tenant counts as gone only when a complete ListTenants
// omits it. The system tenant is never reclaimed.
func (f *tenantCAKeyFactory) ReclaimWithdrawnTenants(ctx context.Context) error {
	f.mu.RLock()
	svc, _ := f.tenants.(tenantLister)
	f.mu.RUnlock()
	if svc == nil {
		return nil
	}
	base, err := f.backend()
	if err != nil {
		return err
	}
	keys, err := base.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("tenant login CA key factory: list keys: %w", err)
	}
	held := make(map[string]struct{})
	for _, attrs := range keys {
		if id, ok := tenantLoginCAKeyTenant(attrs); ok && id != scope.TenantName(qrdbsdk.SystemTenantID) {
			held[id] = struct{}{}
		}
	}
	if len(held) == 0 {
		return nil
	}
	// Only a complete listing proves a tenant gone: a GetTenant that fails
	// for any other reason must never cost a live tenant its CA.
	live, err := liveTenantNames(ctx, svc)
	if err != nil {
		return fmt.Errorf("tenant login CA key factory: list tenants: %w", err)
	}
	ids := make([]string, 0, len(held))
	for id := range held {
		if _, ok := live[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	f.mu.RLock()
	lookup := f.tenants
	f.mu.RUnlock()
	var errs []error
	for _, id := range ids {
		// go-qrdb's ListTenants skips metadata it cannot decode and still
		// succeeds, so a tenant missing from the listing is only a
		// candidate: GetTenant must report it as typed not-found before its
		// CA is destroyed. Any other answer keeps the material.
		if lookup != nil {
			if _, getErr := lookup.GetTenant(ctx, id); !errors.Is(getErr, qrdbsdk.ErrTenantMissing) {
				slog.Default().Warn("tenant login CA reclaim skipped: tenant not confirmed deleted",
					"tenant", id, "lookup_failed", getErr != nil)
				continue
			}
		}
		if err := f.RemoveTenant(ctx, id); err != nil {
			errs = append(errs, err)
			continue
		}
		// The material is gone. go-qrdb may create this ID again natively,
		// which never calls ReviveTenant, so a reclaim leaves no tombstone:
		// the revive moves the generation, which still fences any late
		// pass of the removed tenant, and a pass that starts now is refused
		// for as long as the node does not list the tenant.
		if err := f.ReviveTenant(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// tenantLister is the tenant service's complete listing, which
// ReclaimWithdrawnTenants needs to prove a tenant gone.
type tenantLister interface {
	ListTenants(ctx context.Context) ([]qrdbsdk.ServiceTenantInfo, error)
}

// liveTenantNames returns the scoped names of the tenants svc lists.
func liveTenantNames(ctx context.Context, svc tenantLister) (map[string]struct{}, error) {
	infos, err := svc.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{}, len(infos))
	for i := range infos {
		if infos[i].ID != "" {
			names[scope.TenantName(infos[i].ID)] = struct{}{}
		}
	}
	return names, nil
}

// EnsureTenant provisions tenantID's login CA once: a P-256 signing key in the
// tenant's scope and a self-signed CA certificate over it, saved under the same
// name. An existing key is kept and its certificate validated, or issued if
// missing.
//
// A tenant RemoveTenant tore down is never provisioned again: teardown
// tombstones the tenant's claim before it deletes anything, and every pass
// checks the tombstone after its last write. A pass that sees it undoes what
// it wrote, so a pass that raced teardown leaves no CA material behind: either
// the pass wrote before the tombstone, and teardown's deletes come after, or
// its check comes after the tombstone, and it deletes its own writes.
func (f *tenantCAKeyFactory) EnsureTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant login CA key factory: empty tenant ID")
	}
	if removed, err := f.tenantLoginCARemoved(ctx, tenantID); err != nil || removed {
		return errors.Join(fmt.Errorf("tenant %q: %w", tenantID, errTenantLoginCARemoved), err)
	}
	// The generation this pass provisions under: a remove and revive of the
	// tenant ID bumps it, and every certificate write this pass makes checks
	// it first (see tenantLoginCAFenceWrite).
	generation, err := f.tenantLoginCAGeneration(ctx, tenantID)
	if err != nil {
		return err
	}
	fence := &tenantLoginCAFence{check: func(ctx context.Context) error {
		return f.checkTenantLoginCAGeneration(ctx, tenantID, generation)
	}}
	fence.claims, _ = f.claimStorage()
	ensureErr := f.ensureTenant(context.WithValue(ctx, tenantLoginCAFenceKey{}, fence), tenantID)
	removed, err := f.tenantLoginCARemoved(ctx, tenantID)
	if err != nil {
		// Teardown may have run: whether this pass's writes outlive it is
		// unknown, so the pass fails.
		return errors.Join(ensureErr, err)
	}
	if removed {
		base, baseErr := f.backend()
		if baseErr != nil {
			return errors.Join(fmt.Errorf("tenant %q: %w", tenantID, errTenantLoginCARemoved), baseErr)
		}
		claims, claimsErr := f.claimStorage()
		if claimsErr != nil {
			return errors.Join(fmt.Errorf("tenant %q: %w", tenantID, errTenantLoginCARemoved), claimsErr)
		}
		// Between the read above and the deletes, the tenant may have been
		// removed, created again and given a fresh key: the cleanup lease
		// keeps that revive out for the whole of the deletes, and a cleanup
		// that finds the tombstone gone deletes nothing.
		cleaned, errs := f.cleanTenantLoginCAMaterial(ctx, claims, base, tenantID)
		errs = append([]error{fmt.Errorf("tenant %q: %w", tenantID, errTenantLoginCARemoved)}, errs...)
		if !cleaned && fence.wrote.Load() {
			if current, genErr := f.tenantLoginCAGeneration(ctx, tenantID); genErr != nil {
				errs = append(errs, genErr)
			} else if current != generation {
				errs = append(errs, f.repairRevivedTenantLoginCA(ctx, tenantID)...)
			}
		}
		return errors.Join(errs...)
	}
	current, err := f.tenantLoginCAGeneration(ctx, tenantID)
	if err != nil {
		return errors.Join(ensureErr, err)
	}
	if current != generation {
		// The tenant was removed and created again while this pass ran: its
		// work belongs to the removed tenant. A write it made after its last
		// fence check may have replaced the new tenant's provenance or
		// certificate, so put those back over the key that is there now.
		errs := []error{fmt.Errorf("tenant %q (removed and created again during this pass): %w", tenantID, errTenantLoginCARemoved)}
		if fence.wrote.Load() {
			errs = append(errs, f.repairRevivedTenantLoginCA(ctx, tenantID)...)
		}
		return errors.Join(errs...)
	}
	if errors.Is(ensureErr, errTenantLoginCAClaimHeld) {
		// Name the holder: a holder on a lost host is released only when the
		// operator fences it (WithTenantLoginCAFencedHolders).
		if holder := f.tenantLoginCAClaimHolder(ctx, tenantID); holder != "" {
			ensureErr = fmt.Errorf("%w (claim holder %s)", ensureErr, holder)
		}
	}
	return ensureErr
}

// tenantLoginCAFenceKey carries a provisioning pass's *tenantLoginCAFence in
// its context.
type tenantLoginCAFenceKey struct{}

// tenantLoginCAFence is the generation fence of one provisioning pass: check
// refuses once the tenant was removed or revived, and wrote records that the
// pass wrote a certificate.
type tenantLoginCAFence struct {
	check func(context.Context) error
	wrote atomic.Bool
	// claims is the cluster claims store certificate publishes go through
	// (see publishTenantLoginCACert); nil publishes unguarded.
	claims storage.Backend
}

// tenantLoginCAFenceWrite runs before every certificate write of a
// provisioning pass: it refuses the write once the pass's generation is gone.
func tenantLoginCAFenceWrite(ctx context.Context) error {
	fence, _ := ctx.Value(tenantLoginCAFenceKey{}).(*tenantLoginCAFence)
	if fence == nil {
		return nil
	}
	if err := fence.check(ctx); err != nil {
		return err
	}
	fence.wrote.Store(true)
	return nil
}

// tenantLoginCAGenerationKey is the claims-storage key of a tenant ID's
// provisioning generation.
func tenantLoginCAGenerationKey(tenantID string) string {
	return "tenant-login-ca/generations/" + tenantLoginCAKeyName(tenantID)
}

// tenantLoginCAGeneration reads a tenant ID's provisioning generation (0
// until its first revive).
func (f *tenantCAKeyFactory) tenantLoginCAGeneration(ctx context.Context, tenantID string) (uint64, error) {
	claims, err := f.claimStorage()
	if err != nil {
		return 0, err
	}
	raw, err := claims.Get(ctx, tenantLoginCAGenerationKey(tenantID))
	if errors.Is(err, storage.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("tenant login CA key factory: read generation of tenant %q: %w", tenantID, err)
	}
	n, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("tenant login CA key factory: generation of tenant %q: %w", tenantID, err)
	}
	return n, nil
}

// checkTenantLoginCAGeneration refuses once the tenant was removed, or
// revived past generation.
func (f *tenantCAKeyFactory) checkTenantLoginCAGeneration(ctx context.Context, tenantID string, generation uint64) error {
	removed, err := f.tenantLoginCARemoved(ctx, tenantID)
	if err != nil {
		return err
	}
	current, err := f.tenantLoginCAGeneration(ctx, tenantID)
	if err != nil {
		return err
	}
	if removed || current != generation {
		return fmt.Errorf("tenant %q: %w", tenantID, errTenantLoginCARemoved)
	}
	return nil
}

// bumpTenantLoginCAGeneration advances a tenant ID's provisioning generation.
func bumpTenantLoginCAGeneration(ctx context.Context, claims storage.Backend, tenantID string) error {
	key := tenantLoginCAGenerationKey(tenantID)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		cur, err := claims.Get(ctx, key)
		if errors.Is(err, storage.ErrNotFound) {
			stored, putErr := claims.PutIfAbsent(ctx, key, []byte("1"))
			if putErr != nil || stored {
				return putErr
			}
			continue
		}
		if err != nil {
			return err
		}
		n, err := strconv.ParseUint(string(cur), 10, 64)
		if err != nil {
			return fmt.Errorf("generation %q: %w", cur, err)
		}
		next := []byte(strconv.FormatUint(n+1, 10))
		swapper, ok := claims.(storage.CompareAndSwapper)
		if !ok {
			return claims.Put(ctx, key, next)
		}
		swapped, _, err := swapper.CompareAndSwap(ctx, key, cur, next)
		if err != nil || swapped {
			return err
		}
	}
}

// repairRevivedTenantLoginCA puts back the provenance and certificate of a
// revived tenant that a pass of its removed generation overwrote: a stored
// one whose public key is not the stored key's is signed again over the key
// there now, or deleted when there is no key yet (its pass writes them).
func (f *tenantCAKeyFactory) repairRevivedTenantLoginCA(ctx context.Context, tenantID string) []error {
	base, err := f.backend()
	if err != nil {
		return []error{err}
	}
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	var signer crypto.Signer
	attrs, err := tenantLoginCAKeyAttrs(ctx, base, tenantID)
	switch {
	case err == nil:
		if signer, err = scoped.Signer(ctx, attrs); err != nil {
			return []error{fmt.Errorf("tenant login CA key factory: signer for tenant %q: %w", tenantID, err)}
		}
	case !errors.Is(err, errTenantLoginCAKeyNotFound):
		return []error{err}
	}
	var errs []error
	for _, certID := range []string{tenantLoginCAProvenanceID, tenantLoginCAKeyCN} {
		exists, err := scoped.CertExists(ctx, certID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !exists {
			continue
		}
		cert, err := scoped.GetCert(ctx, certID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if signer != nil {
			if pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok && pub.Equal(signer.Public()) {
				continue
			}
			var fixed *x509.Certificate
			if certID == tenantLoginCAKeyCN {
				fixed, err = f.publishedTenantLoginCACert(ctx, tenantID, signer)
			} else {
				fixed, err = selfSignTenantLoginCA(tenantID, signer)
			}
			if err == nil {
				err = scoped.SaveCert(ctx, certID, fixed)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("tenant login CA key factory: repair %s of tenant %q: %w", certID, tenantID, err))
			}
			continue
		}
		if err := scoped.DeleteCert(ctx, certID); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// publishedTenantLoginCACert returns the login CA certificate the live
// generation of tenantID published (the DER go-qrdb registers as the tenant's
// issuer). A repair writes it back rather than signing a new one, since a
// fresh certificate would not be the registered issuer. It fails closed when
// no certificate over signer's key is published.
func (f *tenantCAKeyFactory) publishedTenantLoginCACert(ctx context.Context, tenantID string, signer crypto.Signer) (*x509.Certificate, error) {
	claims, err := f.claimStorage()
	if err != nil {
		return nil, err
	}
	held, err := claims.Get(ctx, tenantLoginCACertPublishKey(tenantID))
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: read published certificate for tenant %q: %w", tenantID, err)
	}
	cert, err := x509.ParseCertificate(held)
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: parse published certificate for tenant %q: %w", tenantID, err)
	}
	if !tenantLoginCACertFor(cert, signer.Public()) {
		return nil, fmt.Errorf("tenant login CA key factory: published certificate of tenant %q is not over its stored key", tenantID)
	}
	return cert, nil
}

// ensureTenant is one provisioning pass of EnsureTenant.
func (f *tenantCAKeyFactory) ensureTenant(ctx context.Context, tenantID string) error {
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
	defer tenantLoginCALiveOwners.Delete(owner)
	attrs := tenantLoginCAKeyGenAttrs(tenantID)
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
	// The claim now says a generate is in flight, and no pass takes it
	// over while this pass runs: a backend may ignore the context (PKCS#11
	// waits on the token's mutex without a deadline), so no lease bounds
	// when this pass can still make its key.
	tenantLoginCAGenerateHook(tenantID)
	// Teardown may have replaced the claim since (it fences a holder the
	// operator named, or one whose process ended): re-check it is still
	// this pass's generating claim, so a fenced pass makes no key.
	if err := f.checkTenantLoginCAGenerating(ctx, tenantID, generating); err != nil {
		return err
	}
	_, err = scoped.GenerateECDSA(ctx, attrs)
	// The generate returned, so it makes no key any more: put back a plain
	// claim, which teardown may replace and a later pass may take over once
	// its lease runs out and no key is behind it. Writes this pass still
	// makes are fenced by EnsureTenant's tombstone check.
	f.releaseTenantLoginCAGenerating(ctx, tenantID, owner, generating)
	if err != nil {
		if !errors.Is(err, backend.ErrKeyAlreadyExists) {
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
	// The owner is live before its claim is written; a pass that wins the
	// claim keeps it live until EnsureTenant returns.
	tenantLoginCALiveOwners.Store(owner, struct{}{})
	won := false
	defer func() {
		if !won {
			tenantLoginCALiveOwners.Delete(owner)
		}
	}()
	key := tenantLoginCAClaimKey(tenantID)
	claim := tenantLoginCAClaim(owner, time.Now())
	stored, err := claims.PutIfAbsent(ctx, key, claim)
	if err != nil {
		return "", fmt.Errorf("tenant login CA key factory: claim tenant %q: %w", tenantID, err)
	}
	if stored {
		won = true
		return owner, nil
	}
	held, err := claims.Get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("tenant login CA key factory: read claim of tenant %q: %w", tenantID, err)
	}
	if tenantLoginCAClaimIsRemoved(held) {
		return "", fmt.Errorf("tenant %q: %w", tenantID, errTenantLoginCARemoved)
	}
	if at, _, parseErr := parseTenantLoginCAClaim(held); parseErr == nil && time.Since(at) < tenantLoginCAClaimLease {
		return "", nil
	}
	if tenantLoginCAClaimGenerating(held) {
		// Its owner may still be inside a generate that no lease bounds,
		// and an unchanged claim does not prove it stopped: taking over
		// could make a second key beside the one it makes. Take it over
		// only on proof that its owner's process ended, or once the
		// operator fenced its host and named it a fenced holder.
		if _, heldOwner, _ := parseTenantLoginCAClaim(held); !tenantLoginCAHolderStopped(heldOwner) && !f.fencedHolder(heldOwner) {
			return "", nil
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
	won = true
	return owner, nil
}

// fenceTenantLoginCAClaim is the last step before generation: it confirms
// the pass still owns the tenant's claim and marks the claim generating, and
// returns the claim it wrote. A claim older than the lease does not prove
// its owner stopped: a pass delayed past the lease may have lost the claim
// to a takeover, and it must not generate beside the new owner's key. The
// mark is a compare-and-swap on the owner's own claim, so a takeover and the
// mark never both succeed; a generating claim is taken over only once its
// owner provably stopped (see tenantLoginCAHolderStopped).
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
	host, _ := os.Hostname()
	return tenantLoginCAClaimOwner(fmt.Sprintf("%x", token), tenantLoginCAProcess, os.Getpid(), host), nil
}

// tenantLoginCAClaimOwner is a claim owner: the pass's token, then the
// process, PID and host it runs in, so a later pass can tell whether the
// holder's process ended. No part holds a space or a "/".
func tenantLoginCAClaimOwner(token, process string, pid int, host string) string {
	return fmt.Sprintf("%s/%s/%d/%s", token, process, pid, tenantLoginCAClaimHost(host))
}

// tenantLoginCAClaimHost is host as a claim owner carries it.
func tenantLoginCAClaimHost(host string) string {
	return strings.NewReplacer(" ", "_", "/", "_").Replace(host)
}

// tenantLoginCAHolderStopped reports whether the pass that wrote a generating
// claim as owner provably stopped, so its generate can make no key any more.
// Only the holder's own host can prove it: a pass of this process is stopped
// once it returned; a pass of another process on this host is stopped once
// that process's PID no longer runs, or is this process's own (a restart
// that reused it). Anything else, a holder on another host included, is not
// proof, and its claim stays held.
func tenantLoginCAHolderStopped(owner string) bool {
	parts := strings.SplitN(owner, "/", 4)
	if len(parts) != 4 {
		return false
	}
	process, host := parts[1], parts[3]
	pid, err := strconv.Atoi(parts[2])
	if err != nil || pid <= 0 || process == "" || tenantLoginCAProcess == "" {
		return false
	}
	thisHost, err := os.Hostname()
	if err != nil || thisHost == "" || tenantLoginCAClaimHost(thisHost) != host {
		return false
	}
	if process == tenantLoginCAProcess {
		_, live := tenantLoginCALiveOwners.Load(owner)
		return !live
	}
	if pid == os.Getpid() {
		return true
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return errors.Is(proc.Signal(syscall.Signal(0)), os.ErrProcessDone)
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
	if err := tenantLoginCAFenceWrite(ctx); err != nil {
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
	claims, err := f.claimStorage()
	if err != nil {
		return err
	}
	// The tombstone goes first, through the same claim every pass takes: no
	// pass claims or generates after it, and a pass already running sees it
	// after its last write and undoes that write (see EnsureTenant).
	if err := f.tombstoneTenantLoginCAClaim(ctx, claims, tenantID); err != nil {
		return fmt.Errorf("tenant login CA key factory: remove tenant %q: tombstone claim: %w", tenantID, err)
	}
	for {
		cleaned, errs := f.cleanTenantLoginCAMaterial(ctx, claims, base, tenantID)
		if len(errs) > 0 {
			return fmt.Errorf("tenant login CA key factory: remove tenant %q: %w", tenantID, errors.Join(errs...))
		}
		if cleaned {
			return nil
		}
		// Another cleanup holds the lease, or the tenant was created again
		// after the tombstone: wait for the lease, and leave a revived
		// tenant's material alone.
		removed, err := f.tenantLoginCARemoved(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("tenant login CA key factory: remove tenant %q: %w", tenantID, err)
		}
		if !removed {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("tenant login CA key factory: remove tenant %q: wait for cleanup lease: %w", tenantID, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// ReviveTenant clears the teardown tombstone of a tenant created again under
// the ID RemoveTenant tore down (a create retried after its undo), so
// EnsureTenant provisions it anew. Nothing but RemoveTenant writes over a
// tombstone, and it leaves one in place, so reading it and then deleting it
// races no other writer. A tenant without a tombstone is left as it is.
func (f *tenantCAKeyFactory) ReviveTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant login CA key factory: empty tenant ID")
	}
	removed, err := f.tenantLoginCARemoved(ctx, tenantID)
	if err != nil || !removed {
		return err
	}
	claims, err := f.claimStorage()
	if err != nil {
		return err
	}
	// The generation moves before the tombstone goes: a pass of the removed
	// tenant that resumes now finds its generation gone and writes nothing.
	if err := bumpTenantLoginCAGeneration(ctx, claims, tenantID); err != nil {
		return fmt.Errorf("tenant login CA key factory: revive tenant %q: bump generation: %w", tenantID, err)
	}
	key := tenantLoginCAClaimKey(tenantID)
	deleter, ok := claims.(storage.CompareAndDeleter)
	if !ok {
		if err := claims.Delete(ctx, key); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("tenant login CA key factory: revive tenant %q: %w", tenantID, err)
		}
		return nil
	}
	// Only a plain tombstone, or the lease of a cleanup that stopped, goes:
	// a live cleanup deletes the removed generation's material by tenant and
	// name, and a fresh key provisioned beside it would go with it.
	for {
		held, err := claims.Get(ctx, key)
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tenant login CA key factory: revive tenant %q: %w", tenantID, err)
		}
		if !tenantLoginCAClaimIsRemoved(held) {
			return nil
		}
		if holder := tenantLoginCAClaimCleanupOwner(held); holder != "" && !tenantLoginCAHolderStopped(holder) && !f.fencedHolder(holder) {
			return fmt.Errorf("tenant login CA key factory: revive tenant %q: %w (cleanup holder %s)", tenantID, errTenantLoginCAClaimHeld, holder)
		}
		deleted, err := deleter.CompareAndDelete(ctx, key, held)
		if err != nil {
			return fmt.Errorf("tenant login CA key factory: revive tenant %q: %w", tenantID, err)
		}
		if deleted {
			return nil
		}
	}
}

// errTenantLoginCARemoved reports a tenant whose login CA RemoveTenant tore
// down: its claim is a tombstone, and no pass provisions it again.
var errTenantLoginCARemoved = errors.New("tenant login CA key factory: the tenant's login CA was removed")

// tenantLoginCAClaimRemovedValue is the claim value of a torn-down tenant.
// It holds no time, so no pass parses it as a claim it may take over.
const tenantLoginCAClaimRemovedValue = "removed"

// tenantLoginCAClaimIsRemoved reports whether claim is a teardown tombstone.
func tenantLoginCAClaimIsRemoved(claim []byte) bool {
	return string(claim) == tenantLoginCAClaimRemovedValue || strings.HasPrefix(string(claim), tenantLoginCAClaimCleanupPrefix)
}

// tenantLoginCAClaimCleanupPrefix marks a tombstone a cleanup holds as its
// lease: "removed cleanup <owner>". The tenant stays removed while it is held,
// and ReviveTenant refuses to clear it, so no new generation provisions while
// the cleanup deletes the removed one's material.
const tenantLoginCAClaimCleanupPrefix = tenantLoginCAClaimRemovedValue + " cleanup "

// tenantLoginCAClaimCleanupOwner returns the owner of a cleanup lease, or ""
// when claim is not one.
func tenantLoginCAClaimCleanupOwner(claim []byte) string {
	owner, ok := strings.CutPrefix(string(claim), tenantLoginCAClaimCleanupPrefix)
	if !ok {
		return ""
	}
	return owner
}

// cleanTenantLoginCAMaterial deletes a removed tenant's login CA material
// under a cleanup lease: it swaps the plain tombstone for one naming this
// pass, deletes, and puts the plain tombstone back. ReviveTenant clears only a
// plain tombstone (or the lease of a stopped holder), so a revive and a fresh
// key cannot land while this deletes by tenant and name. cleaned is false when
// the tombstone was no longer plain: the tenant was revived (its material
// belongs to the new generation) or another cleanup holds the lease.
func (f *tenantCAKeyFactory) cleanTenantLoginCAMaterial(ctx context.Context, claims storage.Backend, base xkms.Backend, tenantID string) (cleaned bool, errs []error) {
	swapper, ok := claims.(storage.CompareAndSwapper)
	if !ok {
		// Claim storage without a guarded swap cannot hold a lease; it
		// cannot fence a revive either (see ReviveTenant).
		return true, deleteTenantLoginCAMaterial(ctx, base, tenantID)
	}
	owner, err := newTenantLoginCAClaimOwner()
	if err != nil {
		return false, []error{err}
	}
	key := tenantLoginCAClaimKey(tenantID)
	removed := []byte(tenantLoginCAClaimRemovedValue)
	lease := []byte(tenantLoginCAClaimCleanupPrefix + owner)
	tenantLoginCALiveOwners.Store(owner, struct{}{})
	defer tenantLoginCALiveOwners.Delete(owner)
	expected := removed
	if held, getErr := claims.Get(ctx, key); getErr == nil {
		// The lease of a cleanup that stopped before it put the plain
		// tombstone back is taken over.
		if holder := tenantLoginCAClaimCleanupOwner(held); holder != "" && (tenantLoginCAHolderStopped(holder) || f.fencedHolder(holder)) {
			expected = held
		}
	}
	swapped, _, err := swapper.CompareAndSwap(ctx, key, expected, lease)
	if err != nil {
		return false, []error{fmt.Errorf("tenant login CA key factory: lease cleanup of tenant %q: %w", tenantID, err)}
	}
	if !swapped {
		return false, nil
	}
	errs = deleteTenantLoginCAMaterial(ctx, base, tenantID)
	if _, _, err := swapper.CompareAndSwap(context.WithoutCancel(ctx), key, lease, removed); err != nil {
		// The lease stays; once this pass returns its holder is stopped,
		// and ReviveTenant clears it then.
		errs = append(errs, fmt.Errorf("tenant login CA key factory: release cleanup lease of tenant %q: %w", tenantID, err))
	}
	return true, errs
}

// tombstoneTenantLoginCAClaim replaces the tenant's claim with the teardown
// tombstone: written with PutIfAbsent or compare-and-swap, so a claim or
// takeover racing it either lands first and is replaced, or finds the
// tombstone. A claim marked generating by a holder that may still run is not
// replaced: errTenantLoginCAClaimHeld, and teardown retries.
func (f *tenantCAKeyFactory) tombstoneTenantLoginCAClaim(ctx context.Context, claims storage.Backend, tenantID string) error {
	key := tenantLoginCAClaimKey(tenantID)
	removed := []byte(tenantLoginCAClaimRemovedValue)
	waitUntil := time.Now().Add(tenantLoginCATeardownWait)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		stored, err := claims.PutIfAbsent(ctx, key, removed)
		if err != nil {
			return err
		}
		if stored {
			return nil
		}
		held, err := claims.Get(ctx, key)
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if tenantLoginCAClaimIsRemoved(held) {
			return nil
		}
		if tenantLoginCAClaimGenerating(held) {
			// A generate may be in flight, and a key it makes after the
			// deletes would outlive teardown: wait for it to return, or for
			// proof (or the operator's fence) that its holder stopped.
			if _, heldOwner, _ := parseTenantLoginCAClaim(held); !tenantLoginCAHolderStopped(heldOwner) && !f.fencedHolder(heldOwner) {
				if time.Now().After(waitUntil) {
					return fmt.Errorf("%w (claim holder %s)", errTenantLoginCAClaimHeld, heldOwner)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(20 * time.Millisecond):
				}
				continue
			}
		}
		swapper, ok := claims.(storage.CompareAndSwapper)
		if !ok {
			return claims.Put(ctx, key, removed)
		}
		swapped, _, err := swapper.CompareAndSwap(ctx, key, held, removed)
		if err != nil {
			return err
		}
		if swapped {
			return nil
		}
	}
}

// tenantLoginCARemoved reports whether the tenant's claim is a teardown
// tombstone. A storage error leaves it unknown and is returned.
func (f *tenantCAKeyFactory) tenantLoginCARemoved(ctx context.Context, tenantID string) (bool, error) {
	claims, err := f.claimStorage()
	if err != nil {
		return false, err
	}
	held, err := claims.Get(ctx, tenantLoginCAClaimKey(tenantID))
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("tenant login CA key factory: read claim of tenant %q: %w", tenantID, err)
	}
	return tenantLoginCAClaimIsRemoved(held), nil
}

// tenantLoginCAClaimHolder is the owner named by the tenant's claim, or "".
func (f *tenantCAKeyFactory) tenantLoginCAClaimHolder(ctx context.Context, tenantID string) string {
	claims, err := f.claimStorage()
	if err != nil {
		return ""
	}
	held, err := claims.Get(ctx, tenantLoginCAClaimKey(tenantID))
	if err != nil {
		return ""
	}
	_, owner, parseErr := parseTenantLoginCAClaim(held)
	if parseErr != nil {
		return ""
	}
	return owner
}

// FenceHolders names the claim holders whose hosts the operator fenced: each
// is a claim owner a lost host left marked generating (EnsureTenant's
// "claim holder" error names it). A pass takes such a claim over as if its
// holder had provably stopped. Naming a holder whose host may still run is
// unsafe: its generate could make a second key.
func (f *tenantCAKeyFactory) FenceHolders(owners []string) {
	fenced := make(map[string]struct{}, len(owners))
	for _, owner := range owners {
		if owner = strings.TrimSpace(owner); owner != "" {
			fenced[owner] = struct{}{}
		}
	}
	f.mu.Lock()
	f.fenced = fenced
	f.mu.Unlock()
}

// fencedHolder reports whether the operator fenced owner's host.
func (f *tenantCAKeyFactory) fencedHolder(owner string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.fenced[owner]
	return ok
}

// deleteTenantLoginCAMaterial deletes the tenant's login CA certificate,
// provenance and intent records and its key, and returns what failed. A
// lookup error other than absence leaves the key in place and is returned.
func deleteTenantLoginCAMaterial(ctx context.Context, base xkms.Backend, tenantID string) []error {
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
		errs = append(errs, lookupErr)
	}
	return errs
}

// ensureTenantLoginCACert makes sure the tenant's saved login CA certificate is
// a valid CA certificate over the key attrs names, issuing and saving one if it
// is missing or does not match. A certificate another node saved first wins.
// tenantLoginCACertPublishHook runs after a pass finds the tenant's login CA
// certificate missing or invalid and before it publishes one. Tests set it to
// interleave passes; it is a no-op otherwise.
var tenantLoginCACertPublishHook = func(string) {}

// tenantLoginCAGenerateHook runs after a pass holds the generating claim and
// before it generates the key. Tests set it to interleave teardown; it is a
// no-op otherwise.
var tenantLoginCAGenerateHook = func(string) {}

// checkTenantLoginCAGenerating fails unless the tenant's claim is still
// exactly the generating claim this pass put, so a pass whose claim teardown
// tombstoned or recovery fenced makes no key.
func (f *tenantCAKeyFactory) checkTenantLoginCAGenerating(ctx context.Context, tenantID string, generating []byte) error {
	claims, err := f.claimStorage()
	if err != nil {
		return err
	}
	held, err := claims.Get(ctx, tenantLoginCAClaimKey(tenantID))
	if err != nil {
		return fmt.Errorf("tenant login CA key factory: re-check claim of tenant %q: %w", tenantID, err)
	}
	if !bytes.Equal(held, generating) {
		return fmt.Errorf("tenant %q: claim replaced before generate: %w", tenantID, errTenantLoginCARemoved)
	}
	return nil
}

func ensureTenantLoginCACert(ctx context.Context, scoped *xkms.TenantScopedBackend, tenantID string, signer crypto.Signer) error {
	if tenantLoginCACertValid(ctx, scoped, signer.Public()) {
		return nil
	}
	tenantLoginCACertPublishHook(tenantID)
	cert, err := publishTenantLoginCACert(ctx, scoped, tenantID, signer)
	if err != nil {
		return err
	}
	if err := tenantLoginCAFenceWrite(ctx); err != nil {
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

// tenantLoginCACertPublishKey is the claims-storage key of the tenant's
// published login CA certificate (its DER).
func tenantLoginCACertPublishKey(tenantID string) string {
	return "tenant-login-ca/certs/" + tenantLoginCAKeyName(tenantID)
}

// publishTenantLoginCACert returns the certificate the pass must store: the
// one already published in the claims store when it is a valid CA
// certificate over signer's key, else a fresh one published there with a
// create-if-absent (or compare-and-swap over a stale record) write. Two passes
// that both found the certificate missing thus store the same DER, the first
// published, which a listener may already trust. Without a claims store in
// the pass's fence it signs a fresh certificate unguarded.
func publishTenantLoginCACert(ctx context.Context, scoped *xkms.TenantScopedBackend, tenantID string, signer crypto.Signer) (*x509.Certificate, error) {
	fence, _ := ctx.Value(tenantLoginCAFenceKey{}).(*tenantLoginCAFence)
	if fence == nil || fence.claims == nil {
		return selfSignTenantLoginCA(tenantID, signer)
	}
	claims := fence.claims
	key := tenantLoginCACertPublishKey(tenantID)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		held, err := claims.Get(ctx, key)
		switch {
		case err == nil:
			if winner, parseErr := x509.ParseCertificate(held); parseErr == nil && tenantLoginCACertFor(winner, signer.Public()) {
				return winner, nil
			}
		case !errors.Is(err, storage.ErrNotFound):
			return nil, fmt.Errorf("tenant login CA key factory: read published certificate for tenant %q: %w", tenantID, err)
		}
		cert, err := selfSignTenantLoginCA(tenantID, signer)
		if err != nil {
			return nil, err
		}
		if err := tenantLoginCAFenceWrite(ctx); err != nil {
			return nil, err
		}
		var won bool
		if held == nil {
			won, err = claims.PutIfAbsent(ctx, key, cert.Raw)
		} else if swapper, ok := claims.(storage.CompareAndSwapper); ok {
			won, _, err = swapper.CompareAndSwap(ctx, key, held, cert.Raw)
		} else {
			won, err = true, claims.Put(ctx, key, cert.Raw)
		}
		if err != nil {
			return nil, fmt.Errorf("tenant login CA key factory: publish certificate for tenant %q: %w", tenantID, err)
		}
		if won {
			return cert, nil
		}
		// Another pass published first: adopt its certificate.
	}
}

// tenantLoginCACertFor reports whether cert is a currently valid CA
// certificate over pub.
func tenantLoginCACertFor(cert *x509.Certificate, pub crypto.PublicKey) bool {
	if cert == nil || !cert.IsCA {
		return false
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}
	certPub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && certPub.Equal(pub)
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
	// A listing that succeeds is not a complete one: PKCS#11 skips an
	// object whose attributes it could not read, and Azure a key whose
	// metadata read failed. Absence is only what an exact lookup of the key
	// this path makes reports as not found; any other lookup failure is
	// not absence.
	exact := tenantLoginCAKeyGenAttrs(tenantID)
	exact.TenantID = tenantID
	if _, err := xkms.NewTenantScopedBackend(base, tenantID).Signer(ctx, exact); err != nil {
		if errors.Is(err, backend.ErrKeyNotFound) || errors.Is(err, xkms.ErrKeyNotFound) {
			return nil, errTenantLoginCAKeyNotFound
		}
		return nil, fmt.Errorf("tenant login CA key factory: look up key of tenant %q: %w", tenantID, err)
	}
	return exact, nil
}

// tenantLoginCAKeyGenAttrs are the attributes of the login CA key this path
// generates for a tenant.
func tenantLoginCAKeyGenAttrs(tenantID string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            tenantLoginCAKeyName(tenantID),
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
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
	// they issued on an upgrade (see WithTenantLoginCAKeys).
	if !s.tenantLoginCAKeys || !s.trustedCAIsClusterCA() {
		return nil
	}
	f := newTenantCAKeyFactory()
	// Left unbound here: the node starts before the key backends exist, and
	// its background trust refresh would read s.backends while New writes
	// it. provisionTenantCAKeys binds the factory once they are ready.
	s.tenantCAKeys = f
	return []qrdbnode.NodeOption{qrdbnode.WithCertKeyProviderFactory(f)}
}

// WithTenantLoginCAKeys is the node construction option (SPEC row
// qrdb-crypto-provider-seam) that has the embedded qrdb node sign each
// tenant's login CA with a tenant-scoped xkms key, passed to the node as its
// cert key provider factory. Off by default: go-qrdb keeps the tenant login
// CAs it already persisted. Turning it on replaces those CAs with fresh
// xkms-held keys and certificates, so login certificates issued under the old
// CAs stop chaining to a trusted issuer. Only meaningful when the TrustedCA is
// the cluster CA.
func WithTenantLoginCAKeys() Option {
	return func(s *Server) { s.tenantLoginCAKeys = true }
}

// WithTenantLoginCAFencedHolders is the recovery for a tenant login CA
// provisioning claim a lost host left marked generating: no other host can
// prove that host's generate stopped, so the claim is held and the boot pass
// fails with an error naming the "claim holder". After fencing that host
// (powered off, or its HSM session revoked) the embedder passes the named
// holder here; the boot pass then takes the claim over. Passing a holder
// whose host may still run is unsafe: its generate could leave a second key.
func WithTenantLoginCAFencedHolders(holders ...string) Option {
	return func(s *Server) {
		s.tenantLoginCAFencedHolders = append(s.tenantLoginCAFencedHolders, holders...)
	}
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
