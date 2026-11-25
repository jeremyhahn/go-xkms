package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TenantProvisionError reports a tenant whose login CA key could not be
// provisioned. TenantID is empty when the tenants could not be listed. Err
// never carries key material.
type TenantProvisionError struct {
	TenantID string
	Err      error
}

func (e *TenantProvisionError) Error() string {
	if e.TenantID == "" {
		return fmt.Sprintf("provision tenant login CA keys: %v", e.Err)
	}
	return fmt.Sprintf("provision login CA key for tenant %q: %v", e.TenantID, e.Err)
}

func (e *TenantProvisionError) Unwrap() error { return e.Err }

// tenantCAKeyProvisioner provisions a tenant's login CA key once and
// removes it at teardown; tenantCAKeyFactory implements it.
type tenantCAKeyProvisioner interface {
	EnsureTenant(ctx context.Context, tenantID string) error
	RemoveTenant(ctx context.Context, tenantID string) error
	ReviveTenant(ctx context.Context, tenantID string) error
}

// provisioningTenantService is the node's tenant service with one change:
// a tenant it creates gets its login CA key at once, so the factory wired
// through WithCertKeyProviderFactory never meets an unprovisioned tenant.
type provisioningTenantService struct {
	qrdbsdk.ServiceTenantServicer
	keys tenantCAKeyProvisioner
}

func newProvisioningTenantService(svc qrdbsdk.ServiceTenantServicer, keys tenantCAKeyProvisioner) *provisioningTenantService {
	return &provisioningTenantService{ServiceTenantServicer: svc, keys: keys}
}

// CreateTenant creates the tenant, then provisions its login CA key. When the
// key cannot be provisioned the create is undone, so no tenant exists whose
// logins would fail and the tenant ID can be created again.
func (p *provisioningTenantService) CreateTenant(ctx context.Context, id, name string, isolationType qrdbsdk.TenantIsolationType, opts ...qrdbsdk.CreateTenantOption) (*qrdbsdk.ServiceTenantInfo, error) {
	info, err := p.ServiceTenantServicer.CreateTenant(ctx, id, name, isolationType, opts...)
	if err != nil {
		return nil, err
	}
	// The tenant is new: a login CA an earlier tenant under this ID tore
	// down does not keep it from being provisioned. A create can reach this
	// ID only after an earlier rollback of it finished, so a rollback record
	// left for the ID is stale.
	var ensureErr error
	if rec, ok := p.keys.(tenantCreateUndoRecorder); ok {
		ensureErr = rec.ClearCreateUndo(ctx, info.ID)
	}
	if ensureErr == nil {
		ensureErr = p.keys.ReviveTenant(ctx, info.ID)
	}
	if ensureErr == nil {
		ensureErr = p.keys.EnsureTenant(ctx, info.ID)
	}
	if ensureErr != nil {
		return nil, &TenantProvisionError{
			TenantID: info.ID,
			Err:      errors.Join(ensureErr, p.undoCreate(ctx, info.ID, info.CreatedAt)),
		}
	}
	return info, nil
}

// tenantCreateUndoTimeout bounds the rollback of a create whose login CA
// could not be provisioned.
const tenantCreateUndoTimeout = 30 * time.Second

// tenantCreateUndoRecorder persists a create rollback across restarts;
// tenantCAKeyFactory implements it. A provisioner without it rolls back
// without a record.
type tenantCreateUndoRecorder interface {
	MarkCreateUndo(ctx context.Context, tenantID string, createdAt time.Time) error
	createUndoPendingFor(ctx context.Context, tenantID string, createdAt time.Time) (bool, error)
	ClearCreateUndo(ctx context.Context, tenantID string) error
	tenantLoginCARemoved(ctx context.Context, tenantID string) (bool, error)
}

// undoCreate rolls back a create that did not complete. It undoes the create
// rather than deleting the tenant, so the tenant ID stays free for a retry,
// and it runs on its own bounded context: a request cancelled during
// provisioning must not leave the tenant behind.
func (p *provisioningTenantService) undoCreate(ctx context.Context, id string, createdAt time.Time) error {
	undoCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tenantCreateUndoTimeout)
	defer cancel()
	// The rollback is recorded before the CA cleanup tombstones the ID: a
	// cleanup that fails leaves the tenant listed beside its tombstone, and
	// the boot pass resumes the recorded rollback once the key backend
	// recovers. When the record cannot be written nothing is torn down, so
	// the tenant has no tombstone and the boot pass provisions it.
	rec, recorded := p.keys.(tenantCreateUndoRecorder)
	if recorded {
		if err := rec.MarkCreateUndo(undoCtx, id, createdAt); err != nil {
			return err
		}
	}
	// The tenant record fences the ID until its login CA material is gone:
	// undoing it first would let a concurrent create reuse the ID, adopt
	// the saved key, and then have this rollback tombstone its CA. When the
	// CA cleanup fails the tenant stays, still fencing the ID, for the boot
	// pass or DeleteTenant to finish.
	if err := p.keys.RemoveTenant(undoCtx, id); err != nil {
		return err
	}
	if err := p.UndoCreateTenant(undoCtx, id); err != nil {
		return err
	}
	if recorded {
		return rec.ClearCreateUndo(undoCtx, id)
	}
	return nil
}

// DeleteTenant deletes the tenant, then its login CA key and certificate, so
// the CA a deleted tenant's logins chained to does not outlive it.
func (p *provisioningTenantService) DeleteTenant(ctx context.Context, id string) error {
	if err := p.ServiceTenantServicer.DeleteTenant(ctx, id); err != nil {
		return err
	}
	return p.keys.RemoveTenant(ctx, id)
}

// adoptTenantService installs the node's tenant service, wrapped to
// provision login CA keys when the tenant login CA key factory is wired.
func (s *Server) adoptTenantService(svc qrdbsdk.ServiceTenantServicer) {
	if svc == nil || s.tenantCAKeys == nil {
		s.tenantService = svc
		return
	}
	s.tenantService = newProvisioningTenantService(svc, s.tenantCAKeys)
}

// provisionTenantCAKeys is the boot pass: every tenant, the system tenant
// included, gets its login CA key before the server serves. It first binds
// the factory to the server's default backend, which exists only from here
// on. It is a no-op when the factory is not wired, and idempotent otherwise.
func (s *Server) provisionTenantCAKeys(ctx context.Context) error {
	if s.tenantCAKeys == nil || s.tenantService == nil {
		return nil
	}
	base, err := s.tenantCAKeyBackend()
	if err != nil {
		return &TenantProvisionError{Err: err}
	}
	if err := s.tenantCAKeys.Bind(base, s.sharedStorage()); err != nil {
		return &TenantProvisionError{Err: err}
	}
	s.tenantCAKeys.FenceHolders(s.tenantLoginCAFencedHolders)
	s.tenantCAKeys.TrackTenants(s.tenantService)
	return provisionTenantCAKeysWith(ctx, s.tenantService, s.tenantCAKeys)
}

// resumeTenantCreateUndo prepares a listed tenant for the boot pass. A
// tenant whose create rollback was recorded and never finished (its login CA
// cleanup failed) has that rollback finished here: its CA material is
// removed, the create undone and the record cleared, and resumed is true so
// the tenant gets no CA. An error leaves the record for the next boot. A
// tombstoned tenant with no pending rollback was created natively under an
// ID whose rollback had finished: it is new, so its tombstone is cleared
// (as ProviderForTenant's no-key branch does) and EnsureTenant provisions it.
// A rollback record is acted on only when it names this tenant instance
// (createdAt); a record of an earlier instance under the ID is cleared.
func resumeTenantCreateUndo(ctx context.Context, svc qrdbsdk.ServiceTenantServicer, keys tenantCAKeyProvisioner, rec tenantCreateUndoRecorder, id string, createdAt time.Time) (resumed bool, err error) {
	pending, err := rec.createUndoPendingFor(ctx, id, createdAt)
	if err != nil {
		return false, err
	}
	if pending {
		if err := keys.RemoveTenant(ctx, id); err != nil {
			return false, fmt.Errorf("resume create rollback: %w", err)
		}
		if err := svc.UndoCreateTenant(ctx, id); err != nil {
			return false, fmt.Errorf("resume create rollback: %w", err)
		}
		return true, rec.ClearCreateUndo(ctx, id)
	}
	removed, err := rec.tenantLoginCARemoved(ctx, id)
	if err != nil {
		return false, err
	}
	if removed {
		return false, keys.ReviveTenant(ctx, id)
	}
	return false, nil
}

// provisionTenantCAKeysWith provisions every listed tenant's login CA key,
// first resuming a create rollback a restart interrupted (see
// resumeTenantCreateUndo); the system tenant is provisioned as is.
func provisionTenantCAKeysWith(ctx context.Context, svc qrdbsdk.ServiceTenantServicer, keys tenantCAKeyProvisioner) error {
	infos, err := svc.ListTenants(ctx)
	if err != nil {
		return &TenantProvisionError{Err: err}
	}
	ids := []string{qrdbsdk.SystemTenantID}
	created := make(map[string]time.Time, len(infos))
	for i := range infos {
		if id := infos[i].ID; id != "" && id != qrdbsdk.SystemTenantID {
			ids = append(ids, id)
			created[id] = infos[i].CreatedAt
		}
	}
	rec, recorded := keys.(tenantCreateUndoRecorder)
	for _, id := range ids {
		if recorded && id != qrdbsdk.SystemTenantID {
			resumed, err := resumeTenantCreateUndo(ctx, svc, keys, rec, id, created[id])
			if err != nil {
				return &TenantProvisionError{TenantID: id, Err: err}
			}
			if resumed {
				continue
			}
		}
		if err := keys.EnsureTenant(ctx, id); err != nil {
			return &TenantProvisionError{TenantID: id, Err: err}
		}
	}
	// Tenants go-qrdb deleted natively left their login CA material: the
	// boot pass reclaims it (see tenantCAKeyFactory.ReclaimWithdrawnTenants).
	if r, ok := keys.(interface {
		ReclaimWithdrawnTenants(context.Context) error
	}); ok {
		if err := r.ReclaimWithdrawnTenants(ctx); err != nil {
			return &TenantProvisionError{Err: err}
		}
	}
	return nil
}

// provisionTenantCAKeysThenFirstBoot runs the boot pass, then first boot. The
// pass needs the key backends, so it cannot run when the node is adopted.
func (s *Server) provisionTenantCAKeysThenFirstBoot(ctx context.Context) error {
	if err := s.provisionTenantCAKeys(ctx); err != nil {
		return err
	}
	return s.runFirstBoot(ctx)
}
