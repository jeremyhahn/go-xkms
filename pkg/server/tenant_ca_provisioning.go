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
	// down does not keep it from being provisioned.
	ensureErr := p.keys.ReviveTenant(ctx, info.ID)
	if ensureErr == nil {
		ensureErr = p.keys.EnsureTenant(ctx, info.ID)
	}
	if ensureErr != nil {
		return nil, &TenantProvisionError{
			TenantID: info.ID,
			Err:      errors.Join(ensureErr, p.undoCreate(ctx, info.ID)),
		}
	}
	return info, nil
}

// tenantCreateUndoTimeout bounds the rollback of a create whose login CA
// could not be provisioned.
const tenantCreateUndoTimeout = 30 * time.Second

// undoCreate rolls back a create that did not complete. It undoes the create
// rather than deleting the tenant, so the tenant ID stays free for a retry,
// and it runs on its own bounded context: a request cancelled during
// provisioning must not leave the tenant behind.
func (p *provisioningTenantService) undoCreate(ctx context.Context, id string) error {
	undoCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tenantCreateUndoTimeout)
	defer cancel()
	if err := p.UndoCreateTenant(undoCtx, id); err != nil {
		return err
	}
	return p.keys.RemoveTenant(undoCtx, id)
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
	s.tenantCAKeys.FenceHolders(s.config.Datastore.TenantLoginCAFencedHolders)
	s.tenantCAKeys.TrackTenants(s.tenantService)
	return provisionTenantCAKeysWith(ctx, s.tenantService, s.tenantCAKeys)
}

func provisionTenantCAKeysWith(ctx context.Context, svc qrdbsdk.ServiceTenantServicer, keys tenantCAKeyProvisioner) error {
	infos, err := svc.ListTenants(ctx)
	if err != nil {
		return &TenantProvisionError{Err: err}
	}
	ids := []string{qrdbsdk.SystemTenantID}
	for i := range infos {
		if id := infos[i].ID; id != "" && id != qrdbsdk.SystemTenantID {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		if err := keys.EnsureTenant(ctx, id); err != nil {
			return &TenantProvisionError{TenantID: id, Err: err}
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
