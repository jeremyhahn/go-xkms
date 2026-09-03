// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package initialize

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor"
	xkmsfido2 "github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
	xkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file is the reusable administrator-enrollment orchestration for the
// init ceremony: build the factor registry against real hardware, refuse
// before the ceremony mutates anything if a planned factor cannot succeed,
// then run the enrollment.
//
// It lives here rather than in a daemon because every project in the stack
// needs it. go-qrdb decides WHICH factors are enrolled and in what order
// (pkg/ceremony/factors.go, which deliberately defines no registry because
// "go-xkms already implements every factor against them"), and go-xkms owns
// the CTAP2 / PIV / PKCS#11 implementations that satisfy that plan. Anything
// embedding go-qrdb through go-xkms therefore gets hardware-backed admin
// login factors without reimplementing this wiring.

// AdminEnrollmentConfig describes the administrator whose login factors are
// being enrolled and the hardware available to enroll them.
type AdminEnrollmentConfig struct {
	// Plan is the ordered set of factors to enroll. A nil plan means the mTLS
	// baseline and makes every entry point here a no-op.
	Plan *qrdbsdk.AdminEnrollmentPlan

	// Username is the administrator identity factors are enrolled against.
	Username string

	// DisplayName is shown by an authenticator's own UI. Falls back to Username.
	DisplayName string

	// TenantID scopes the administrator. Callers pass the system tenant.
	TenantID string

	// RelyingPartyID / RelyingPartyName scope an enrolled passkey to the
	// domain the console is served from. RelyingPartyID is required when the
	// plan includes FIDO2.
	RelyingPartyID   string
	RelyingPartyName string

	// PasskeyDevice selects one authenticator when several are attached.
	PasskeyDevice string

	// PasskeyPIN is the CTAP2 PIN of the authenticator being enrolled. Read it
	// from stdin or the environment, never a command-line flag, where it would
	// be visible in /proc to every process on the host.
	PasskeyPIN string

	// FIDO2Handler drives an attached authenticator. Nil when this build or
	// host has no FIDO2 support, which makes a planned fido2 factor fail at
	// preflight rather than midway through the ceremony.
	FIDO2Handler *pkgfido2.FIDO2Handler

	// PIVGenerator produces keys in an attached smartcard's PIV slots. It is
	// the PIV counterpart of FIDO2Handler: a console process that can reach a
	// card reader attaches a hardware-backed generator (PKCS#11 / TPM2) here.
	//
	// Nil makes a planned piv factor fail at preflight, unless
	// AllowSoftwarePIV opts the deployment into a software credential.
	PIVGenerator xkms.PIVKeyGenerator

	// AllowSoftwarePIV opts a software-only deployment into a software-backed
	// administrator PIV credential when no PIVGenerator is attached.
	//
	// It is opt-IN by name because the omission case is the dangerous one: an
	// operator who ran with --admin-factor piv holding a smartcard would
	// otherwise receive a software key, enrolled and recorded identically to
	// a hardware one, with nothing in the result to tell them apart.
	AllowSoftwarePIV bool

	// AdminCertPEM is the administrator's client certificate as issued by the
	// ceremony. The mTLS factor binds to it, which is what makes that
	// certificate an actual login credential rather than just a file on disk.
	AdminCertPEM []byte

	// Persister durably records each enrollment. A nil persister enrolls and
	// reports factors without storing them — correct only for a one-shot
	// bootstrap with no durable user store yet.
	Persister qrdbsdk.AdminFactorPersister
}

// NewAdminFactorRegistry builds the canonical go-xkms factor registry with the
// attached-hardware drivers wired in, returning the registry and the FIDO2
// local ceremony that drives it.
//
// PIV is fail-closed here, unlike the library default: cfg.PIVGenerator is
// passed through, and with none attached the registered piv factor refuses
// rather than substituting a software generator. Software PIV remains
// reachable, but only by naming AllowSoftwarePIV.
//
// The default fido2 factor is REPLACED rather than supplemented: Register
// refuses a duplicate name, and a factor without the local ceremony would
// answer the availability probe without being able to run, reporting a factor
// that cannot actually enroll. With no handler the default registry is
// returned unchanged and a planned fido2 factor fails preflight.
func NewAdminFactorRegistry(cfg AdminEnrollmentConfig) (*qrdbsdk.AuthFactorRegistry, *xkmsfido2.LocalCeremony, error) {
	local := xkmsfido2.NewLocalCeremony(cfg.FIDO2Handler, 0)

	registry, err := factor.NewDefaultRegistry(factor.Config{
		PIVGenerator:        cfg.PIVGenerator,
		RequirePIVGenerator: !cfg.AllowSoftwarePIV,
		FIDO2RPID:           cfg.RelyingPartyID,
	})
	if err != nil {
		return nil, nil, err
	}

	if cfg.FIDO2Handler != nil {
		registry.Unregister(xkmsfido2.FactorName)
		if rerr := registry.Register(xkmsfido2.NewWithLocalCeremony(xkmsfido2.Config{
			RPID: cfg.RelyingPartyID,
		}, local)); rerr != nil {
			return nil, nil, rerr
		}
	}
	return registry, local, nil
}

// PreflightAdminFactors refuses the ceremony before it changes any state when a
// planned factor cannot succeed. A missing security key then costs the operator
// one retry instead of leaving an initialized barrier behind a half-enrolled
// administrator who cannot log in.
func PreflightAdminFactors(ctx context.Context, cfg AdminEnrollmentConfig) error {
	if cfg.Plan == nil {
		return nil
	}
	registry, _, err := NewAdminFactorRegistry(cfg)
	if err != nil {
		return err
	}
	return cfg.Plan.Preflight(ctx, registry)
}

// EnrollAdminFactors runs the planned login factors for the administrator the
// ceremony created.
//
// Enrolled factors are returned even on error, so a caller can report what IS
// live rather than leaving an operator guessing whether the administrator has
// any usable credential at all.
func EnrollAdminFactors(
	ctx context.Context,
	cfg AdminEnrollmentConfig,
) ([]qrdbsdk.AdminEnrollmentResult, error) {
	if cfg.Plan == nil {
		return nil, nil
	}
	registry, local, err := NewAdminFactorRegistry(cfg)
	if err != nil {
		return nil, err
	}

	displayName := cfg.DisplayName
	if displayName == "" {
		displayName = cfg.Username
	}

	params := NewAdminEnrollmentParams(AdminEnrollmentContext{
		Username:         cfg.Username,
		DisplayName:      displayName,
		RelyingPartyID:   cfg.RelyingPartyID,
		RelyingPartyName: cfg.RelyingPartyName,
		PasskeyDevice:    cfg.PasskeyDevice,
		PasskeyPIN:       cfg.PasskeyPIN,
		LocalCeremony:    local,
		AdminCertPEM:     cfg.AdminCertPEM,
	})

	return qrdbsdk.EnrollAdminFactors(
		ctx, cfg.Plan, registry, cfg.Username, cfg.TenantID, params, cfg.Persister,
	)
}
