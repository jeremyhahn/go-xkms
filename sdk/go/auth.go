// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package xkms

import (
	"context"
	"crypto/x509"
	"time"

	qrdb "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	embedded "github.com/jeremyhahn/go-qrdb/sdk/go/transport/embedded"
	"github.com/jeremyhahn/go-xkms/pkg/auth_factors"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// AuthClient is the xkms-flavoured projection of qrdb's auth-related
// SDK surface. It re-exports qrdb's user / role / factor / login /
// session / permission / RBAC / volume-pool clients verbatim so a
// downstream consumer can depend on a single SDK import point and
// still reach the canonical qrdb behaviour.
//
// Hardware factor verification is layered on top: the WebAuthn, PIV,
// and PKCS#11 verifiers from pkg/auth_factors plug into qrdb's embedded
// transport via WithFactorVerifier so FactorClient.Verify routes
// through xkms's verification logic.
type AuthClient interface {
	// Users returns the qrdb UserClient (passwordless user lifecycle).
	Users() qrdbtransport.UserClient

	// Roles returns the qrdb RoleClient (FIPS 140-3 six-role model).
	Roles() qrdbtransport.RoleClient

	// Permissions returns the qrdb PermissionClient (permission registry).
	Permissions() qrdbtransport.PermissionClient

	// Factors returns the qrdb FactorClient (Phase 3 enroll / list /
	// remove / verify). When the underlying qrdb client uses the
	// embedded transport configured with the xkms factor verifiers,
	// Verify exercises the xkms verification path.
	Factors() qrdbtransport.FactorClient

	// Login returns the qrdb LoginClient (FactorType + lookup-key →
	// Principal resolver).
	Login() qrdbtransport.LoginClient

	// Sessions returns the qrdb SessionClient (resolve / revoke).
	Sessions() qrdbtransport.SessionClient

	// RBAC returns the qrdb RBACClient (Authorize + ListPermissions).
	RBAC() qrdbtransport.RBACClient

	// VolumePools returns the qrdb VolumePoolClient (multi-backend
	// storage placement primitives).
	VolumePools() qrdbtransport.VolumePoolClient
}

// authClient delegates every accessor to the wrapped qrdb client. The
// indirection lets downstream consumers depend on a single
// xkms-flavoured surface (`xkms.Auth(qrdbClient).RBAC()`) without
// importing qrdb directly.
type authClient struct {
	q *qrdb.Client
}

// Auth wraps a qrdb client and exposes the xkms auth surface. The
// qrdb client must be non-nil and connected; the wrapper does not
// take ownership of its lifecycle.
func Auth(q *qrdb.Client) AuthClient {
	if q == nil {
		return nil
	}
	return &authClient{q: q}
}

// Users returns qrdb's UserClient.
func (a *authClient) Users() qrdbtransport.UserClient { return a.q.Users() }

// Roles returns qrdb's RoleClient.
func (a *authClient) Roles() qrdbtransport.RoleClient { return a.q.Roles() }

// Permissions returns qrdb's PermissionClient.
func (a *authClient) Permissions() qrdbtransport.PermissionClient { return a.q.Permissions() }

// Factors returns qrdb's FactorClient.
func (a *authClient) Factors() qrdbtransport.FactorClient { return a.q.Factors() }

// Login returns qrdb's LoginClient.
func (a *authClient) Login() qrdbtransport.LoginClient { return a.q.Login() }

// Sessions returns qrdb's SessionClient.
func (a *authClient) Sessions() qrdbtransport.SessionClient { return a.q.Sessions() }

// RBAC returns qrdb's RBACClient.
func (a *authClient) RBAC() qrdbtransport.RBACClient { return a.q.RBAC() }

// VolumePools returns qrdb's VolumePoolClient.
func (a *authClient) VolumePools() qrdbtransport.VolumePoolClient { return a.q.VolumePools() }

// ---------------------------------------------------------------------------
// Embedded-transport factor-verifier wiring helpers
// ---------------------------------------------------------------------------

// AuthFactorOptions captures the dependencies the xkms factor
// verifiers need at construction time. Callers that build a qrdb
// embedded transport pass these options to WithXKMSFactorVerifiers
// to register the WebAuthn, PIV, and PKCS#11 adapters in one shot.
type AuthFactorOptions struct {
	// WebAuthnService is the configured xkms webauthn relying-party.
	// Required for the WebAuthn verifier; nil disables it.
	WebAuthnService *xkmswebauthn.Service

	// PIVRoots is the trust-root pool used when verifying PIV slot
	// certificates. Required for the PIV verifier; nil disables it.
	PIVRoots *x509.CertPool

	// PIVIntermediates is the optional intermediate pool used during
	// PIV chain verification.
	PIVIntermediates *x509.CertPool
}

// WithXKMSFactorVerifiers builds the embedded-transport options that
// register the factor verifiers (WebAuthn, PIV, PKCS#11). Pass the
// returned slice through to the qrdb embedded transport constructor.
//
// Example:
//
//	opts := xkms.WithXKMSFactorVerifiers(xkms.AuthFactorOptions{
//	    WebAuthnService: svc,
//	    PIVRoots:        roots,
//	})
//	tr := embedded.New(adminSvc, kvSvc, opts...)
//
// Verifiers are registered only when their dependencies are present.
// The PKCS#11 verifier is always registered — it has no external
// dependencies (the enrolled public key is embedded in the factor
// record). Missing WebAuthn/PIV dependencies are not an error.
func WithXKMSFactorVerifiers(o AuthFactorOptions) []embedded.Option {
	var opts []embedded.Option
	if o.WebAuthnService != nil {
		v, err := auth_factors.NewWebAuthnFactorVerifier(o.WebAuthnService)
		if err == nil {
			opts = append(opts, embedded.WithFactorVerifier(verifierAdapter{webauthn: v}))
		}
	}
	if o.PIVRoots != nil {
		v, err := auth_factors.NewPIVHardwareFactorVerifier(o.PIVRoots, o.PIVIntermediates)
		if err == nil {
			opts = append(opts, embedded.WithFactorVerifier(verifierAdapter{piv: v}))
		}
	}
	// PKCS#11 is always registered — it has no external dependencies.
	pkcs11v := auth_factors.NewPKCS11FactorVerifier()
	opts = append(opts, embedded.WithFactorVerifier(verifierAdapter{pkcs11: pkcs11v}))
	return opts
}

// verifierAdapter glues a single xkms factor verifier into qrdb's
// embedded.FactorVerifier interface. Exactly one of webauthn/piv/pkcs11
// is non-nil per instance — the constructor in WithXKMSFactorVerifiers
// produces one adapter per type.
type verifierAdapter struct {
	webauthn *auth_factors.WebAuthnFactorVerifier
	piv      *auth_factors.PIVHardwareFactorVerifier
	pkcs11   *auth_factors.PKCS11FactorVerifier
}

// Type returns the underlying verifier's factor type.
func (v verifierAdapter) Type() qrdbtransport.FactorType {
	if v.webauthn != nil {
		return v.webauthn.Type()
	}
	if v.piv != nil {
		return v.piv.Type()
	}
	return v.pkcs11.Type()
}

// Verify routes to the underlying verifier.
func (v verifierAdapter) Verify(ctx context.Context, factor *qrdb.AuthFactor, challenge qrdbtransport.VerifyChallenge) error {
	if v.webauthn != nil {
		return v.webauthn.Verify(ctx, factor, challenge)
	}
	if v.piv != nil {
		return v.piv.Verify(ctx, factor, challenge)
	}
	return v.pkcs11.Verify(ctx, factor, challenge)
}

// BeginChallenge implements qrdb's embedded.FactorChallenger so the unified
// login ceremony can obtain a per-method challenge during BeginLogin. WebAuthn
// returns an RP-bound assertion ceremony (options + session); PIV and PKCS#11
// — both nonce-based factors — return a nil challenge to signal that qrdb
// should use its generic server nonce (which the verifier signs over at Verify
// time).
func (v verifierAdapter) BeginChallenge(ctx context.Context, tenantID string, ft qrdbtransport.FactorType, hint string) ([]byte, map[string]string, time.Time, error) {
	if v.webauthn != nil {
		return v.webauthn.BeginChallenge(ctx, tenantID, ft, hint)
	}
	// PIV and PKCS#11 use the generic server nonce; no custom challenge needed.
	return nil, nil, time.Time{}, nil
}

// ---------------------------------------------------------------------------
// pkg/auth_factors verifier re-exports.
//
// Downstream composers (e.g. quicbaas wiring qrdb's embedded transport
// directly) construct the hardware factor verifiers themselves instead of
// going through Auth(); these aliases keep that wiring on the SDK surface.
// ---------------------------------------------------------------------------

// WebAuthnFactorVerifier verifies webauthn/fido2 auth factors against the
// canonical xkms WebAuthn relying-party service.
type WebAuthnFactorVerifier = auth_factors.WebAuthnFactorVerifier

// NewWebAuthnFactorVerifier constructs a WebAuthnFactorVerifier bound to the
// given WebAuthn service.
var NewWebAuthnFactorVerifier = auth_factors.NewWebAuthnFactorVerifier

// PIVHardwareFactorVerifier verifies piv auth factors by validating the
// signature and certificate chain against the configured roots.
type PIVHardwareFactorVerifier = auth_factors.PIVHardwareFactorVerifier

// NewPIVHardwareFactorVerifier constructs a PIVHardwareFactorVerifier from
// the given root and intermediate certificate pools.
var NewPIVHardwareFactorVerifier = auth_factors.NewPIVHardwareFactorVerifier

// PKCS11FactorVerifier verifies pkcs11 / HSM auth factors by validating the
// signature over a server nonce against the enrolled public key. Unlike PIV,
// it performs no certificate chain validation — possession is proven purely
// against the enrolled SubjectPublicKeyInfo.
type PKCS11FactorVerifier = auth_factors.PKCS11FactorVerifier

// NewPKCS11FactorVerifier constructs a PKCS11FactorVerifier. It has no
// external dependencies; the enrolled public key is embedded in the factor
// record at enrollment time.
var NewPKCS11FactorVerifier = auth_factors.NewPKCS11FactorVerifier

// ---------------------------------------------------------------------------
// pkg/auth_factors error re-exports.
//
// The verifiers above return these typed errors; downstream consumers need
// them on the SDK surface to errors.As without importing go-xkms/pkg.
// ---------------------------------------------------------------------------

// NilTrustPoolError reports a verifier constructed without a root pool.
type NilTrustPoolError = auth_factors.NilTrustPoolError

// MissingChallengeFieldError reports a challenge missing a required field
// such as the nonce or signature.
type MissingChallengeFieldError = auth_factors.MissingChallengeFieldError

// SignatureVerifyError reports a challenge signature that failed verification.
type SignatureVerifyError = auth_factors.SignatureVerifyError

// UnsupportedPublicKeyError reports an enrolled public key of an unsupported
// algorithm.
type UnsupportedPublicKeyError = auth_factors.UnsupportedPublicKeyError

// CertDecodeError reports an enrolled certificate that could not be decoded.
type CertDecodeError = auth_factors.CertDecodeError

// PublicKeyDecodeError reports an enrolled public key that could not be
// decoded from the factor metadata.
type PublicKeyDecodeError = auth_factors.PublicKeyDecodeError

// NilServiceError reports a verifier constructed without its backing service.
type NilServiceError = auth_factors.NilServiceError

// MissingFactorError reports a verification attempt against a nil factor.
type MissingFactorError = auth_factors.MissingFactorError

// CredentialMismatchError reports an enrolled credential that does not match
// the presented key material.
type CredentialMismatchError = auth_factors.CredentialMismatchError

// MissingMethodMetadataError reports factor metadata missing a required key.
type MissingMethodMetadataError = auth_factors.MissingMethodMetadataError

// VerifyNotSupportedError reports a verifier that requires the challenge
// flow rather than direct verification.
type VerifyNotSupportedError = auth_factors.VerifyNotSupportedError
