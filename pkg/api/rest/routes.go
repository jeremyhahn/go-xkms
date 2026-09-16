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

package rest

import (
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// RouteAuth classifies how a route is authenticated and authorized.
type RouteAuth int

const (
	// RouteAuthPublic serves without authentication.
	RouteAuthPublic RouteAuth = iota
	// RouteAuthSession requires an authenticated identity but no specific
	// RBAC permission.
	RouteAuthSession
	// RouteAuthPermission requires an authenticated identity holding the
	// route's Resource:Action permission when RBAC is enabled.
	RouteAuthPermission
)

// RouteGroup names the middleware profile a route is served under. The
// profiles mirror the historical registration groups in setupRouter.
type RouteGroup int

const (
	// GroupRoot routes carry no group middleware (health, discovery,
	// trust bootstrap).
	GroupRoot RouteGroup = iota
	// GroupAPIv1 routes carry authentication + tenant enforcement.
	GroupAPIv1
	// GroupAuthSession routes sit behind the login rate limiter; the
	// exchange endpoints are unauthenticated (they ARE the
	// authentication), the introspection endpoints require a session.
	GroupAuthSession
	// GroupWebAuthn routes sit behind the login rate limiter and are
	// unauthenticated: WebAuthn is the auth mechanism.
	GroupWebAuthn
	// GroupUsers routes carry authentication only (no tenant middleware):
	// the user plane is identity-scoped, not tenant-scoped.
	GroupUsers
	// GroupSSH routes carry authentication + tenant enforcement; every
	// route additionally gates on ssh:use.
	GroupSSH
)

// RouteSpec describes one REST route: the wire surface, its authorization
// contract, and how to bind its handler to a constructed *Server. This
// table is the single source of truth for the xkms REST surface — it is
// consumed by the legacy in-process server (setupRouter) and by the
// unified-API-server ServiceModule (pkg/apimodule), so a route exists on
// both paths, with the same permission, by construction.
type RouteSpec struct {
	Method  string
	Pattern string // full path, including any /api/v1 or /xkms/v1 prefix
	Group   RouteGroup
	Auth    RouteAuth

	// Resource and Action carry the RBAC permission for
	// RouteAuthPermission routes (pkg/auth vocabulary).
	Resource string
	Action   string

	// Enabled reports whether the route's backing subsystem is configured
	// on s; nil means always enabled. The legacy server skips disabled
	// routes; the module registers the full surface and answers 501 for
	// routes whose subsystem is absent at request time.
	Enabled func(s *Server) bool

	// Handler binds the route's handler on a constructed server.
	Handler func(s *Server) http.HandlerFunc
}

// Routes returns the full REST route table. Order is stable and grouped by
// capability; the table is data, so tests can assert the exact surface.
func Routes() []RouteSpec {
	specs := []RouteSpec{
		// --- Root: health + discovery + trust bootstrap (public) ---
		{Method: "GET", Pattern: "/health", Group: GroupRoot, Auth: RouteAuthPublic, Handler: func(s *Server) http.HandlerFunc { return s.handlers.HealthHandler }},
		{Method: "HEAD", Pattern: "/health", Group: GroupRoot, Auth: RouteAuthPublic, Handler: func(s *Server) http.HandlerFunc { return s.handlers.HealthHandler }},
		{Method: "GET", Pattern: "/health/live", Group: GroupRoot, Auth: RouteAuthPublic, Handler: func(s *Server) http.HandlerFunc { return s.handlers.LivenessHandler }},
		{Method: "GET", Pattern: "/health/ready", Group: GroupRoot, Auth: RouteAuthPublic, Handler: func(s *Server) http.HandlerFunc { return s.handlers.ReadinessHandler }},
		{Method: "GET", Pattern: "/health/startup", Group: GroupRoot, Auth: RouteAuthPublic, Handler: func(s *Server) http.HandlerFunc { return s.handlers.StartupHandler }},
		{Method: "GET", Pattern: "/api/v1/algorithms", Group: GroupRoot, Auth: RouteAuthPublic, Handler: func(s *Server) http.HandlerFunc { return s.handlers.AlgorithmsHandler }},
		{Method: "GET", Pattern: "/api/v1/capabilities", Group: GroupRoot, Auth: RouteAuthPublic, Handler: func(s *Server) http.HandlerFunc { return s.handleCapabilities }},
		{Method: "GET", Pattern: "/v1/ca/bootstrap", Group: GroupRoot, Auth: RouteAuthPublic, Handler: func(s *Server) http.HandlerFunc { return s.handlers.GetCABundleHandler }},
	}

	// apiv1 appends a permission-gated /api/v1 route.
	perm := func(method, pattern, resource, action string, h func(s *Server) http.HandlerFunc) {
		specs = append(specs, RouteSpec{Method: method, Pattern: "/api/v1" + pattern, Group: GroupAPIv1, Auth: RouteAuthPermission, Resource: resource, Action: action, Handler: h})
	}
	// session appends an authenticated-session /api/v1 route.
	session := func(method, pattern string, enabled func(*Server) bool, h func(s *Server) http.HandlerFunc) {
		specs = append(specs, RouteSpec{Method: method, Pattern: "/api/v1" + pattern, Group: GroupAPIv1, Auth: RouteAuthSession, Enabled: enabled, Handler: h})
	}
	// permIf appends a permission-gated /api/v1 route with an enable guard.
	permIf := func(method, pattern, resource, action string, enabled func(*Server) bool, h func(s *Server) http.HandlerFunc) {
		specs = append(specs, RouteSpec{Method: method, Pattern: "/api/v1" + pattern, Group: GroupAPIv1, Auth: RouteAuthPermission, Resource: resource, Action: action, Enabled: enabled, Handler: h})
	}

	// --- Backends ---
	perm("GET", "/backends", auth.ResourceBackends, auth.ActionList, func(s *Server) http.HandlerFunc { return s.handlers.ListBackendsHandler })
	perm("GET", "/backends/{id}", auth.ResourceBackends, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.GetBackendHandler })

	// --- Keys + crypto operations ---
	perm("POST", "/keys", auth.ResourceKeys, auth.ActionCreate, func(s *Server) http.HandlerFunc { return s.handlers.GenerateKeyHandler })
	perm("GET", "/keys", auth.ResourceKeys, auth.ActionList, func(s *Server) http.HandlerFunc { return s.handlers.ListKeysHandler })
	perm("GET", "/keys/{id}", auth.ResourceKeys, auth.ActionGet, func(s *Server) http.HandlerFunc { return s.handlers.GetKeyHandler })
	perm("DELETE", "/keys/{id}", auth.ResourceKeys, auth.ActionDelete, func(s *Server) http.HandlerFunc { return s.handlers.DeleteKeyHandler })
	perm("POST", "/keys/{id}/sign", auth.ResourceKeys, auth.ActionSign, func(s *Server) http.HandlerFunc { return s.handlers.SignHandler })
	perm("POST", "/keys/{id}/verify", auth.ResourceKeys, auth.ActionVerify, func(s *Server) http.HandlerFunc { return s.handlers.VerifyHandler })
	perm("POST", "/keys/{id}/rotate", auth.ResourceKeys, auth.ActionRotate, func(s *Server) http.HandlerFunc { return s.handlers.RotateKeyHandler })
	perm("POST", "/keys/{id}/encrypt", auth.ResourceKeys, auth.ActionEncrypt, func(s *Server) http.HandlerFunc { return s.handlers.EncryptHandler })
	perm("POST", "/keys/{id}/decrypt", auth.ResourceKeys, auth.ActionDecrypt, func(s *Server) http.HandlerFunc { return s.handlers.DecryptHandler })
	perm("POST", "/keys/{id}/encrypt-asym", auth.ResourceKeys, auth.ActionEncrypt, func(s *Server) http.HandlerFunc { return s.handlers.EncryptAsymHandler })
	perm("POST", "/keys/import-params", auth.ResourceKeys, auth.ActionImport, func(s *Server) http.HandlerFunc { return s.handlers.GetImportParametersHandler })
	perm("POST", "/keys/wrap", auth.ResourceKeys, auth.ActionEncrypt, func(s *Server) http.HandlerFunc { return s.handlers.WrapKeyHandler })
	perm("POST", "/keys/unwrap", auth.ResourceKeys, auth.ActionDecrypt, func(s *Server) http.HandlerFunc { return s.handlers.UnwrapKeyHandler })
	perm("POST", "/keys/import", auth.ResourceKeys, auth.ActionImport, func(s *Server) http.HandlerFunc { return s.handlers.ImportKeyHandler })
	perm("POST", "/keys/{id}/export", auth.ResourceKeys, auth.ActionExport, func(s *Server) http.HandlerFunc { return s.handlers.ExportKeyHandler })
	perm("POST", "/keys/copy", auth.ResourceKeys, auth.ActionCreate, func(s *Server) http.HandlerFunc { return s.handlers.CopyKeyHandler })
	// Hardware-capability key operations. "derive", "wrap" and "unwrap" are
	// the canonical go-qrdb keys:derive / keys:wrap / keys:unwrap actions,
	// matching pkg/api/grpc/service.go's authorize calls.
	perm("POST", "/attest", auth.ResourceKeys, auth.ActionGet, func(s *Server) http.HandlerFunc { return s.handlers.AttestKeyHandler })
	perm("POST", "/keys/derive-ecdh", auth.ResourceKeys, "derive", func(s *Server) http.HandlerFunc { return s.handlers.DeriveKeyECDHHandler })
	perm("POST", "/keys/{id}/export-material", auth.ResourceKeys, auth.ActionExport, func(s *Server) http.HandlerFunc { return s.handlers.ExportKeyMaterialHandler })
	perm("POST", "/keys/wrap-by-id", auth.ResourceKeys, "wrap", func(s *Server) http.HandlerFunc { return s.handlers.WrapKeyByIDHandler })
	perm("POST", "/keys/unwrap-by-id", auth.ResourceKeys, "unwrap", func(s *Server) http.HandlerFunc { return s.handlers.UnwrapKeyByIDHandler })

	// --- Certificates + TLS ---
	perm("POST", "/certs", auth.ResourceCerts, auth.ActionGenerate, func(s *Server) http.HandlerFunc { return s.handlers.SaveCertHandler })
	perm("GET", "/certs", auth.ResourceCerts, auth.ActionList, func(s *Server) http.HandlerFunc { return s.handlers.ListCertsHandler })
	perm("GET", "/certs/{id}", auth.ResourceCerts, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.GetCertHandler })
	perm("DELETE", "/certs/{id}", auth.ResourceCerts, auth.ActionRevoke, func(s *Server) http.HandlerFunc { return s.handlers.DeleteCertHandler })
	perm("HEAD", "/certs/{id}", auth.ResourceCerts, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.CertExistsHandler })
	perm("POST", "/certs/{id}/chain", auth.ResourceCerts, auth.ActionGenerate, func(s *Server) http.HandlerFunc { return s.handlers.SaveCertChainHandler })
	perm("GET", "/certs/{id}/chain", auth.ResourceCerts, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.GetCertChainHandler })
	perm("GET", "/tls/{id}", auth.ResourceCerts, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.GetTLSCertificateHandler })

	// --- Sealing (hardware-backed data protection) ---
	perm("POST", "/seal", auth.ResourceKeys, auth.ActionEncrypt, func(s *Server) http.HandlerFunc { return s.handlers.SealHandler })
	perm("POST", "/unseal", auth.ResourceKeys, auth.ActionDecrypt, func(s *Server) http.HandlerFunc { return s.handlers.UnsealHandler })
	perm("GET", "/seal/capability", auth.ResourceKeys, auth.ActionGet, func(s *Server) http.HandlerFunc { return s.handlers.CanSealHandler })

	// --- FROST threshold signatures. Threshold key material carries the
	// keys:* permission of its single-key equivalent; the signing rounds
	// take keys:sign exactly as QUIC and MCP gate them. ---
	perm("POST", "/frost/keys", auth.ResourceKeys, auth.ActionCreate, func(s *Server) http.HandlerFunc { return s.handlers.FrostGenerateKeyHandler })
	perm("POST", "/frost/keys/import", auth.ResourceKeys, auth.ActionImport, func(s *Server) http.HandlerFunc { return s.handlers.FrostImportKeyHandler })
	perm("GET", "/frost/keys", auth.ResourceKeys, auth.ActionList, func(s *Server) http.HandlerFunc { return s.handlers.FrostListKeysHandler })
	perm("GET", "/frost/keys/{id}", auth.ResourceKeys, auth.ActionGet, func(s *Server) http.HandlerFunc { return s.handlers.FrostGetKeyHandler })
	perm("DELETE", "/frost/keys/{id}", auth.ResourceKeys, auth.ActionDelete, func(s *Server) http.HandlerFunc { return s.handlers.FrostDeleteKeyHandler })
	perm("POST", "/frost/keys/{id}/nonces", auth.ResourceKeys, auth.ActionSign, func(s *Server) http.HandlerFunc { return s.handlers.FrostGenerateNoncesHandler })
	perm("POST", "/frost/keys/{id}/sign", auth.ResourceKeys, auth.ActionSign, func(s *Server) http.HandlerFunc { return s.handlers.FrostSignRoundHandler })
	perm("POST", "/frost/aggregate", auth.ResourceKeys, auth.ActionSign, func(s *Server) http.HandlerFunc { return s.handlers.FrostAggregateHandler })
	perm("POST", "/frost/verify", auth.ResourceKeys, auth.ActionVerify, func(s *Server) http.HandlerFunc { return s.handlers.FrostVerifyHandler })

	// --- Barrier management. The resource:action pairs mirror the MCP
	// barrier.* methodPermissions map and the QUIC barrier handlers. ---
	perm("POST", "/barrier/initialize", auth.ResourceSeal, auth.ActionBootstrap, func(s *Server) http.HandlerFunc { return s.handlers.BarrierInitializeHandler })
	perm("POST", "/barrier/unseal", auth.ResourceSeal, auth.ActionUnseal, func(s *Server) http.HandlerFunc { return s.handlers.BarrierUnsealHandler })
	perm("POST", "/barrier/seal", auth.ResourceSeal, auth.ActionSeal, func(s *Server) http.HandlerFunc { return s.handlers.BarrierSealHandler })
	perm("GET", "/barrier/status", auth.ResourceSeal, auth.ActionStatus, func(s *Server) http.HandlerFunc { return s.handlers.BarrierStatusHandler })
	perm("POST", "/barrier/shamir/initialize", auth.ResourceSeal, auth.ActionInitializeShamir, func(s *Server) http.HandlerFunc { return s.handlers.BarrierInitializeShamirHandler })
	perm("POST", "/barrier/shamir/unseal-share", auth.ResourceBarrier, auth.ActionUnsealShare, func(s *Server) http.HandlerFunc { return s.handlers.BarrierUnsealShareHandler })
	perm("POST", "/barrier/shamir/unseal-shares", auth.ResourceSeal, auth.ActionUnseal, func(s *Server) http.HandlerFunc { return s.handlers.BarrierUnsealSharesHandler })
	perm("POST", "/barrier/rekey", auth.ResourceSeal, auth.ActionRekey, func(s *Server) http.HandlerFunc { return s.handlers.BarrierRekeyHandler })
	perm("POST", "/barrier/recovery/generate", auth.ResourceSeal, auth.ActionGenerateRecovery, func(s *Server) http.HandlerFunc { return s.handlers.BarrierGenerateRecoveryKeysHandler })
	perm("POST", "/barrier/recovery/recover", auth.ResourceSeal, auth.ActionRecoverWithKeys, func(s *Server) http.HandlerFunc { return s.handlers.BarrierRecoverWithKeysHandler })
	perm("DELETE", "/barrier/recovery/keys", auth.ResourceSeal, auth.ActionGenerateRecovery, func(s *Server) http.HandlerFunc { return s.handlers.BarrierDeleteRecoveryKeysHandler })
	perm("POST", "/barrier/recovery/root-token", auth.ResourceSeal, auth.ActionRotateRootKey, func(s *Server) http.HandlerFunc { return s.handlers.BarrierGenerateRootTokenHandler })
	perm("POST", "/barrier/enable-encryption", auth.ResourceSeal, auth.ActionEnableEncryption, func(s *Server) http.HandlerFunc { return s.handlers.BarrierEnableEncryptionHandler })

	// --- PIN management ---
	session("POST", "/pin/so/set", nil, func(s *Server) http.HandlerFunc { return s.handlers.SetSOPINHandler })
	session("POST", "/pin/user/set", nil, func(s *Server) http.HandlerFunc { return s.handlers.SetUserPINHandler })
	session("POST", "/pin/so/change", nil, func(s *Server) http.HandlerFunc { return s.handlers.ChangeSOPINHandler })
	session("POST", "/pin/user/change", nil, func(s *Server) http.HandlerFunc { return s.handlers.ChangeUserPINHandler })
	session("POST", "/pin/so/verify", nil, func(s *Server) http.HandlerFunc { return s.handlers.VerifySOPINHandler })
	session("POST", "/pin/user/verify", nil, func(s *Server) http.HandlerFunc { return s.handlers.VerifyUserPINHandler })
	session("GET", "/pin/lockout", nil, func(s *Server) http.HandlerFunc { return s.handlers.GetLockoutStatusHandler })
	session("POST", "/pin/lockout/reset", nil, func(s *Server) http.HandlerFunc { return s.handlers.ResetLockoutHandler })

	// --- PIV ---
	session("GET", "/piv/slots", nil, func(s *Server) http.HandlerFunc { return s.handlers.ListPIVSlotsHandler })
	session("GET", "/piv/slots/{slot}/certificate", nil, func(s *Server) http.HandlerFunc { return s.handlers.GetPIVCertificateHandler })
	session("POST", "/piv/slots/{slot}/certificate", nil, func(s *Server) http.HandlerFunc { return s.handlers.StorePIVCertificateHandler })
	session("DELETE", "/piv/slots/{slot}/certificate", nil, func(s *Server) http.HandlerFunc { return s.handlers.DeletePIVCertificateHandler })
	session("POST", "/piv/slots/{slot}/generate", nil, func(s *Server) http.HandlerFunc { return s.handlers.GeneratePIVKeyHandler })
	session("POST", "/piv/slots/{slot}/import", nil, func(s *Server) http.HandlerFunc { return s.handlers.ImportPIVCertificateHandler })
	session("GET", "/piv/slots/{slot}/export", nil, func(s *Server) http.HandlerFunc { return s.handlers.ExportPIVCertificateHandler })
	session("POST", "/piv/slots/{slot}/csr", nil, func(s *Server) http.HandlerFunc { return s.handlers.GeneratePIVCSRHandler })

	// --- CA. When the full CA subsystem is absent the legacy bundle
	// endpoint serves bootstrap alone. ---
	hasCA := func(s *Server) bool { return s.caHandlers != nil }
	noCA := func(s *Server) bool { return s.caHandlers == nil }
	session("GET", "/ca/bundle", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleGetCABundle })
	session("GET", "/ca/certificate", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleGetCACertificate })
	session("POST", "/ca/sign-csr", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleSignCSR })
	session("POST", "/ca/issue", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleIssueCertificate })
	session("POST", "/ca/revoke", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleRevokeCertificate })
	session("POST", "/ca/crl", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleGenerateCRL })
	session("GET", "/ca/revoked/{serial}", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleIsRevoked })
	session("POST", "/ca/tcg/ek", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleIssueEKCertificate })
	session("POST", "/ca/tcg/ak", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleIssueAKCertificate })
	session("POST", "/ca/tcg/sign-csr", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleSignTCGCSR })
	session("POST", "/ca/tcg/enroll", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleEnrollDevice })
	session("GET", "/ca/bundle", noCA, func(s *Server) http.HandlerFunc { return s.handlers.GetCABundleHandler })

	// --- Custodian groups ---
	hasCustodian := func(s *Server) bool { return s.custodianHandlers != nil }
	session("POST", "/custodian/groups/", hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.CreateGroupHandler })
	session("GET", "/custodian/groups/", hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.ListGroupsHandler })
	session("GET", "/custodian/groups/{id}", hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.GetGroupHandler })
	session("DELETE", "/custodian/groups/{id}", hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.DeleteGroupHandler })
	session("POST", "/custodian/groups/{id}/members", hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.AddMemberHandler })
	session("DELETE", "/custodian/groups/{id}/members/{userID}", hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.RemoveMemberHandler })
	session("POST", "/custodian/groups/{id}/distribute", hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.DistributeSharesHandler })

	// --- Shares (Shamir custody) ---
	hasShares := func(s *Server) bool { return s.shareHandlers != nil }
	session("POST", "/shares/submit", hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.SubmitShareHandler })
	session("GET", "/shares/", hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.ListSharesHandler })
	session("GET", "/shares/{serverURL}/{groupID}/{shareIndex}", hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.GetShareHandler })
	session("DELETE", "/shares/{serverURL}/{groupID}/{shareIndex}", hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.DeleteShareHandler })
	session("GET", "/shares/status/{groupID}", hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.GetShareCollectionStatusHandler })

	// --- Tenants ---
	hasTenants := func(s *Server) bool { return s.tenantHandlers != nil }
	session("POST", "/tenants/", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.CreateTenantHandler })
	session("GET", "/tenants/", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.ListTenantsHandler })
	session("GET", "/tenants/{tenantID}", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.GetTenantHandler })
	session("DELETE", "/tenants/{tenantID}", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.DeleteTenantHandler })
	session("GET", "/tenants/{tenantID}/barrier/status", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.TenantBarrierStatusHandler })
	session("POST", "/tenants/{tenantID}/barrier/init", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.TenantBarrierInitHandler })
	session("POST", "/tenants/{tenantID}/barrier/unseal", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.TenantBarrierUnsealHandler })
	session("PUT", "/tenants/{tenantID}/entitlements", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.UpdateTenantEntitlementsHandler })
	session("PUT", "/tenants/{tenantID}/quotas", hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.UpdateTenantQuotasHandler })

	// --- Passwords ---
	hasPasswords := func(s *Server) bool { return s.passwordHandlers != nil }
	session("POST", "/passwords/", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.AddPasswordHandler })
	session("GET", "/passwords/", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.ListPasswordsHandler })
	session("GET", "/passwords/{id}", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.GetPasswordHandler })
	session("PUT", "/passwords/{id}", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.UpdatePasswordHandler })
	session("DELETE", "/passwords/{id}", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.DeletePasswordHandler })
	session("POST", "/passwords/unlock", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.UnlockHandler })
	session("POST", "/passwords/lock", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.LockHandler })
	session("GET", "/passwords/status", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.StatusHandler })
	session("POST", "/passwords/access-mode", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.SetAccessModeHandler })
	session("POST", "/passwords/generate", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.GeneratePasswordHandler })

	// --- PKCS#11 remote state. Records are a token's key/object state, so
	// they gate on the keys resource. All POST so opaque binary values
	// never ride in a URL. ---
	hasP11 := func(s *Server) bool { return s.pkcs11StateHandlers != nil }
	permIf("POST", "/pkcs11state/put", auth.ResourceKeys, auth.ActionCreate, hasP11, func(s *Server) http.HandlerFunc { return s.pkcs11StateHandlers.PutHandler })
	permIf("POST", "/pkcs11state/put-if-absent", auth.ResourceKeys, auth.ActionCreate, hasP11, func(s *Server) http.HandlerFunc { return s.pkcs11StateHandlers.PutIfAbsentHandler })
	permIf("POST", "/pkcs11state/compare-and-swap", auth.ResourceKeys, auth.ActionUpdate, hasP11, func(s *Server) http.HandlerFunc { return s.pkcs11StateHandlers.CASHandler })
	permIf("POST", "/pkcs11state/compare-and-delete", auth.ResourceKeys, auth.ActionDelete, hasP11, func(s *Server) http.HandlerFunc { return s.pkcs11StateHandlers.CADHandler })
	permIf("POST", "/pkcs11state/get", auth.ResourceKeys, auth.ActionGet, hasP11, func(s *Server) http.HandlerFunc { return s.pkcs11StateHandlers.GetHandler })
	permIf("POST", "/pkcs11state/delete", auth.ResourceKeys, auth.ActionDelete, hasP11, func(s *Server) http.HandlerFunc { return s.pkcs11StateHandlers.DeleteHandler })
	permIf("POST", "/pkcs11state/list", auth.ResourceKeys, auth.ActionList, hasP11, func(s *Server) http.HandlerFunc { return s.pkcs11StateHandlers.ListHandler })

	// --- Platform store (sealed secrets). Placeholder must be {name}: the
	// handlers read chi.URLParam(r, "name"). Secrets sealed here are
	// key-protection material (the same trust class as pkcs11state above),
	// so the routes carry the identical keys:* permission pairs rather than
	// a bare authenticated-session gate. ---
	hasPlatform := func(s *Server) bool { return s.platformHandlers != nil }
	permIf("PUT", "/platform/secrets/{name}", auth.ResourceKeys, auth.ActionWrite, hasPlatform, func(s *Server) http.HandlerFunc { return s.platformHandlers.PutSecretHandler })
	permIf("GET", "/platform/secrets/{name}", auth.ResourceKeys, auth.ActionRead, hasPlatform, func(s *Server) http.HandlerFunc { return s.platformHandlers.GetSecretHandler })
	permIf("DELETE", "/platform/secrets/{name}", auth.ResourceKeys, auth.ActionDelete, hasPlatform, func(s *Server) http.HandlerFunc { return s.platformHandlers.DeleteSecretHandler })
	permIf("GET", "/platform/secrets", auth.ResourceKeys, auth.ActionList, hasPlatform, func(s *Server) http.HandlerFunc { return s.platformHandlers.ListSecretsHandler })
	permIf("POST", "/platform/secrets/{name}/reseal", auth.ResourceKeys, auth.ActionWrite, hasPlatform, func(s *Server) http.HandlerFunc { return s.platformHandlers.ResealSecretHandler })
	permIf("GET", "/platform/status", auth.ResourceKeys, auth.ActionRead, hasPlatform, func(s *Server) http.HandlerFunc { return s.platformHandlers.StatusHandler })

	// --- Policies ---
	hasPolicies := func(s *Server) bool { return s.policyHandlers != nil }
	session("POST", "/policies/", hasPolicies, func(s *Server) http.HandlerFunc { return s.policyHandlers.CreatePolicyHandler })
	session("GET", "/policies/", hasPolicies, func(s *Server) http.HandlerFunc { return s.policyHandlers.ListPoliciesHandler })
	session("GET", "/policies/{id}", hasPolicies, func(s *Server) http.HandlerFunc { return s.policyHandlers.GetPolicyHandler })
	session("DELETE", "/policies/{id}", hasPolicies, func(s *Server) http.HandlerFunc { return s.policyHandlers.DeletePolicyHandler })
	session("POST", "/policies/{id}/refresh", hasPolicies, func(s *Server) http.HandlerFunc { return s.policyHandlers.RefreshPolicyHandler })
	session("POST", "/policies/{id}/verify", hasPolicies, func(s *Server) http.HandlerFunc { return s.policyHandlers.VerifyPolicyHandler })
	session("GET", "/policies/{id}/export", hasPolicies, func(s *Server) http.HandlerFunc { return s.policyHandlers.ExportPolicyHandler })

	// --- Init ceremony. status and the claim-* halves are reachable
	// without an account while the ceremony has not reached the
	// operational state (publicCeremonyPaths in middleware_init_public.go
	// — a middleware concern, not a table concern); sign-csr and officer
	// enrolment stay behind authentication and RBAC on every transport. ---
	hasInit := func(s *Server) bool { return s.initHandlers != nil }
	session("GET", "/init/status", hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleGetStatus })
	session("POST", "/init/claim-cert/begin", hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleClaimCertBegin })
	session("POST", "/init/claim-cert/complete", hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleClaimCertComplete })
	session("POST", "/init/claim-share/begin", hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleClaimShareBegin })
	session("POST", "/init/claim-share/complete", hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleClaimShareComplete })
	permIf("POST", "/init/sign-csr", auth.ResourceCeremony, auth.ActionSignCSR, hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleSignCSRInit })
	permIf("POST", "/init/officer/register", auth.ResourceCeremony, auth.ActionSignCSR, hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleOfficerRegister })
	permIf("POST", "/init/enroll-external-officer", auth.ResourceCeremony, auth.ActionSignCSR, hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleEnrollExternalOfficer })
	session("GET", "/init/officer/status", hasInit, func(s *Server) http.HandlerFunc { return s.initHandlers.HandleOfficerStatus })

	// --- Credentials ---
	hasCreds := func(s *Server) bool { return s.credentialHandlers != nil }
	session("POST", "/credentials/submit", hasCreds, func(s *Server) http.HandlerFunc { return s.credentialHandlers.HandleSubmit })
	session("GET", "/credentials/strategy", hasCreds, func(s *Server) http.HandlerFunc { return s.credentialHandlers.HandleGetStrategy })
	session("GET", "/credentials/", hasCreds, func(s *Server) http.HandlerFunc { return s.credentialHandlers.HandleList })

	// --- User-side N-factor. Reads are users:read, mutations users:update
	// — enrolling or revoking a factor changes who can log in. ---
	hasFactors := func(s *Server) bool { return s.authFactorHandlers != nil }
	permIf("GET", "/factors/", auth.ResourceUsers, auth.ActionRead, hasFactors, func(s *Server) http.HandlerFunc { return s.authFactorHandlers.ListHandler })
	permIf("POST", "/factors/", auth.ResourceUsers, auth.ActionUpdate, hasFactors, func(s *Server) http.HandlerFunc { return s.authFactorHandlers.AddHandler })
	permIf("POST", "/factors/login", auth.ResourceUsers, auth.ActionRead, hasFactors, func(s *Server) http.HandlerFunc { return s.authFactorHandlers.LoginHandler })
	permIf("GET", "/factors/{factorID}", auth.ResourceUsers, auth.ActionRead, hasFactors, func(s *Server) http.HandlerFunc { return s.authFactorHandlers.GetHandler })
	permIf("DELETE", "/factors/{factorID}", auth.ResourceUsers, auth.ActionUpdate, hasFactors, func(s *Server) http.HandlerFunc { return s.authFactorHandlers.RemoveHandler })
	permIf("PATCH", "/factors/{factorID}", auth.ResourceUsers, auth.ActionUpdate, hasFactors, func(s *Server) http.HandlerFunc { return s.authFactorHandlers.RelabelHandler })
	permIf("POST", "/factors/{factorID}/rotate", auth.ResourceUsers, auth.ActionUpdate, hasFactors, func(s *Server) http.HandlerFunc { return s.authFactorHandlers.RotateHandler })

	// --- Audit chain, read-only: audit:read is its own permission, never
	// a freebie for anyone already authenticated. ---
	hasAudit := func(s *Server) bool { return s.auditHandlers != nil }
	permIf("GET", "/audit/", auth.ResourceAudit, auth.ActionRead, hasAudit, func(s *Server) http.HandlerFunc { return s.auditHandlers.QueryHandler })

	// --- Session endpoints. Exchange endpoints are unauthenticated (they
	// ARE the authentication); introspection requires a live session. ---
	hasIssuer := func(s *Server) bool { return s.tokenIssuer != nil }
	specs = append(specs,
		RouteSpec{Method: "POST", Pattern: "/api/v1/auth/login/piv", Group: GroupAuthSession, Auth: RouteAuthPublic, Enabled: hasIssuer, Handler: func(s *Server) http.HandlerFunc { return s.handlePIVLogin }},
		RouteSpec{Method: "POST", Pattern: "/api/v1/auth/refresh", Group: GroupAuthSession, Auth: RouteAuthPublic, Enabled: hasIssuer, Handler: func(s *Server) http.HandlerFunc { return s.handleAuthRefresh }},
		RouteSpec{Method: "GET", Pattern: "/api/v1/auth/me", Group: GroupAuthSession, Auth: RouteAuthSession, Enabled: hasIssuer, Handler: func(s *Server) http.HandlerFunc { return s.handleAuthMe }},
		RouteSpec{Method: "GET", Pattern: "/api/v1/auth/validate", Group: GroupAuthSession, Auth: RouteAuthSession, Enabled: hasIssuer, Handler: func(s *Server) http.HandlerFunc { return s.handleAuthValidate }},
		RouteSpec{Method: "POST", Pattern: "/api/v1/auth/logout", Group: GroupAuthSession, Auth: RouteAuthSession, Enabled: hasIssuer, Handler: func(s *Server) http.HandlerFunc { return s.handleAuthLogout }},
	)

	// --- WebAuthn (unauthenticated: WebAuthn IS the auth mechanism).
	// Browser ceremony routes mirror pkg/webauthn/http MountChi; the SDK
	// ceremony routes delegate to the XKMSService. ---
	hasWebAuthn := func(s *Server) bool { return s.webauthnHandler != nil }
	wa := func(method, pattern string, h func(s *Server) http.HandlerFunc) {
		specs = append(specs, RouteSpec{Method: method, Pattern: "/api/v1/webauthn" + pattern, Group: GroupWebAuthn, Auth: RouteAuthPublic, Enabled: hasWebAuthn, Handler: h})
	}
	wa("POST", "/registration/begin", func(s *Server) http.HandlerFunc { return s.webauthnHandler.BeginRegistration })
	wa("POST", "/registration/finish", func(s *Server) http.HandlerFunc { return s.webauthnHandler.FinishRegistration })
	wa("GET", "/registration/status", func(s *Server) http.HandlerFunc { return s.webauthnHandler.RegistrationStatus })
	wa("POST", "/login/begin", func(s *Server) http.HandlerFunc { return s.webauthnHandler.BeginLogin })
	wa("POST", "/login/finish", func(s *Server) http.HandlerFunc { return s.webauthnHandler.FinishLogin })
	wa("POST", "/sdk/registration/begin", func(s *Server) http.HandlerFunc { return s.handleSDKBeginRegistration })
	wa("POST", "/sdk/registration/finish", func(s *Server) http.HandlerFunc { return s.handleSDKFinishRegistration })
	wa("POST", "/sdk/authentication/begin", func(s *Server) http.HandlerFunc { return s.handleSDKBeginAuthentication })
	wa("POST", "/sdk/authentication/finish", func(s *Server) http.HandlerFunc { return s.handleSDKFinishAuthentication })

	// --- Users. xkms presents its own user API backed by the embedded
	// qrdb node; authentication only, no tenant middleware. ---
	user := func(method, pattern, resource, action string, h func(s *Server) http.HandlerFunc) {
		specs = append(specs, RouteSpec{Method: method, Pattern: "/api/v1/users" + pattern, Group: GroupUsers, Auth: RouteAuthPermission, Resource: resource, Action: action, Handler: h})
	}
	user("POST", "/", auth.ResourceUsers, auth.ActionCreate, func(s *Server) http.HandlerFunc { return s.handleCreateUser })
	user("GET", "/", auth.ResourceUsers, auth.ActionList, func(s *Server) http.HandlerFunc { return s.handleListUsers })
	user("GET", "/{username}", auth.ResourceUsers, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handleGetUser })
	user("GET", "/{username}/credentials", auth.ResourceUsers, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handleListUserCredentials })
	user("PUT", "/{username}", auth.ResourceUsers, auth.ActionUpdate, func(s *Server) http.HandlerFunc { return s.handleUpdateUser })
	user("POST", "/{username}/cert-bindings", auth.ResourceUsers, auth.ActionUpdate, func(s *Server) http.HandlerFunc { return s.handleBindUserCert })
	user("DELETE", "/{username}", auth.ResourceUsers, auth.ActionDelete, func(s *Server) http.HandlerFunc { return s.handleDeleteUser })

	// --- SSH. Every route carries the blanket ssh:use gate; key
	// generation and signing must never be reachable anonymously. No
	// interactive SSH console is served, by design. ---
	hasSSH := func(s *Server) bool { return s.sshHandlers != nil }
	ssh := func(method, pattern string, h func(s *Server) http.HandlerFunc) {
		specs = append(specs, RouteSpec{Method: method, Pattern: "/xkms/v1/ssh" + pattern, Group: GroupSSH, Auth: RouteAuthPermission, Resource: auth.ResourceSSH, Action: auth.ActionUse, Enabled: hasSSH, Handler: h})
	}
	ssh("POST", "/keys", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleGenerate })
	ssh("POST", "/keys/import", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleImport })
	ssh("GET", "/keys", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleListKeys })
	ssh("GET", "/keys/{scope}/{owner}/{name}", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleGetKey })
	ssh("DELETE", "/keys/{scope}/{owner}/{name}", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleDeleteKey })
	ssh("GET", "/keys/{scope}/{owner}/{name}/public", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleExportPublic })
	ssh("POST", "/keys/{scope}/{owner}/{name}/sign", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleSign })
	ssh("POST", "/known-hosts", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleAddKnownHost })
	ssh("GET", "/known-hosts", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleListKnownHosts })
	ssh("DELETE", "/known-hosts/{host}", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleRemoveKnownHost })
	ssh("POST", "/known-hosts/{host}/verify", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleVerifyKnownHost })
	ssh("POST", "/authorized-keys", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleAddAuthorized })
	ssh("GET", "/authorized-keys", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleListAuthorized })
	ssh("GET", "/authorized-keys/{scope}/{owner}/{name}", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleGetAuthorized })
	ssh("DELETE", "/authorized-keys/{scope}/{owner}/{name}", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleRemoveAuthorized })
	ssh("POST", "/authorized-keys/emit", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleEmit })
	ssh("POST", "/authorized-keys/verify", func(s *Server) http.HandlerFunc { return s.sshHandlers.handleVerifyAuthorized })

	return specs
}
