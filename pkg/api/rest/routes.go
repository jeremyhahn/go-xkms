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

	// --- Trust bootstrap listener (go-xkms#632): the listener's own public
	// keys, admin-read-only. Distinct from /v1/ca/bootstrap above, which is
	// the public CA-bundle fetch endpoint. ---
	hasBootstrapHandlers := func(s *Server) bool { return s.bootstrapHandlers != nil }
	permIf("GET", "/bootstrap/keys", auth.ResourceBootstrap, auth.ActionRead, hasBootstrapHandlers, func(s *Server) http.HandlerFunc { return s.bootstrapHandlers.ShowKeysHandler })

	// --- PIN management. Every route carries exactly the pin:* pair
	// pkg/api/grpc/service_barrier_pin.go authorizes (and the proto's
	// qrdb.v1.permission option declares) for the same operation: setting,
	// changing, or resetting a PIN's lockout is pin:write; verifying a PIN
	// or reading the lockout counters is pin:read. An authenticated session
	// alone never reaches the token's PIN surface (go-xkms#780). ---
	perm("POST", "/pin/so/set", auth.ResourcePIN, auth.ActionWrite, func(s *Server) http.HandlerFunc { return s.handlers.SetSOPINHandler })
	perm("POST", "/pin/user/set", auth.ResourcePIN, auth.ActionWrite, func(s *Server) http.HandlerFunc { return s.handlers.SetUserPINHandler })
	perm("POST", "/pin/so/change", auth.ResourcePIN, auth.ActionWrite, func(s *Server) http.HandlerFunc { return s.handlers.ChangeSOPINHandler })
	perm("POST", "/pin/user/change", auth.ResourcePIN, auth.ActionWrite, func(s *Server) http.HandlerFunc { return s.handlers.ChangeUserPINHandler })
	perm("POST", "/pin/so/verify", auth.ResourcePIN, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.VerifySOPINHandler })
	perm("POST", "/pin/user/verify", auth.ResourcePIN, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.VerifyUserPINHandler })
	perm("GET", "/pin/lockout", auth.ResourcePIN, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.GetLockoutStatusHandler })
	perm("POST", "/pin/lockout/reset", auth.ResourcePIN, auth.ActionWrite, func(s *Server) http.HandlerFunc { return s.handlers.ResetLockoutHandler })

	// --- PIV. The piv:* pairs of pkg/api/grpc/service_piv.go and the MCP
	// xkms.*PIV* methods: reads are piv:read, certificate and key
	// provisioning piv:write, deletion piv:delete, and CSR generation —
	// a signature by a slot key that never leaves the card — piv:use. ---
	perm("GET", "/piv/slots", auth.ResourcePIV, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.ListPIVSlotsHandler })
	perm("GET", "/piv/slots/{slot}/certificate", auth.ResourcePIV, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.GetPIVCertificateHandler })
	perm("POST", "/piv/slots/{slot}/certificate", auth.ResourcePIV, auth.ActionWrite, func(s *Server) http.HandlerFunc { return s.handlers.StorePIVCertificateHandler })
	perm("DELETE", "/piv/slots/{slot}/certificate", auth.ResourcePIV, auth.ActionDelete, func(s *Server) http.HandlerFunc { return s.handlers.DeletePIVCertificateHandler })
	perm("POST", "/piv/slots/{slot}/generate", auth.ResourcePIV, auth.ActionWrite, func(s *Server) http.HandlerFunc { return s.handlers.GeneratePIVKeyHandler })
	perm("POST", "/piv/slots/{slot}/import", auth.ResourcePIV, auth.ActionWrite, func(s *Server) http.HandlerFunc { return s.handlers.ImportPIVCertificateHandler })
	perm("GET", "/piv/slots/{slot}/export", auth.ResourcePIV, auth.ActionRead, func(s *Server) http.HandlerFunc { return s.handlers.ExportPIVCertificateHandler })
	perm("POST", "/piv/slots/{slot}/csr", auth.ResourcePIV, auth.ActionUse, func(s *Server) http.HandlerFunc { return s.handlers.GeneratePIVCSRHandler })

	// --- CA. When the full CA subsystem is absent the legacy bundle
	// endpoint serves bootstrap alone; both variants of GET /ca/bundle carry
	// the same pair, because the unified-server module registers a
	// multi-variant route once under its first variant's permission. The
	// certs:* pairs are pkg/api/grpc/service_ca*.go's and the MCP xkms.ca.*
	// methods'. Unauthenticated first-contact trust stays on the public
	// /v1/ca/bootstrap route. GET /ca/crl has no counterpart on any other
	// transport (go-xkms#275), so it has no canonical pair to adopt and stays
	// session-authenticated until one is defined. ---
	hasCA := func(s *Server) bool { return s.caHandlers != nil }
	noCA := func(s *Server) bool { return s.caHandlers == nil }
	permIf("GET", "/ca/bundle", auth.ResourceCerts, auth.ActionRead, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleGetCABundle })
	permIf("GET", "/ca/certificate", auth.ResourceCerts, auth.ActionRead, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleGetCACertificate })
	permIf("POST", "/ca/sign-csr", auth.ResourceCerts, auth.ActionGenerate, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleSignCSR })
	permIf("POST", "/ca/issue", auth.ResourceCerts, auth.ActionGenerate, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleIssueCertificate })
	permIf("POST", "/ca/revoke", auth.ResourceCerts, auth.ActionRevoke, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleRevokeCertificate })
	permIf("POST", "/ca/crl", auth.ResourceCerts, auth.ActionRead, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleGenerateCRL })
	session("GET", "/ca/crl", hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleGetCRL })
	permIf("GET", "/ca/revoked/{serial}", auth.ResourceCerts, auth.ActionRead, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleIsRevoked })
	permIf("POST", "/ca/tcg/ek", auth.ResourceCerts, auth.ActionGenerate, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleIssueEKCertificate })
	permIf("POST", "/ca/tcg/ak", auth.ResourceCerts, auth.ActionGenerate, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleIssueAKCertificate })
	permIf("POST", "/ca/tcg/sign-csr", auth.ResourceCerts, auth.ActionGenerate, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleSignTCGCSR })
	permIf("POST", "/ca/tcg/enroll", auth.ResourceCerts, auth.ActionGenerate, hasCA, func(s *Server) http.HandlerFunc { return s.caHandlers.HandleEnrollDevice })
	permIf("GET", "/ca/bundle", auth.ResourceCerts, auth.ActionRead, noCA, func(s *Server) http.HandlerFunc { return s.handlers.GetCABundleHandler })

	// --- Custodian groups. The ceremony:* pairs of
	// pkg/api/grpc/service_custodian_share_tenant.go: reads are
	// ceremony:status; adding a custodian is ceremony:enroll_custodian and
	// removing one ceremony:revoke_custodian, because each changes who can
	// contribute an unseal share; distributing shares is
	// ceremony:claim_share_begin. ---
	hasCustodian := func(s *Server) bool { return s.custodianHandlers != nil }
	permIf("POST", "/custodian/groups/", auth.ResourceCeremony, auth.ActionEnrollCustodian, hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.CreateGroupHandler })
	permIf("GET", "/custodian/groups/", auth.ResourceCeremony, auth.ActionStatus, hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.ListGroupsHandler })
	permIf("GET", "/custodian/groups/{id}", auth.ResourceCeremony, auth.ActionStatus, hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.GetGroupHandler })
	permIf("DELETE", "/custodian/groups/{id}", auth.ResourceCeremony, auth.ActionRevokeCustodian, hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.DeleteGroupHandler })
	permIf("POST", "/custodian/groups/{id}/members", auth.ResourceCeremony, auth.ActionEnrollCustodian, hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.AddMemberHandler })
	permIf("DELETE", "/custodian/groups/{id}/members/{userID}", auth.ResourceCeremony, auth.ActionRevokeCustodian, hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.RemoveMemberHandler })
	permIf("POST", "/custodian/groups/{id}/distribute", auth.ResourceCeremony, auth.ActionClaimShareBegin, hasCustodian, func(s *Server) http.HandlerFunc { return s.custodianHandlers.DistributeSharesHandler })

	// --- Shares (Shamir custody). Reads are ceremony:status; submitting
	// or deleting a share moves quorum material and carries
	// barrier:unseal-share — the gRPC and MCP pairs for the same calls. ---
	hasShares := func(s *Server) bool { return s.shareHandlers != nil }
	permIf("POST", "/shares/submit", auth.ResourceBarrier, auth.ActionUnsealShare, hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.SubmitShareHandler })
	permIf("GET", "/shares/", auth.ResourceCeremony, auth.ActionStatus, hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.ListSharesHandler })
	permIf("GET", "/shares/{serverURL}/{groupID}/{shareIndex}", auth.ResourceCeremony, auth.ActionStatus, hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.GetShareHandler })
	permIf("DELETE", "/shares/{serverURL}/{groupID}/{shareIndex}", auth.ResourceBarrier, auth.ActionUnsealShare, hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.DeleteShareHandler })
	permIf("GET", "/shares/status/{groupID}", auth.ResourceCeremony, auth.ActionStatus, hasShares, func(s *Server) http.HandlerFunc { return s.shareHandlers.GetShareCollectionStatusHandler })

	// --- Tenants. Tenant metadata carries tenants:*; the per-tenant
	// barrier lifecycle is its own tenant_barrier:* family, distinct from
	// the system barrier's seal:*. Pairs are
	// pkg/api/grpc/service_custodian_share_tenant.go's. The permission gate
	// runs before the handler, so it answers 403 regardless of which
	// tenantID was named; a caller holding the grant still gets the
	// handlers' cross-tenant 404, which never distinguishes "belongs to
	// another tenant" from "does not exist". ---
	hasTenants := func(s *Server) bool { return s.tenantHandlers != nil }
	permIf("POST", "/tenants/", auth.ResourceTenants, auth.ActionCreate, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.CreateTenantHandler })
	permIf("GET", "/tenants/", auth.ResourceTenants, auth.ActionList, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.ListTenantsHandler })
	permIf("GET", "/tenants/{tenantID}", auth.ResourceTenants, auth.ActionRead, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.GetTenantHandler })
	permIf("DELETE", "/tenants/{tenantID}", auth.ResourceTenants, auth.ActionDelete, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.DeleteTenantHandler })
	permIf("GET", "/tenants/{tenantID}/barrier/status", auth.ResourceTenantBarrier, auth.ActionStatus, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.TenantBarrierStatusHandler })
	permIf("POST", "/tenants/{tenantID}/barrier/init", auth.ResourceTenantBarrier, auth.ActionInit, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.TenantBarrierInitHandler })
	permIf("POST", "/tenants/{tenantID}/barrier/unseal", auth.ResourceTenantBarrier, auth.ActionUnseal, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.TenantBarrierUnsealHandler })
	permIf("PUT", "/tenants/{tenantID}/entitlements", auth.ResourceTenants, auth.ActionUpdate, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.UpdateTenantEntitlementsHandler })
	permIf("PUT", "/tenants/{tenantID}/quotas", auth.ResourceTenants, auth.ActionUpdate, hasTenants, func(s *Server) http.HandlerFunc { return s.tenantHandlers.UpdateTenantQuotasHandler })

	// --- Passwords. The passwords:* pairs of pkg/api/grpc/service_password.go
	// and the MCP password.* methods. POST /passwords/access-mode has no
	// counterpart on any other transport, so it has no canonical pair to
	// adopt and stays session-authenticated until one is defined. ---
	hasPasswords := func(s *Server) bool { return s.passwordHandlers != nil }
	permIf("POST", "/passwords/", auth.ResourcePasswords, auth.ActionWrite, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.AddPasswordHandler })
	permIf("GET", "/passwords/", auth.ResourcePasswords, auth.ActionRead, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.ListPasswordsHandler })
	permIf("GET", "/passwords/{id}", auth.ResourcePasswords, auth.ActionRead, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.GetPasswordHandler })
	permIf("PUT", "/passwords/{id}", auth.ResourcePasswords, auth.ActionWrite, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.UpdatePasswordHandler })
	permIf("DELETE", "/passwords/{id}", auth.ResourcePasswords, auth.ActionDelete, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.DeletePasswordHandler })
	permIf("POST", "/passwords/unlock", auth.ResourcePasswords, auth.ActionUnlock, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.UnlockHandler })
	permIf("POST", "/passwords/lock", auth.ResourcePasswords, auth.ActionLock, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.LockHandler })
	permIf("GET", "/passwords/status", auth.ResourcePasswords, auth.ActionRead, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.StatusHandler })
	session("POST", "/passwords/access-mode", hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.SetAccessModeHandler })
	permIf("POST", "/passwords/generate", auth.ResourcePasswords, auth.ActionGenerate, hasPasswords, func(s *Server) http.HandlerFunc { return s.passwordHandlers.GeneratePasswordHandler })

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
	// enrolment stay behind authentication and RBAC on every transport.
	// status and claim-* stay session-authenticated rather than carrying
	// MCP's ceremony:* pairs: the RequirePermission decorator has no
	// pre-operational exemption, so gating them here would refuse the
	// account-less officer the exemption exists for. officer/status has no
	// counterpart on any other transport. ---
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

	// --- Credentials. submit and strategy carry the credentials:* pairs
	// the MCP credentials.* methods are gated with; neither is on the
	// pre-operational ceremony allowlist, so gating them never blocks an
	// account-less officer. GET /credentials/ has no counterpart on any
	// other transport, so it has no canonical pair to adopt and stays
	// session-authenticated until one is defined. ---
	hasCreds := func(s *Server) bool { return s.credentialHandlers != nil }
	permIf("POST", "/credentials/submit", auth.ResourceCredentials, auth.ActionSubmit, hasCreds, func(s *Server) http.HandlerFunc { return s.credentialHandlers.HandleSubmit })
	permIf("GET", "/credentials/strategy", auth.ResourceCredentials, auth.ActionStrategy, hasCreds, func(s *Server) http.HandlerFunc { return s.credentialHandlers.HandleGetStrategy })
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

	// --- Cluster (go-xkms#847). Raft shard status and membership, backed by
	// the embedded go-qrdb node's own cluster client
	// (pkg/xkms/servicer_cluster.go). Status and membership reads never fail
	// on a standalone node — they report clustered:false and an empty
	// member list — so both GET routes register unconditionally, matching
	// clusterHandlers' own unconditional construction in NewServer.
	// Membership mutation is NOT exposed over REST at all — there is no
	// POST/DELETE here to stub out. Raft membership changes go through
	// go-qrdb's own control plane exclusively, via `xkmsctl cluster
	// add`/`remove` (docs/clustering/api.md, docs/web/parity.md "Cluster
	// mutations"). Permissions mirror go-qrdb's own AdminService vocabulary
	// exactly (admin:status, admin:peers — pkg/permission/constants.go),
	// matching what xkmsd registers on its control-plane gRPC surface
	// (pkg/server/qrdb_control_plane.go). ---
	perm("GET", "/cluster/status", auth.ResourceAdmin, auth.ActionStatus, func(s *Server) http.HandlerFunc { return s.clusterHandlers.StatusHandler })
	perm("GET", "/cluster/members", auth.ResourceAdmin, auth.ActionPeers, func(s *Server) http.HandlerFunc { return s.clusterHandlers.MembersHandler })

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
