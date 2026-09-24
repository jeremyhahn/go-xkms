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

package mcp

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/api/initgate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Authorization sentinels for the MCP JSON-RPC surface.
var (
	// ErrAuthorizerRequired is returned by NewServer when Config.EnableRBAC is
	// true but no usable Authorizer was supplied. The constructor refuses to
	// start a server that believes it enforces RBAC while every method would
	// in fact be allowed: enabling RBAC without a qrdb-backed authorizer is a
	// wiring bug, not a permissive deployment mode. Deployments that really
	// want an open gate leave EnableRBAC false.
	ErrAuthorizerRequired = errors.New("mcp: authorizer is required when rbac is enabled")

	// ErrPermissionDenied is the caller-facing denial for an authenticated
	// identity that lacks the qrdb role grant required by the invoked method.
	// The qrdb decision detail is logged, never returned, mirroring the REST
	// RBAC middleware's "Access denied: insufficient permissions" response.
	ErrPermissionDenied = errors.New("access denied: insufficient permissions")

	// ErrMethodPermissionUnmapped is returned when a dispatchable JSON-RPC
	// method carries no entry in methodPermissions and is not declared public.
	// The gate fails closed so a method added without a permission mapping is
	// denied rather than silently exposed.
	ErrMethodPermissionUnmapped = errors.New("access denied: method has no permission mapping")
)

// permission is the canonical go-qrdb resource:action pair required to invoke
// a JSON-RPC method. xkms defines no permission vocabulary of its own; every
// pair below is taken verbatim from the transport that already gates the
// equivalent operation (pkg/api/grpc/service.go, pkg/api/quic/handlers*.go,
// pkg/api/rest/server.go).
type permission struct {
	resource string
	action   string
}

// publicMethods are the JSON-RPC methods that carry no authorization
// requirement. Only liveness is public, matching the REST RBAC middleware's
// SkipPaths ("/health", "/health/live", "/health/ready", "/health/startup").
var publicMethods = map[string]struct{}{
	"health": {},

	// Algorithm discovery reports compiled-in capability and reads no state.
	// REST serves it unauthenticated (pkg/api/rest/server.go, outside the
	// authenticated /api/v1 group), so gating it here would make the same
	// question answerable on one transport and not another.
	"xkms.algorithms": {},
}

// methodPermissions maps every privileged JSON-RPC method to the qrdb
// resource:action grant the caller must hold. Sources, per namespace:
//
//   - xkms.* key/backend/cert methods — pkg/api/grpc/service.go's
//     s.authorize(ctx, "keys"|"certs"|"backends", ...) calls, which
//     pkg/api/quic/handlers.go mirrors one-for-one.
//   - xkms.attestKey / deriveKeyECDH / exportKeyMaterial / wrapKeyByID /
//     unwrapKeyByID — pkg/api/quic/handlers_keyops.go and the matching
//     pkg/api/rest/server.go route decorators (keys:get, keys:derive,
//     keys:export, keys:wrap, keys:unwrap).
//   - xkms.seal / unseal / canSeal — pkg/api/quic/handlers_seal.go
//     (keys:encrypt, keys:decrypt, keys:get), identical to the REST
//     /seal, /unseal, /seal/capability decorators.
//   - xkms.*PIV* — pkg/api/quic/handlers_piv.go (piv:read/write/delete/use).
//   - xkms.ca.* and xkms.ca.tcg.* — pkg/api/quic/handlers_ca.go and
//     handlers_ca_tcg.go (certs:read/generate/revoke).
//   - barrier.* — pkg/api/quic/handlers_barrier_pin.go and
//     handlers_barrier_shamir.go (seal:* plus barrier:unseal-share).
//   - init.* and credentials.* — pkg/api/quic/handlers_init_credentials.go
//     (ceremony:*, credentials:*).
//   - password.* — pkg/api/quic/handlers_password.go, whose
//     operationForMethod maps GET to read, POST/PUT to write, DELETE to
//     delete, plus the explicit unlock/lock/generate actions.
//   - ssh.* — pkg/api/quic/handlers_ssh.go (ssh:read/write/delete).
//   - frost.* — pkg/api/quic/handlers_frost.go, which gates the FROST
//     surface with the ordinary keys:* actions. The entries live here rather
//     than in the frost-tagged handlers so a `frost` build cannot ship an
//     unenforced FROST surface.
var methodPermissions = map[string]permission{
	// Backends.
	"xkms.listBackends": {auth.ResourceBackends, auth.ActionList},
	"xkms.getBackend":   {auth.ResourceBackends, auth.ActionRead},

	// Key lifecycle and crypto operations.
	"xkms.generateKey":         {auth.ResourceKeys, auth.ActionCreate},
	"xkms.getKey":              {auth.ResourceKeys, auth.ActionGet},
	"xkms.deleteKey":           {auth.ResourceKeys, auth.ActionDelete},
	"xkms.listKeys":            {auth.ResourceKeys, auth.ActionList},
	"xkms.rotateKey":           {auth.ResourceKeys, auth.ActionRotate},
	"xkms.sign":                {auth.ResourceKeys, auth.ActionSign},
	"xkms.verify":              {auth.ResourceKeys, auth.ActionVerify},
	"xkms.encrypt":             {auth.ResourceKeys, auth.ActionEncrypt},
	"xkms.decrypt":             {auth.ResourceKeys, auth.ActionDecrypt},
	"xkms.asymmetricEncrypt":   {auth.ResourceKeys, auth.ActionEncrypt},
	"xkms.asymmetricDecrypt":   {auth.ResourceKeys, auth.ActionDecrypt},
	"xkms.getImportParameters": {auth.ResourceKeys, auth.ActionImport},
	"xkms.wrapKey":             {auth.ResourceKeys, auth.ActionWrap},
	"xkms.unwrapKey":           {auth.ResourceKeys, auth.ActionUnwrap},
	"xkms.importKey":           {auth.ResourceKeys, auth.ActionImport},
	"xkms.exportKey":           {auth.ResourceKeys, auth.ActionExport},
	"xkms.copyKey":             {auth.ResourceKeys, auth.ActionCreate},

	// Hardware-capability key operations.
	"xkms.attestKey":         {auth.ResourceKeys, auth.ActionGet},
	"xkms.deriveKeyECDH":     {auth.ResourceKeys, auth.ActionDerive},
	"xkms.exportKeyMaterial": {auth.ResourceKeys, auth.ActionExport},
	"xkms.wrapKeyByID":       {auth.ResourceKeys, auth.ActionWrap},
	"xkms.unwrapKeyByID":     {auth.ResourceKeys, auth.ActionUnwrap},

	// Certificate storage.
	"xkms.saveCert":          {auth.ResourceCerts, auth.ActionGenerate},
	"xkms.getCert":           {auth.ResourceCerts, auth.ActionRead},
	"xkms.deleteCert":        {auth.ResourceCerts, auth.ActionRevoke},
	"xkms.listCerts":         {auth.ResourceCerts, auth.ActionList},
	"xkms.certExists":        {auth.ResourceCerts, auth.ActionRead},
	"xkms.saveCertChain":     {auth.ResourceCerts, auth.ActionGenerate},
	"xkms.getCertChain":      {auth.ResourceCerts, auth.ActionRead},
	"xkms.getTLSCertificate": {auth.ResourceCerts, auth.ActionRead},

	// Hardware sealing.
	"xkms.seal":    {auth.ResourceKeys, auth.ActionEncrypt},
	"xkms.unseal":  {auth.ResourceKeys, auth.ActionDecrypt},
	"xkms.canSeal": {auth.ResourceKeys, auth.ActionGet},

	// PIV slots.
	"xkms.listPIVSlots":         {auth.ResourcePIV, auth.ActionRead},
	"xkms.getPIVCertificate":    {auth.ResourcePIV, auth.ActionRead},
	"xkms.storePIVCertificate":  {auth.ResourcePIV, auth.ActionWrite},
	"xkms.deletePIVCertificate": {auth.ResourcePIV, auth.ActionDelete},
	"xkms.generatePIVKey":       {auth.ResourcePIV, auth.ActionWrite},
	"xkms.importPIVCertificate": {auth.ResourcePIV, auth.ActionWrite},
	"xkms.exportPIVCertificate": {auth.ResourcePIV, auth.ActionRead},
	"xkms.generatePIVCSR":       {auth.ResourcePIV, auth.ActionUse},

	// Certificate authority.
	"xkms.ca.bundle":      {auth.ResourceCerts, auth.ActionRead},
	"xkms.ca.certificate": {auth.ResourceCerts, auth.ActionRead},
	"xkms.ca.sign-csr":    {auth.ResourceCerts, auth.ActionGenerate},
	"xkms.ca.issue":       {auth.ResourceCerts, auth.ActionGenerate},
	"xkms.ca.revoke":      {auth.ResourceCerts, auth.ActionRevoke},
	"xkms.ca.crl":         {auth.ResourceCerts, auth.ActionRead},
	"xkms.ca.is-revoked":  {auth.ResourceCerts, auth.ActionRead},

	// TCG certificate authority.
	"xkms.ca.tcg.issue-ek": {auth.ResourceCerts, auth.ActionGenerate},
	"xkms.ca.tcg.issue-ak": {auth.ResourceCerts, auth.ActionGenerate},
	"xkms.ca.tcg.sign-csr": {auth.ResourceCerts, auth.ActionGenerate},
	"xkms.ca.tcg.enroll":   {auth.ResourceCerts, auth.ActionGenerate},

	// Barrier lifecycle.
	"barrier.initialize":           {auth.ResourceSeal, auth.ActionBootstrap},
	"barrier.initializeShamir":     {auth.ResourceSeal, auth.ActionInitializeShamir},
	"barrier.unseal":               {auth.ResourceSeal, auth.ActionUnseal},
	"barrier.unsealShare":          {auth.ResourceBarrier, auth.ActionUnsealShare},
	"barrier.unsealShares":         {auth.ResourceSeal, auth.ActionUnseal},
	"barrier.seal":                 {auth.ResourceSeal, auth.ActionSeal},
	"barrier.status":               {auth.ResourceSeal, auth.ActionStatus},
	"barrier.rekey":                {auth.ResourceSeal, auth.ActionRekey},
	"barrier.generateRecoveryKeys": {auth.ResourceSeal, auth.ActionGenerateRecovery},
	"barrier.recoverWithKeys":      {auth.ResourceSeal, auth.ActionRecoverWithKeys},
	"barrier.deleteRecoveryKeys":   {auth.ResourceSeal, auth.ActionGenerateRecovery},
	"barrier.hasRecoveryKeys":      {auth.ResourceSeal, auth.ActionStatus},
	"barrier.generateRootToken":    {auth.ResourceSeal, auth.ActionRotateRootKey},
	"barrier.enableEncryption":     {auth.ResourceSeal, auth.ActionEnableEncryption},

	// Trust bootstrap listener (go-xkms#632).
	"bootstrap.showKeys": {auth.ResourceBootstrap, auth.ActionRead},

	// Shamir shares. Reads are ceremony status; writes (submit, delete)
	// move quorum material and carry the barrier's unseal-share action.
	"xkms.submitShare":              {auth.ResourceBarrier, auth.ActionUnsealShare},
	"xkms.listShares":               {auth.ResourceCeremony, auth.ActionStatus},
	"xkms.getShare":                 {auth.ResourceCeremony, auth.ActionStatus},
	"xkms.deleteShare":              {auth.ResourceBarrier, auth.ActionUnsealShare},
	"xkms.getShareCollectionStatus": {auth.ResourceCeremony, auth.ActionStatus},

	// Audit read plane. Emission is a side effect of the audited operation;
	// this is the only reader, gated on the audit resource with a read action.
	"xkms.queryAudit": {auth.ResourceAudit, auth.ActionRead},

	// Init ceremony.
	"init.getStatus":          {auth.ResourceCeremony, auth.ActionStatus},
	"init.claimCertBegin":     {auth.ResourceCeremony, auth.ActionClaimCert},
	"init.claimCertComplete":  {auth.ResourceCeremony, auth.ActionClaimCert},
	"init.claimShareBegin":    {auth.ResourceCeremony, auth.ActionClaimShareBegin},
	"init.claimShareComplete": {auth.ResourceCeremony, auth.ActionClaimShareComplete},
	"init.signCSR":            {auth.ResourceCeremony, auth.ActionSignCSR},

	// Credential submission.
	"credentials.submit":   {auth.ResourceCredentials, auth.ActionSubmit},
	"credentials.strategy": {auth.ResourceCredentials, auth.ActionStrategy},

	// User management. Mirrors pkg/api/rest/routes.go's /api/v1/users
	// decorators exactly: create/list/read/delete carry their ordinary CRUD
	// actions, enable/disable/bindCert all carry update since each mutates an
	// existing user's state rather than replacing it.
	"user.create":          {auth.ResourceUsers, auth.ActionCreate},
	"user.list":            {auth.ResourceUsers, auth.ActionList},
	"user.get":             {auth.ResourceUsers, auth.ActionRead},
	"user.delete":          {auth.ResourceUsers, auth.ActionDelete},
	"user.enable":          {auth.ResourceUsers, auth.ActionUpdate},
	"user.disable":         {auth.ResourceUsers, auth.ActionUpdate},
	"user.bindCert":        {auth.ResourceUsers, auth.ActionUpdate},
	"user.listCredentials": {auth.ResourceUsers, auth.ActionRead},

	// Password store.
	"password.add":           {auth.ResourcePasswords, auth.ActionWrite},
	"password.get":           {auth.ResourcePasswords, auth.ActionRead},
	"password.list":          {auth.ResourcePasswords, auth.ActionRead},
	"password.update":        {auth.ResourcePasswords, auth.ActionWrite},
	"password.delete":        {auth.ResourcePasswords, auth.ActionDelete},
	"password.unlock":        {auth.ResourcePasswords, auth.ActionUnlock},
	"password.lock":          {auth.ResourcePasswords, auth.ActionLock},
	"password.status":        {auth.ResourcePasswords, auth.ActionRead},
	"password.generate":      {auth.ResourcePasswords, auth.ActionGenerate},
	"password.setAccessMode": {auth.ResourcePasswords, auth.ActionWrite},

	// Platform-sealed store. Secrets sealed here are key-protection
	// material, so the actions mirror the keys:* pairs used by every other
	// transport's SealStore* handlers.
	"sealStore.put":    {auth.ResourceKeys, auth.ActionWrite},
	"sealStore.get":    {auth.ResourceKeys, auth.ActionRead},
	"sealStore.delete": {auth.ResourceKeys, auth.ActionDelete},
	"sealStore.list":   {auth.ResourceKeys, auth.ActionList},
	"sealStore.reseal": {auth.ResourceKeys, auth.ActionWrite},
	"sealStore.status": {auth.ResourceKeys, auth.ActionRead},

	// SSH keys.
	"ssh.keys.generate": {auth.ResourceSSH, auth.ActionWrite},
	"ssh.keys.import":   {auth.ResourceSSH, auth.ActionWrite},
	"ssh.keys.list":     {auth.ResourceSSH, auth.ActionRead},
	"ssh.keys.get":      {auth.ResourceSSH, auth.ActionRead},
	"ssh.keys.delete":   {auth.ResourceSSH, auth.ActionDelete},
	"ssh.keys.export":   {auth.ResourceSSH, auth.ActionRead},
	"ssh.keys.sign":     {auth.ResourceSSH, auth.ActionWrite},

	// SSH known hosts.
	"ssh.knownHosts.add":    {auth.ResourceSSH, auth.ActionWrite},
	"ssh.knownHosts.list":   {auth.ResourceSSH, auth.ActionRead},
	"ssh.knownHosts.remove": {auth.ResourceSSH, auth.ActionDelete},
	"ssh.knownHosts.verify": {auth.ResourceSSH, auth.ActionRead},

	// SSH authorized keys.
	"ssh.authorizedKeys.add":    {auth.ResourceSSH, auth.ActionWrite},
	"ssh.authorizedKeys.get":    {auth.ResourceSSH, auth.ActionRead},
	"ssh.authorizedKeys.list":   {auth.ResourceSSH, auth.ActionRead},
	"ssh.authorizedKeys.remove": {auth.ResourceSSH, auth.ActionDelete},
	"ssh.authorizedKeys.emit":   {auth.ResourceSSH, auth.ActionRead},
	"ssh.authorizedKeys.verify": {auth.ResourceSSH, auth.ActionRead},

	// FROST threshold signatures.
	"frost.generateKey":    {auth.ResourceKeys, auth.ActionCreate},
	"frost.importKey":      {auth.ResourceKeys, auth.ActionImport},
	"frost.listKeys":       {auth.ResourceKeys, auth.ActionList},
	"frost.getKey":         {auth.ResourceKeys, auth.ActionGet},
	"frost.deleteKey":      {auth.ResourceKeys, auth.ActionDelete},
	"frost.generateNonces": {auth.ResourceKeys, auth.ActionSign},
	"frost.signRound":      {auth.ResourceKeys, auth.ActionSign},
	"frost.aggregate":      {auth.ResourceKeys, auth.ActionSign},
	"frost.verify":         {auth.ResourceKeys, auth.ActionVerify},
}

// publicCeremonyMethods is the exact-match allowlist of init ceremony JSON-RPC
// methods a credential-less officer may invoke. It is derived from the
// canonical transport-neutral table in pkg/api/initgate — never hand-edited —
// so the REST, QUIC and MCP exemptions cannot drift apart. init.signCSR is
// deliberately absent (initgate.Exclusions): it requires the SO PIN and is
// invoked by an already-enrolled operator, so it stays behind the ordinary
// permission gate.
// The two claim-share methods additionally require a client certificate: the
// handlers derive the caller's thumbprint from the verified mTLS peer chain on
// the connection context and match it against the officer's enrolment record.
// What they skip here is *account* authorization, not identity assertion.
var publicCeremonyMethods = initgate.MCPPublicMethods()

// isPublicCeremonyMethod reports whether method is an init ceremony claim
// method invoked while the ceremony is still in progress. It fails closed when
// no XKMS service is wired, when no ceremony service sits behind it, or when
// the ceremony has reached the operational state.
func (s *Server) isPublicCeremonyMethod(ctx context.Context, method string) bool {
	if _, ok := publicCeremonyMethods[method]; !ok {
		return false
	}
	if s.xkmsService == nil {
		return false
	}

	status, err := s.xkmsService.GetInitStatus(ctx)
	if err != nil || status == nil {
		return false
	}
	// The exemption applies only while the ceremony is pre-operational;
	// initgate.PreOperationalName fails closed on any state it does not name.
	return initgate.PreOperationalName(status.State)
}

// frostMethodPrefix identifies the FROST namespace. Its handlers live behind
// the `frost` build tag, so dispatchability is decided by prefix here: a
// frost.* method that is missing from methodPermissions is denied rather than
// treated as an unknown method.
const frostMethodPrefix = "frost."

// isDispatchable reports whether the server has a handler for the method. It
// covers the two dispatch paths InvokeMethod uses: the rpcMethodHandlers
// table and the build-tagged FROST namespace.
func isDispatchable(method string) bool {
	if _, ok := rpcMethodHandlers[method]; ok {
		return true
	}
	return strings.HasPrefix(method, frostMethodPrefix)
}

// authorizeMethod gates a JSON-RPC method against the qrdb-backed authorizer.
//
// When RBAC is disabled the gate is a no-op: every authenticated caller may
// invoke every method. That matches the REST server (which registers its
// routes without the RBAC decorator when EnableRBAC is false) and the QUIC
// server (whose default authorizer has no RBAC client and therefore allows
// all). Authentication is still mandatory on every transport, RBAC or not.
//
// When RBAC is enabled the method must resolve to a permission: a missing
// identity is reported as ErrCodeUnauthorized, a denied grant and an unmapped
// dispatchable method as ErrCodeForbidden. Failures are returned as
// *KeyOpError so InvokeMethod's existing errors.As unwrapping selects the
// wire-level code.
func (s *Server) authorizeMethod(ctx context.Context, method string) error {
	if !s.rbacEnabled {
		return nil
	}

	if _, public := publicMethods[method]; public {
		return nil
	}

	// The init ceremony claim surface is public only while the ceremony has
	// not reached the operational state -- an officer's first credential is
	// the certificate those methods hand out, so gating them on an identity
	// deadlocks M-of-N enrollment. The condition fails closed: an operational
	// (or unreadable) ceremony falls through to the ordinary permission gate.
	if s.isPublicCeremonyMethod(ctx, method) {
		s.logger.DebugContext(ctx, "MCP init ceremony method served without authorization",
			slog.String("method", method))
		return nil
	}

	perm, mapped := methodPermissions[method]
	if !mapped {
		// An unknown method falls through to the dispatcher, which answers
		// with "Method not found". A dispatchable one without a mapping is a
		// registration bug: deny it.
		if !isDispatchable(method) {
			return nil
		}
		s.logger.ErrorContext(ctx, "MCP method has no permission mapping; denying",
			slog.String("method", method))
		return &KeyOpError{Code: ErrCodeForbidden, Err: ErrMethodPermissionUnmapped}
	}

	identity := auth.GetIdentity(ctx)
	if identity == nil {
		s.logger.WarnContext(ctx, "MCP authorization failed: no identity on request",
			slog.String("method", method),
			slog.String("resource", perm.resource),
			slog.String("action", perm.action))
		return &KeyOpError{Code: ErrCodeUnauthorized, Err: auth.ErrUnauthenticated}
	}

	if err := s.authorizer.Authorize(ctx, identity, perm.resource, perm.action); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return &KeyOpError{Code: ErrCodeUnauthorized, Err: err}
		}
		s.logger.WarnContext(ctx, "MCP authorization denied",
			slog.String("method", method),
			slog.String("subject", identity.Subject),
			slog.String("resource", perm.resource),
			slog.String("action", perm.action),
			slog.String("error", err.Error()))
		return &KeyOpError{Code: ErrCodeForbidden, Err: ErrPermissionDenied}
	}

	s.logger.DebugContext(ctx, "MCP authorization granted",
		slog.String("method", method),
		slog.String("subject", identity.Subject),
		slog.String("resource", perm.resource),
		slog.String("action", perm.action))

	return nil
}
