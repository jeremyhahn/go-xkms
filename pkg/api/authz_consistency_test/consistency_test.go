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

// Package authz_consistency_test proves that a capability reachable over more
// than one transport requires the identical go-qrdb resource:action grant on
// every transport that exposes it (go-xkms#1232).
//
// pkg/api/grpc, pkg/api/rest, and pkg/api/mcp each already pin their own
// wire contract against their own source (authz_golden_test.go in each
// package). This package is the fourth leg: it re-derives the same three
// tables with internal/authzscan and cross-checks a hand-built capability
// map against them, so a capability that drifts on only one transport fails
// here even though each transport's own golden test still passes (a golden
// only proves a table is internally self-consistent, not that it agrees
// with the other two).
//
// It lives in its own package, alongside pkg/api/keyops_parity_test, for the
// same reason: a single test cannot import both pkg/api/rest and
// pkg/api/grpc from inside either one, and this check does not import them
// at all -- it points internal/authzscan at their source directories
// directly, exactly as each package's own golden test points it at ".".
package authz_consistency_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/authzscan"
)

const (
	grpcDir = "../grpc"
	restDir = "../rest"
	mcpDir  = "../mcp"
)

// grpcSeams mirrors pkg/api/grpc/authz_golden_test.go's authzSeams exactly.
// It cannot be imported from there (unexported, and importing pkg/api/grpc
// here would pull in build-tagged proto generated code this check does not
// need), so it is kept in sync by the two packages' own goldens: if
// pkg/api/grpc/service.go's authorize seam shape ever changes, that
// package's own TestRPCPermissions_MatchWireContract fails first.
var grpcSeams = []authzscan.Seam{
	{Method: "authorize", Args: 4, ResourceArg: 1, ActionArg: 2},
}

// restSeams mirrors pkg/api/rest/authz_golden_test.go's authzSeams exactly.
var restSeams = []authzscan.Seam{
	{Method: "perm", Args: 5, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1"},
	{Method: "permBulk", Args: 5, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1"},
	{Method: "permIf", Args: 6, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1"},
	{Method: "user", Args: 5, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1/users"},
	{Method: "ssh", Args: 4, ResourceArg: -1, ActionArg: 2, FixedResource: "ResourceSSH", Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/xkms/v1/ssh"},
}

// capability names one operation's identity on each transport that exposes
// it. An empty field means the operation does not exist on that transport,
// so it is not compared there.
type capability struct {
	GRPC string
	MCP  string
	REST string
}

// canonicalCapabilities is every capability go-xkms#1232's audit found
// reachable on two or more of gRPC, MCP, and REST, built by cross-reading
// pkg/api/grpc/authz_golden_test.go, pkg/api/mcp/authz_test.go, and
// pkg/api/rest/authz_golden_test.go's own wire-contract tables (plus, for
// GRPC-only operation names, pkg/api/grpc/service*.go's own authorize call
// sites). Verified byte-for-byte against those three tables while
// go-xkms#1232 was fixed: every entry here matched before that fix's one
// correction (keys.wrap / keys.unwrap, below) and matches after it.
//
// go-xkms#1249 closed every mismatch this table used to allowlist rather
// than fix, so there are no carve-outs left:
//
//   - pkcs11state.*: gRPC's seven PKCS11State* RPCs used to collapse every
//     mutation to keys:write and every read to keys:read, while REST's
//     /api/v1/pkcs11state/* routes already carried the ordinary per-verb
//     CRUD actions. gRPC now carries the same per-verb actions REST does.
//   - users.enable / users.disable: REST's single PUT /api/v1/users/{username}
//     used to pick EnableUser or DisableUser from a request-body field and
//     so could only carry the one coarse users:update permission for both
//     directions, while gRPC's EnableUser/DisableUser and MCP's
//     user.enable/user.disable required qrdb's own users:enable/
//     users:disable. REST now serves POST /api/v1/users/{username}/enable
//     and /disable as their own routes, one per qrdb-native permission,
//     matching gRPC and MCP; PUT no longer touches enablement at all.
//   - password.setAccessMode: REST used to serve
//     POST /api/v1/passwords/access-mode under RouteAuthSession (any
//     authenticated caller, no RBAC permission) while gRPC's
//     PasswordStoreSetAccessMode and MCP's password.setAccessMode both
//     required passwords:write — closed by the owner's 2026-09-29 ruling
//     that the password vault is not a login feature, so it takes the same
//     passwords:write every other mutating passwords:* route already
//     required. REST now gates it the same as its siblings.
var canonicalCapabilities = map[string]capability{
	"audit.query":              {GRPC: "QueryAudit", MCP: "xkms.queryAudit", REST: "GET /api/v1/audit/"},
	"backends.get":             {GRPC: "GetBackendInfo", MCP: "xkms.getBackend", REST: "GET /api/v1/backends/{id}"},
	"backends.list":            {GRPC: "ListBackends", MCP: "xkms.listBackends", REST: "GET /api/v1/backends"},
	"barrier.deleteRecovery":   {GRPC: "BarrierDeleteRecoveryKeys", MCP: "barrier.deleteRecoveryKeys", REST: "DELETE /api/v1/barrier/recovery/keys"},
	"barrier.enableEncryption": {GRPC: "BarrierEnableEncryption", MCP: "barrier.enableEncryption", REST: "POST /api/v1/barrier/enable-encryption"},
	"barrier.genRecovery":      {GRPC: "BarrierGenerateRecoveryKeys", MCP: "barrier.generateRecoveryKeys", REST: "POST /api/v1/barrier/recovery/generate"},
	"barrier.genRootToken":     {GRPC: "BarrierGenerateRootToken", MCP: "barrier.generateRootToken", REST: "POST /api/v1/barrier/recovery/root-token"},
	"barrier.hasRecoveryKeys":  {GRPC: "BarrierHasRecoveryKeys", MCP: "barrier.hasRecoveryKeys", REST: ""},
	"barrier.initShamir":       {GRPC: "BarrierInitializeShamir", MCP: "barrier.initializeShamir", REST: "POST /api/v1/barrier/shamir/initialize"},
	"barrier.initialize":       {GRPC: "BarrierInitialize", MCP: "barrier.initialize", REST: "POST /api/v1/barrier/initialize"},
	"barrier.recoverWithKeys":  {GRPC: "BarrierRecoverWithKeys", MCP: "barrier.recoverWithKeys", REST: "POST /api/v1/barrier/recovery/recover"},
	"barrier.rekey":            {GRPC: "BarrierRekey", MCP: "barrier.rekey", REST: "POST /api/v1/barrier/rekey"},
	"barrier.seal":             {GRPC: "BarrierSeal", MCP: "barrier.seal", REST: "POST /api/v1/barrier/seal"},
	"barrier.status":           {GRPC: "BarrierStatus", MCP: "barrier.status", REST: "GET /api/v1/barrier/status"},
	"barrier.unseal":           {GRPC: "BarrierUnseal", MCP: "barrier.unseal", REST: "POST /api/v1/barrier/unseal"},
	"barrier.unsealShare":      {GRPC: "BarrierUnsealShare", MCP: "barrier.unsealShare", REST: "POST /api/v1/barrier/shamir/unseal-share"},
	"barrier.unsealShares":     {GRPC: "BarrierUnsealShares", MCP: "barrier.unsealShares", REST: "POST /api/v1/barrier/shamir/unseal-shares"},
	"bootstrap.showKeys":       {GRPC: "BootstrapListenerKeys", MCP: "bootstrap.showKeys", REST: "GET /api/v1/bootstrap/keys"},
	"ca.bundle":                {GRPC: "GetCABundle", MCP: "xkms.ca.bundle", REST: "GET /api/v1/ca/bundle#0"},
	"ca.certificate":           {GRPC: "GetCACertificate", MCP: "xkms.ca.certificate", REST: "GET /api/v1/ca/certificate"},
	"ca.crl":                   {GRPC: "GenerateCRL", MCP: "xkms.ca.crl", REST: "POST /api/v1/ca/crl"},
	"ca.isRevoked":             {GRPC: "IsRevoked", MCP: "xkms.ca.is-revoked", REST: "GET /api/v1/ca/revoked/{serial}"},
	"ca.issue":                 {GRPC: "IssueCertificate", MCP: "xkms.ca.issue", REST: "POST /api/v1/ca/issue"},
	"ca.revoke":                {GRPC: "RevokeCertificate", MCP: "xkms.ca.revoke", REST: "POST /api/v1/ca/revoke"},
	"ca.signCSR":               {GRPC: "SignCSR", MCP: "xkms.ca.sign-csr", REST: "POST /api/v1/ca/sign-csr"},
	"ca.tcg.enroll":            {GRPC: "EnrollDevice", MCP: "xkms.ca.tcg.enroll", REST: "POST /api/v1/ca/tcg/enroll"},
	"ca.tcg.issueAK":           {GRPC: "IssueAKCertificate", MCP: "xkms.ca.tcg.issue-ak", REST: "POST /api/v1/ca/tcg/ak"},
	"ca.tcg.issueEK":           {GRPC: "IssueEKCertificate", MCP: "xkms.ca.tcg.issue-ek", REST: "POST /api/v1/ca/tcg/ek"},
	"ca.tcg.signCSR":           {GRPC: "SignTCGCSR", MCP: "xkms.ca.tcg.sign-csr", REST: "POST /api/v1/ca/tcg/sign-csr"},
	"certs.delete":             {GRPC: "DeleteCert", MCP: "xkms.deleteCert", REST: "DELETE /api/v1/certs/{id}"},
	"certs.exists":             {GRPC: "CertExists", MCP: "xkms.certExists", REST: "HEAD /api/v1/certs/{id}"},
	"certs.get":                {GRPC: "GetCert", MCP: "xkms.getCert", REST: "GET /api/v1/certs/{id}"},
	"certs.getChain":           {GRPC: "GetCertChain", MCP: "xkms.getCertChain", REST: "GET /api/v1/certs/{id}/chain"},
	"certs.getTLS":             {GRPC: "GetTLSCertificate", MCP: "xkms.getTLSCertificate", REST: "GET /api/v1/tls/{id}"},
	"certs.list":               {GRPC: "ListCerts", MCP: "xkms.listCerts", REST: "GET /api/v1/certs"},
	"certs.save":               {GRPC: "SaveCert", MCP: "xkms.saveCert", REST: "POST /api/v1/certs"},
	"certs.saveChain":          {GRPC: "SaveCertChain", MCP: "xkms.saveCertChain", REST: "POST /api/v1/certs/{id}/chain"},
	"credentials.strategy":     {GRPC: "", MCP: "credentials.strategy", REST: "GET /api/v1/credentials/strategy"},
	"credentials.submit":       {GRPC: "", MCP: "credentials.submit", REST: "POST /api/v1/credentials/submit"},
	"backup.create":            {GRPC: "CreateBackup", MCP: "xkms.createBackup", REST: "POST /api/v1/backups"},
	"backup.list":              {GRPC: "ListBackups", MCP: "xkms.listBackups", REST: "GET /api/v1/backups"},
	"backup.get":               {GRPC: "GetBackup", MCP: "xkms.getBackup", REST: "GET /api/v1/backups/{id}"},
	"backup.delete":            {GRPC: "DeleteBackup", MCP: "xkms.deleteBackup", REST: "DELETE /api/v1/backups/{id}"},
	"backup.restore":           {GRPC: "RestoreBackup", MCP: "xkms.restoreBackup", REST: "POST /api/v1/backups/restore"},
	"backup.verify":            {GRPC: "VerifyBackup", MCP: "xkms.verifyBackup", REST: "POST /api/v1/backups/{id}/verify"},
	"custodian.add":            {GRPC: "AddCustodianMember", MCP: "xkms.addCustodianMember", REST: "POST /api/v1/custodian/groups/{id}/members"},
	"custodian.create":         {GRPC: "CreateCustodianGroup", MCP: "xkms.createCustodianGroup", REST: "POST /api/v1/custodian/groups/"},
	"custodian.delete":         {GRPC: "DeleteCustodianGroup", MCP: "xkms.deleteCustodianGroup", REST: "DELETE /api/v1/custodian/groups/{id}"},
	"custodian.distribute":     {GRPC: "DistributeShares", MCP: "xkms.distributeShares", REST: "POST /api/v1/custodian/groups/{id}/distribute"},
	"custodian.get":            {GRPC: "GetCustodianGroup", MCP: "xkms.getCustodianGroup", REST: "GET /api/v1/custodian/groups/{id}"},
	"custodian.list":           {GRPC: "ListCustodianGroups", MCP: "xkms.listCustodianGroups", REST: "GET /api/v1/custodian/groups/"},
	"custodian.remove":         {GRPC: "RemoveCustodianMember", MCP: "xkms.removeCustodianMember", REST: "DELETE /api/v1/custodian/groups/{id}/members/{userID}"},
	"frost.aggregate":          {GRPC: "FrostAggregate", MCP: "frost.aggregate", REST: "POST /api/v1/frost/aggregate"},
	"frost.delete":             {GRPC: "FrostDeleteKey", MCP: "frost.deleteKey", REST: "DELETE /api/v1/frost/keys/{id}"},
	"frost.generate":           {GRPC: "FrostGenerateKey", MCP: "frost.generateKey", REST: "POST /api/v1/frost/keys"},
	"frost.get":                {GRPC: "FrostGetKey", MCP: "frost.getKey", REST: "GET /api/v1/frost/keys/{id}"},
	"frost.import":             {GRPC: "FrostImportKey", MCP: "frost.importKey", REST: "POST /api/v1/frost/keys/import"},
	"frost.list":               {GRPC: "FrostListKeys", MCP: "frost.listKeys", REST: "GET /api/v1/frost/keys"},
	"frost.nonces":             {GRPC: "FrostGenerateNonces", MCP: "frost.generateNonces", REST: "POST /api/v1/frost/keys/{id}/nonces"},
	"frost.signRound":          {GRPC: "FrostSignRound", MCP: "frost.signRound", REST: "POST /api/v1/frost/keys/{id}/sign"},
	"frost.verify":             {GRPC: "FrostVerify", MCP: "frost.verify", REST: "POST /api/v1/frost/verify"},
	"init.signCSR":             {GRPC: "", MCP: "init.signCSR", REST: "POST /api/v1/init/sign-csr"},
	"keys.attest":              {GRPC: "AttestKey", MCP: "xkms.attestKey", REST: "POST /api/v1/attest"},
	"keys.canSeal":             {GRPC: "CanSeal", MCP: "xkms.canSeal", REST: "GET /api/v1/seal/capability"},
	"keys.copy":                {GRPC: "CopyKey", MCP: "xkms.copyKey", REST: "POST /api/v1/keys/copy"},
	"keys.decrypt":             {GRPC: "Decrypt", MCP: "xkms.decrypt", REST: "POST /api/v1/keys/{id}/decrypt"},
	"keys.delete":              {GRPC: "DeleteKey", MCP: "xkms.deleteKey", REST: "DELETE /api/v1/keys/{id}"},
	"keys.derive":              {GRPC: "DeriveKey", MCP: "xkms.deriveKey", REST: ""},
	"keys.deriveECDH":          {GRPC: "DeriveKeyECDH", MCP: "xkms.deriveKeyECDH", REST: "POST /api/v1/keys/derive-ecdh"},
	"keys.encrypt":             {GRPC: "Encrypt", MCP: "xkms.encrypt", REST: "POST /api/v1/keys/{id}/encrypt"},
	"keys.encryptAsym":         {GRPC: "EncryptAsym", MCP: "xkms.asymmetricEncrypt", REST: "POST /api/v1/keys/{id}/encrypt-asym"},
	"keys.export":              {GRPC: "ExportKey", MCP: "xkms.exportKey", REST: "POST /api/v1/keys/{id}/export"},
	"keys.exportMaterial":      {GRPC: "ExportKeyMaterial", MCP: "xkms.exportKeyMaterial", REST: "POST /api/v1/keys/{id}/export-material"},
	"keys.generate":            {GRPC: "GenerateKey", MCP: "xkms.generateKey", REST: "POST /api/v1/keys"},
	"keys.get":                 {GRPC: "GetKey", MCP: "xkms.getKey", REST: "GET /api/v1/keys/{id}"},
	"keys.getImportParameters": {GRPC: "GetImportParameters", MCP: "xkms.getImportParameters", REST: "POST /api/v1/keys/import-params"},
	"keys.import":              {GRPC: "ImportKey", MCP: "xkms.importKey", REST: "POST /api/v1/keys/import"},
	"keys.list":                {GRPC: "ListKeys", MCP: "xkms.listKeys", REST: "GET /api/v1/keys"},
	"keys.rotate":              {GRPC: "RotateKey", MCP: "xkms.rotateKey", REST: "POST /api/v1/keys/{id}/rotate"},
	"keys.seal":                {GRPC: "Seal", MCP: "xkms.seal", REST: "POST /api/v1/seal"},
	"keys.sign":                {GRPC: "Sign", MCP: "xkms.sign", REST: "POST /api/v1/keys/{id}/sign"},
	"keys.unseal":              {GRPC: "Unseal", MCP: "xkms.unseal", REST: "POST /api/v1/unseal"},
	"keys.unwrap":              {GRPC: "UnwrapKey", MCP: "xkms.unwrapKey", REST: "POST /api/v1/keys/unwrap"},
	"keys.unwrapByID":          {GRPC: "UnwrapKeyByID", MCP: "xkms.unwrapKeyByID", REST: "POST /api/v1/keys/unwrap-by-id"},
	"keys.verify":              {GRPC: "Verify", MCP: "xkms.verify", REST: "POST /api/v1/keys/{id}/verify"},
	"keys.wrap":                {GRPC: "WrapKey", MCP: "xkms.wrapKey", REST: "POST /api/v1/keys/wrap"},
	"keys.wrapByID":            {GRPC: "WrapKeyByID", MCP: "xkms.wrapKeyByID", REST: "POST /api/v1/keys/wrap-by-id"},
	"password.add":             {GRPC: "PasswordAdd", MCP: "password.add", REST: "POST /api/v1/passwords/"},
	"password.delete":          {GRPC: "PasswordDelete", MCP: "password.delete", REST: "DELETE /api/v1/passwords/{id}"},
	"password.generate":        {GRPC: "PasswordGenerate", MCP: "password.generate", REST: "POST /api/v1/passwords/generate"},
	"password.get":             {GRPC: "PasswordGet", MCP: "password.get", REST: "GET /api/v1/passwords/{id}"},
	"password.list":            {GRPC: "PasswordList", MCP: "password.list", REST: "GET /api/v1/passwords/"},
	"password.lock":            {GRPC: "PasswordStoreLock", MCP: "password.lock", REST: "POST /api/v1/passwords/lock"},
	"password.setAccessMode":   {GRPC: "PasswordStoreSetAccessMode", MCP: "password.setAccessMode", REST: "POST /api/v1/passwords/access-mode"},
	"password.status":          {GRPC: "PasswordStoreStatus", MCP: "password.status", REST: "GET /api/v1/passwords/status"},
	"password.unlock":          {GRPC: "PasswordStoreUnlock", MCP: "password.unlock", REST: "POST /api/v1/passwords/unlock"},
	"password.update":          {GRPC: "PasswordUpdate", MCP: "password.update", REST: "PUT /api/v1/passwords/{id}"},
	"pkcs11state.cad":          {GRPC: "PKCS11StateCAD", REST: "POST /api/v1/pkcs11state/compare-and-delete"},
	"pkcs11state.cas":          {GRPC: "PKCS11StateCAS", REST: "POST /api/v1/pkcs11state/compare-and-swap"},
	"pkcs11state.delete":       {GRPC: "PKCS11StateDelete", REST: "POST /api/v1/pkcs11state/delete"},
	"pkcs11state.get":          {GRPC: "PKCS11StateGet", REST: "POST /api/v1/pkcs11state/get"},
	"pkcs11state.list":         {GRPC: "PKCS11StateList", REST: "POST /api/v1/pkcs11state/list"},
	"pkcs11state.put":          {GRPC: "PKCS11StatePut", REST: "POST /api/v1/pkcs11state/put"},
	"pkcs11state.putIfAbsent":  {GRPC: "PKCS11StatePutIfAbsent", REST: "POST /api/v1/pkcs11state/put-if-absent"},
	"pin.changeSO":             {GRPC: "ChangeSOPIN", MCP: "xkms.changeSOPIN", REST: "POST /api/v1/pin/so/change"},
	"pin.changeUser":           {GRPC: "ChangeUserPIN", MCP: "xkms.changeUserPIN", REST: "POST /api/v1/pin/user/change"},
	"pin.getLockout":           {GRPC: "GetLockoutStatus", MCP: "xkms.getLockoutStatus", REST: "GET /api/v1/pin/lockout"},
	"pin.resetLockout":         {GRPC: "ResetLockout", MCP: "xkms.resetLockout", REST: "POST /api/v1/pin/lockout/reset"},
	"pin.setSO":                {GRPC: "SetSOPIN", MCP: "xkms.setSOPIN", REST: "POST /api/v1/pin/so/set"},
	"pin.setUser":              {GRPC: "SetUserPIN", MCP: "xkms.setUserPIN", REST: "POST /api/v1/pin/user/set"},
	"pin.verifySO":             {GRPC: "VerifySOPIN", MCP: "xkms.verifySOPIN", REST: "POST /api/v1/pin/so/verify"},
	"pin.verifyUser":           {GRPC: "VerifyUserPIN", MCP: "xkms.verifyUserPIN", REST: "POST /api/v1/pin/user/verify"},
	"piv.deleteCert":           {GRPC: "DeletePIVCertificate", MCP: "xkms.deletePIVCertificate", REST: "DELETE /api/v1/piv/slots/{slot}/certificate"},
	"piv.exportCert":           {GRPC: "ExportPIVCertificate", MCP: "xkms.exportPIVCertificate", REST: "GET /api/v1/piv/slots/{slot}/export"},
	"piv.generateCSR":          {GRPC: "GeneratePIVCSR", MCP: "xkms.generatePIVCSR", REST: "POST /api/v1/piv/slots/{slot}/csr"},
	"piv.generateKey":          {GRPC: "GeneratePIVKey", MCP: "xkms.generatePIVKey", REST: "POST /api/v1/piv/slots/{slot}/generate"},
	"piv.getCert":              {GRPC: "GetPIVCertificate", MCP: "xkms.getPIVCertificate", REST: "GET /api/v1/piv/slots/{slot}/certificate"},
	"piv.importCert":           {GRPC: "ImportPIVCertificate", MCP: "xkms.importPIVCertificate", REST: "POST /api/v1/piv/slots/{slot}/import"},
	"piv.list":                 {GRPC: "ListPIVSlots", MCP: "xkms.listPIVSlots", REST: "GET /api/v1/piv/slots"},
	"piv.storeCert":            {GRPC: "StorePIVCertificate", MCP: "xkms.storePIVCertificate", REST: "POST /api/v1/piv/slots/{slot}/certificate"},
	"sealStore.delete":         {GRPC: "SealStoreDelete", MCP: "sealStore.delete", REST: "DELETE /api/v1/platform/secrets/{name}"},
	"sealStore.get":            {GRPC: "SealStoreGet", MCP: "sealStore.get", REST: "GET /api/v1/platform/secrets/{name}"},
	"sealStore.list":           {GRPC: "SealStoreList", MCP: "sealStore.list", REST: "GET /api/v1/platform/secrets"},
	"sealStore.put":            {GRPC: "SealStorePut", MCP: "sealStore.put", REST: "PUT /api/v1/platform/secrets/{name}"},
	"sealStore.reseal":         {GRPC: "SealStoreReseal", MCP: "sealStore.reseal", REST: "POST /api/v1/platform/secrets/{name}/reseal"},
	"sealStore.status":         {GRPC: "SealStoreStatus", MCP: "sealStore.status", REST: "GET /api/v1/platform/status"},
	"shares.collectionStatus":  {GRPC: "GetShareCollectionStatus", MCP: "xkms.getShareCollectionStatus", REST: "GET /api/v1/shares/status/{groupID}"},
	"shares.delete":            {GRPC: "DeleteShare", MCP: "xkms.deleteShare", REST: "DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex}"},
	"shares.get":               {GRPC: "GetShare", MCP: "xkms.getShare", REST: "GET /api/v1/shares/{serverURL}/{groupID}/{shareIndex}"},
	"shares.list":              {GRPC: "ListShares", MCP: "xkms.listShares", REST: "GET /api/v1/shares/"},
	"shares.submit":            {GRPC: "SubmitShare", MCP: "xkms.submitShare", REST: "POST /api/v1/shares/submit"},
	"ssh.addAuthorized":        {GRPC: "SSHAddAuthorizedKey", MCP: "ssh.authorizedKeys.add", REST: "POST /xkms/v1/ssh/authorized-keys"},
	"ssh.addKnownHost":         {GRPC: "SSHAddKnownHost", MCP: "ssh.knownHosts.add", REST: "POST /xkms/v1/ssh/known-hosts"},
	"ssh.delete":               {GRPC: "SSHDeleteKey", MCP: "ssh.keys.delete", REST: "DELETE /xkms/v1/ssh/keys/{scope}/{owner}/{name}"},
	"ssh.emitAuthorized":       {GRPC: "", MCP: "ssh.authorizedKeys.emit", REST: "POST /xkms/v1/ssh/authorized-keys/emit"},
	"ssh.exportPublic":         {GRPC: "SSHExportPublic", MCP: "ssh.keys.export", REST: "GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}/public"},
	"ssh.generate":             {GRPC: "SSHGenerateKey", MCP: "ssh.keys.generate", REST: "POST /xkms/v1/ssh/keys"},
	"ssh.get":                  {GRPC: "SSHGetKey", MCP: "ssh.keys.get", REST: "GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}"},
	"ssh.getAuthorized":        {GRPC: "", MCP: "ssh.authorizedKeys.get", REST: "GET /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name}"},
	"ssh.import":               {GRPC: "SSHImportKey", MCP: "ssh.keys.import", REST: "POST /xkms/v1/ssh/keys/import"},
	"ssh.list":                 {GRPC: "SSHListKeys", MCP: "ssh.keys.list", REST: "GET /xkms/v1/ssh/keys"},
	"ssh.listAuthorized":       {GRPC: "SSHListAuthorizedKeys", MCP: "ssh.authorizedKeys.list", REST: "GET /xkms/v1/ssh/authorized-keys"},
	"ssh.listKnownHosts":       {GRPC: "SSHListKnownHosts", MCP: "ssh.knownHosts.list", REST: "GET /xkms/v1/ssh/known-hosts"},
	"ssh.removeAuthorized":     {GRPC: "SSHRemoveAuthorizedKey", MCP: "ssh.authorizedKeys.remove", REST: "DELETE /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name}"},
	"ssh.removeKnownHost":      {GRPC: "SSHRemoveKnownHost", MCP: "ssh.knownHosts.remove", REST: "DELETE /xkms/v1/ssh/known-hosts/{host}"},
	"ssh.sign":                 {GRPC: "SSHSign", MCP: "ssh.keys.sign", REST: "POST /xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign"},
	"ssh.verifyAuthorized":     {GRPC: "", MCP: "ssh.authorizedKeys.verify", REST: "POST /xkms/v1/ssh/authorized-keys/verify"},
	"ssh.verifyKnownHost":      {GRPC: "", MCP: "ssh.knownHosts.verify", REST: "POST /xkms/v1/ssh/known-hosts/{host}/verify"},
	"tenant.barrierInit":       {GRPC: "TenantBarrierInit", MCP: "xkms.tenantBarrierInit", REST: "POST /api/v1/tenants/{tenantID}/barrier/init"},
	"tenant.barrierStatus":     {GRPC: "TenantBarrierStatus", MCP: "xkms.tenantBarrierStatus", REST: "GET /api/v1/tenants/{tenantID}/barrier/status"},
	"tenant.barrierUnseal":     {GRPC: "TenantBarrierUnseal", MCP: "xkms.tenantBarrierUnseal", REST: "POST /api/v1/tenants/{tenantID}/barrier/unseal"},
	"tenant.create":            {GRPC: "CreateTenant", MCP: "xkms.createTenant", REST: "POST /api/v1/tenants/"},
	"tenant.delete":            {GRPC: "DeleteTenant", MCP: "xkms.deleteTenant", REST: "DELETE /api/v1/tenants/{tenantID}"},
	"tenant.get":               {GRPC: "GetTenant", MCP: "xkms.getTenant", REST: "GET /api/v1/tenants/{tenantID}"},
	"tenant.list":              {GRPC: "ListTenants", MCP: "xkms.listTenants", REST: "GET /api/v1/tenants/"},
	"tenant.setEntitlements":   {GRPC: "UpdateTenantEntitlements", MCP: "xkms.updateTenantEntitlements", REST: "PUT /api/v1/tenants/{tenantID}/entitlements"},
	"tenant.setQuotas":         {GRPC: "UpdateTenantQuotas", MCP: "xkms.updateTenantQuotas", REST: "PUT /api/v1/tenants/{tenantID}/quotas"},
	"tenant.getTPMMode":        {GRPC: "GetTenantTPMMode", MCP: "xkms.getTenantTPMMode", REST: "GET /api/v1/tenants/{tenantID}/tpm"},
	"tenant.setTPMMode":        {GRPC: "SetTenantTPMMode", MCP: "xkms.setTenantTPMMode", REST: "PUT /api/v1/tenants/{tenantID}/tpm"},
	"tenant.vtpmStatus":        {GRPC: "TenantVTPMStatus", MCP: "xkms.tenantVTPMStatus", REST: "GET /api/v1/tenants/{tenantID}/tpm/vtpm"},
	"tenant.vtpmStart":         {GRPC: "TenantVTPMStart", MCP: "xkms.tenantVTPMStart", REST: "POST /api/v1/tenants/{tenantID}/tpm/vtpm/start"},
	"tenant.vtpmStop":          {GRPC: "TenantVTPMStop", MCP: "xkms.tenantVTPMStop", REST: "POST /api/v1/tenants/{tenantID}/tpm/vtpm/stop"},
	"tpmPolicy.create":         {GRPC: "TPMPolicyCreate", MCP: "tpm.policy.create", REST: "POST /api/v1/tpm/policies"},
	"tpmPolicy.get":            {GRPC: "TPMPolicyGet", MCP: "tpm.policy.get", REST: "GET /api/v1/tpm/policies/{name}"},
	"tpmPolicy.list":           {GRPC: "TPMPolicyList", MCP: "tpm.policy.list", REST: "GET /api/v1/tpm/policies"},
	"tpmPolicy.update":         {GRPC: "TPMPolicyUpdate", MCP: "tpm.policy.update", REST: "POST /api/v1/tpm/policies/{name}/update"},
	"tpmPolicy.revoke":         {GRPC: "TPMPolicyRevoke", MCP: "tpm.policy.revoke", REST: "POST /api/v1/tpm/policies/{name}/revoke"},
	"tpmPolicy.verify":         {GRPC: "TPMPolicyVerify", MCP: "tpm.policy.verify", REST: "POST /api/v1/tpm/policies/{name}/verify"},
	"tpmPolicy.delete":         {GRPC: "TPMPolicyDelete", MCP: "tpm.policy.delete", REST: "DELETE /api/v1/tpm/policies/{name}"},
	"tpmPolicy.objects":        {GRPC: "TPMPolicyObjects", MCP: "tpm.policy.objects", REST: "GET /api/v1/tpm/policies/{name}/objects"},
	"tpmPolicy.autoUnseal":     {GRPC: "TPMPolicySetAutoUnseal", MCP: "tpm.policy.autoUnseal", REST: "POST /api/v1/tpm/policies/{name}/auto-unseal"},
	"tpmPolicy.setDescription": {GRPC: "TPMPolicySetDescription", MCP: "tpm.policy.setDescription", REST: "POST /api/v1/tpm/policies/{name}/description"},
	"tpmPolicy.objectPolicy":   {GRPC: "TPMObjectPolicy", MCP: "tpm.object.policy", REST: "GET /api/v1/keys/{id}/tpm-policy"},
	"tpmPolicy.rotate":         {GRPC: "TPMPolicyRotateAuthority", MCP: "tpm.authority.rotate", REST: "POST /api/v1/tpm/authority/rotate"},
	"users.bindCert":           {GRPC: "BindUserCert", MCP: "user.bindCert", REST: "POST /api/v1/users/{username}/cert-bindings"},
	"users.create":             {GRPC: "CreateUser", MCP: "user.create", REST: "POST /api/v1/users/"},
	"users.delete":             {GRPC: "DeleteUser", MCP: "user.delete", REST: "DELETE /api/v1/users/{username}"},
	"users.get":                {GRPC: "GetUser", MCP: "user.get", REST: "GET /api/v1/users/{username}"},
	"users.list":               {GRPC: "ListUsers", MCP: "user.list", REST: "GET /api/v1/users/"},
	"users.listCredentials":    {GRPC: "ListUserCredentials", MCP: "user.listCredentials", REST: "GET /api/v1/users/{username}/credentials"},
	"users.disable":            {GRPC: "DisableUser", MCP: "user.disable", REST: "POST /api/v1/users/{username}/disable"},
	"users.enable":             {GRPC: "EnableUser", MCP: "user.enable", REST: "POST /api/v1/users/{username}/enable"},
}

// scan re-derives the three transports' wire tables from their own source,
// exactly as their own golden tests do.
func scan(t *testing.T) (grpcPerm, restPerm, mcpPerm map[string]string) {
	t.Helper()

	grpcSites, err := authzscan.Scan(grpcDir, grpcSeams)
	require.NoError(t, err, "scanning pkg/api/grpc for authorization gates must succeed")
	grpcPerm = make(map[string]string, len(grpcSites))
	for _, s := range grpcSites {
		grpcPerm[s.Key] = s.Pair()
	}

	restSites, err := authzscan.Scan(restDir, restSeams)
	require.NoError(t, err, "scanning pkg/api/rest for authorization gates must succeed")
	restPerm = make(map[string]string, len(restSites))
	for _, s := range restSites {
		restPerm[s.Key] = s.Pair()
	}

	mcpSites, err := authzscan.ScanMap(mcpDir, "methodPermissions")
	require.NoError(t, err, "scanning pkg/api/mcp's methodPermissions map must succeed")
	mcpPerm = make(map[string]string, len(mcpSites))
	for _, s := range mcpSites {
		mcpPerm[s.Key] = s.Pair()
	}

	return grpcPerm, restPerm, mcpPerm
}

// TestCapabilities_RequireSamePermissionOnEveryTransport is the cross-
// transport consistency golden go-xkms#1232 asks for: for every capability
// exposed on more than one transport, the required resource:action must be
// the same. A capability named in canonicalCapabilities that loses its entry
// on a transport, or whose entry there no longer matches, fails here even
// though each transport's own golden test is untouched.
func TestCapabilities_RequireSamePermissionOnEveryTransport(t *testing.T) {
	grpcPerm, restPerm, mcpPerm := scan(t)

	for name, cap := range canonicalCapabilities {
		type entry struct {
			transport, key, value string
		}
		var entries []entry

		if cap.GRPC != "" {
			v, ok := grpcPerm[cap.GRPC]
			require.True(t, ok, "capability %q: gRPC method %q has no authorization gate", name, cap.GRPC)
			entries = append(entries, entry{"gRPC", cap.GRPC, v})
		}
		if cap.MCP != "" {
			v, ok := mcpPerm[cap.MCP]
			require.True(t, ok, "capability %q: MCP method %q has no methodPermissions entry", name, cap.MCP)
			entries = append(entries, entry{"MCP", cap.MCP, v})
		}
		if cap.REST != "" {
			v, ok := restPerm[cap.REST]
			require.True(t, ok, "capability %q: REST route %q has no authorization gate", name, cap.REST)
			entries = append(entries, entry{"REST", cap.REST, v})
		}

		require.GreaterOrEqual(t, len(entries), 2, "capability %q names fewer than two transports; it belongs in a single-transport comment, not this table", name)

		want := entries[0].value
		for _, e := range entries[1:] {
			assert.Equal(t, want, e.value, "capability %q: %s %q requires %q but %s %q requires %q",
				name, entries[0].transport, entries[0].key, want, e.transport, e.key, e.value)
		}
	}
}

// TestCanonicalCapabilities_NoEmptyEntry proves every capability names at
// least two transports (see the require.GreaterOrEqual above); this test
// exists so a canonicalCapabilities entry with a typo'd, always-empty
// transport field fails with a clear message from a dedicated test rather
// than only as a side effect of the consistency check.
func TestCanonicalCapabilities_NoEmptyEntry(t *testing.T) {
	require.NotEmpty(t, canonicalCapabilities)
	for name, cap := range canonicalCapabilities {
		count := 0
		if cap.GRPC != "" {
			count++
		}
		if cap.MCP != "" {
			count++
		}
		if cap.REST != "" {
			count++
		}
		assert.GreaterOrEqual(t, count, 2, "capability %q names fewer than two transports", name)
	}
}
