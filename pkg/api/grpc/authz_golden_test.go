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

package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/authzscan"
)

// authzSeams are the authorization gates this package exposes.
//
//   - (*Service).authorize(ctx, resource, action, resourceID)
var authzSeams = []authzscan.Seam{
	{Method: "authorize", Args: 4, ResourceArg: 1, ActionArg: 2},
}

// goldenRPCPermissions is the complete, literal resource:action pair every
// authorized gRPC RPC requires, keyed by the method that holds the gate.
//
// The strings are spelled out here rather than built from the
// auth.Resource*/auth.Action* constants on purpose: this table is the wire
// contract go-qrdb decides against, so it must fail if a constant is retyped,
// repointed, or swapped for a different one. It is the gRPC counterpart of
// pkg/api/mcp's goldenMethodPermissions and pins the same vocabulary.
var goldenRPCPermissions = map[string]string{
	"AddCustodianMember":          "ceremony:enroll_custodian",
	"AttestKey":                   "keys:get",
	"BarrierDeleteRecoveryKeys":   "seal:generate_recovery",
	"BarrierEnableEncryption":     "seal:enable_encryption",
	"BarrierGenerateRecoveryKeys": "seal:generate_recovery",
	"BarrierGenerateRootToken":    "seal:rotate_root_key",
	"BarrierHasRecoveryKeys":      "seal:status",
	"BarrierInitialize":           "seal:bootstrap",
	"BarrierInitializeShamir":     "seal:initialize_shamir",
	"BarrierRecoverWithKeys":      "seal:recover_with_keys",
	"BarrierRekey":                "seal:rekey",
	"BarrierSeal":                 "seal:seal",
	"BarrierStatus":               "seal:status",
	"BarrierUnseal":               "seal:unseal",
	"BarrierUnsealShare":          "barrier:unseal-share",
	"BarrierUnsealShares":         "seal:unseal",
	"BindUserCert":                "users:update",
	"CanSeal":                     "keys:get",
	"CertExists":                  "certs:read",
	"ChangeSOPIN":                 "pin:write",
	"ChangeUserPIN":               "pin:write",
	"CopyKey":                     "keys:create",
	"CreateCustodianGroup":        "ceremony:enroll_custodian",
	"CreateTenant":                "tenants:create",
	"CreateUser":                  "users:create",
	"Decrypt":                     "keys:decrypt",
	"DeleteCert":                  "certs:revoke",
	"DeleteCustodianGroup":        "ceremony:revoke_custodian",
	"DeleteKey":                   "keys:delete",
	"DeletePIVCertificate":        "piv:delete",
	"DeleteShare":                 "barrier:unseal-share",
	"DeleteTenant":                "tenants:delete",
	"DeleteUser":                  "users:delete",
	"DeriveKey":                   "keys:derive",
	"DeriveKeyECDH":               "keys:derive",
	"DistributeShares":            "ceremony:claim_share_begin",
	"Encrypt":                     "keys:encrypt",
	"EncryptAsym":                 "keys:encrypt",
	"EnrollDevice":                "certs:generate",
	"ExportKey":                   "keys:export",
	"ExportKeyMaterial":           "keys:export",
	"ExportPIVCertificate":        "piv:read",
	"FrostAggregate":              "keys:sign",
	"FrostDeleteKey":              "keys:delete",
	"FrostGenerateKey":            "keys:create",
	"FrostGenerateNonces":         "keys:sign",
	"FrostGetKey":                 "keys:get",
	"FrostImportKey":              "keys:import",
	"FrostListKeys":               "keys:list",
	"FrostSignRound":              "keys:sign",
	"FrostVerify":                 "keys:verify",
	"GenerateCRL":                 "certs:read",
	"GenerateKey":                 "keys:create",
	"GeneratePIVCSR":              "piv:use",
	"GeneratePIVKey":              "piv:write",
	"GetBackendInfo":              "backends:read",
	"GetCABundle":                 "certs:read",
	"GetCACertificate":            "certs:read",
	"GetCert":                     "certs:read",
	"GetCertChain":                "certs:read",
	"GetCustodianGroup":           "ceremony:status",
	"GetImportParameters":         "keys:import",
	"GetKey":                      "keys:get",
	"GetLockoutStatus":            "pin:read",
	"GetPIVCertificate":           "piv:read",
	"GetShare":                    "ceremony:status",
	"GetShareCollectionStatus":    "ceremony:status",
	"GetTLSCertificate":           "certs:read",
	"GetTenant":                   "tenants:read",
	"GetUser":                     "users:read",
	"ImportKey":                   "keys:import",
	"ImportPIVCertificate":        "piv:write",
	"IsRevoked":                   "certs:read",
	"IssueAKCertificate":          "certs:generate",
	"IssueCertificate":            "certs:generate",
	"IssueEKCertificate":          "certs:generate",
	"ListBackends":                "backends:list",
	"ListCerts":                   "certs:list",
	"ListCustodianGroups":         "ceremony:status",
	"ListKeys":                    "keys:list",
	"ListPIVSlots":                "piv:read",
	"ListShares":                  "ceremony:status",
	"ListTenants":                 "tenants:list",
	"ListUserCredentials":         "users:read",
	"ListUsers":                   "users:list",
	"PasswordAdd":                 "passwords:write",
	"PasswordDelete":              "passwords:delete",
	"PasswordGenerate":            "passwords:generate",
	"PasswordGet":                 "passwords:read",
	"PasswordList":                "passwords:read",
	"PasswordStoreLock":           "passwords:lock",
	"PasswordStoreStatus":         "passwords:read",
	"PasswordStoreUnlock":         "passwords:unlock",
	"PasswordUpdate":              "passwords:write",
	// PKCS#11 remote-state RPCs persist a token's key/object state, so they gate
	// on the keys resource: writes for mutation, reads for retrieval/listing.
	"PKCS11StateDelete":      "keys:write",
	"PKCS11StateGet":         "keys:read",
	"PKCS11StateList":        "keys:read",
	"PKCS11StatePut":         "keys:write",
	"PKCS11StatePutIfAbsent": "keys:write",
	"PKCS11StateCAS":         "keys:write",
	"PKCS11StateCAD":         "keys:write",
	// The audit chain records who did what to the rest of this API, so
	// reading it carries its own permission rather than riding on keys:* or
	// users:*. There is no emit gate because there is no emit RPC.
	"QueryAudit":               "audit:read",
	"RemoveCustodianMember":    "ceremony:revoke_custodian",
	"ResetLockout":             "pin:write",
	"RevokeCertificate":        "certs:revoke",
	"RotateKey":                "keys:rotate",
	"SaveCert":                 "certs:generate",
	"SaveCertChain":            "certs:generate",
	"Seal":                     "keys:encrypt",
	"SetSOPIN":                 "pin:write",
	"SetUserPIN":               "pin:write",
	"Sign":                     "keys:sign",
	"SignCSR":                  "certs:generate",
	"SignTCGCSR":               "certs:generate",
	"StorePIVCertificate":      "piv:write",
	"SubmitShare":              "barrier:unseal-share",
	"TenantBarrierInit":        "tenant_barrier:init",
	"TenantBarrierStatus":      "tenant_barrier:status",
	"TenantBarrierUnseal":      "tenant_barrier:unseal",
	"Unseal":                   "keys:decrypt",
	"UnwrapKey":                "keys:unwrap",
	"UnwrapKeyByID":            "keys:unwrap",
	"UpdateTenantEntitlements": "tenants:update",
	"UpdateTenantQuotas":       "tenants:update",
	"Verify":                   "keys:verify",
	"VerifySOPIN":              "pin:read",
	"VerifyUserPIN":            "pin:read",
	"WrapKey":                  "keys:wrap",
	"WrapKeyByID":              "keys:wrap",
	"setUserEnabled":           "users:update",
	"SSHAddAuthorizedKey":      "ssh:write",
	"SSHAddKnownHost":          "ssh:write",
	"SSHDeleteKey":             "ssh:delete",
	"SSHExportPublic":          "ssh:read",
	"SSHGenerateKey":           "ssh:write",
	"SSHGetKey":                "ssh:read",
	"SSHImportKey":             "ssh:write",
	"SSHListAuthorizedKeys":    "ssh:read",
	"SSHListKeys":              "ssh:read",
	"SSHListKnownHosts":        "ssh:read",
	"SSHRemoveAuthorizedKey":   "ssh:delete",
	"SSHRemoveKnownHost":       "ssh:delete",
	"SSHSign":                  "ssh:write",
}

// TestRPCPermissions_MatchWireContract pins the resource:action pair of EVERY
// authorized RPC against the literal wire contract. The scan reads this
// package's own source, so a gate that is added, removed, or repointed fails
// here. The check runs in both directions and asserts the count, so neither a
// changed pair nor an added or dropped gate can slip through.
func TestRPCPermissions_MatchWireContract(t *testing.T) {
	sites, err := authzscan.Scan(".", authzSeams)
	require.NoError(t, err, "scanning this package for authorization gates must succeed")

	require.Len(t, sites, len(goldenRPCPermissions),
		"an authorization gate was added to or removed from this package without updating the wire contract")

	found := make(map[string]string, len(sites))
	for _, site := range sites {
		_, dup := found[site.Key]
		require.False(t, dup, "duplicate gate key %q at %s", site.Key, site.Pos)
		found[site.Key] = site.Pair()
	}

	for method, want := range goldenRPCPermissions {
		got, ok := found[method]
		require.True(t, ok, "method %q lost its authorization gate", method)
		assert.Equal(t, want, got, "method %q", method)
	}

	for method, got := range found {
		want, ok := goldenRPCPermissions[method]
		require.True(t, ok, "method %q gained an authorization gate without a wire-contract entry", method)
		assert.Equal(t, want, got, "method %q", method)
	}
}

// TestRPCPermissions_NoRawLiterals proves no gate in this package spells its
// resource or action as a string literal. authzscan.Scan returns a
// *authzscan.RawLiteralError the moment it sees one, so a successful scan is
// the proof. This is the regression guard: a literal that reappears here is a
// silent authorization change, because it stops matching the qrdb grant with
// no compile error.
func TestRPCPermissions_NoRawLiterals(t *testing.T) {
	sites, err := authzscan.Scan(".", authzSeams)
	require.NoError(t, err, "every gate must name a pkg/auth constant, never a string literal")
	require.NotEmpty(t, sites)
}
