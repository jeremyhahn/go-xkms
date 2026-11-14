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
	"AttestKey":             "keys:get",
	"BindUserCert":          "users:update",
	"BootstrapListenerKeys": "bootstrap:read",
	"CanSeal":               "keys:get",
	"CertExists":            "certs:read",
	"ChangeSOPIN":           "pin:write",
	"ChangeUserPIN":         "pin:write",
	"CopyKey":               "keys:create",
	"CreateTenant":          "tenants:create",
	"CreateUser":            "users:create",
	"Decrypt":               "keys:decrypt",
	"DeleteCert":            "certs:revoke",
	"DeleteKey":             "keys:delete",
	"DeletePIVCertificate":  "piv:delete",
	"DeleteTenant":          "tenants:delete",
	"DeleteUser":            "users:delete",
	"DeriveKey":             "keys:derive",
	"DeriveKeyECDH":         "keys:derive",
	"Encrypt":               "keys:encrypt",
	"EncryptAsym":           "keys:encrypt",

	// Crypto utility operations
	"Rewrap":                     "keys:decrypt",
	"EncryptBatch":               "keys:encrypt",
	"DecryptBatch":               "keys:decrypt",
	"GenerateDataKey":            "keys:encrypt",
	"GenerateWrappedDataKey":     "keys:encrypt",
	"GenerateHMAC":               "keys:sign",
	"VerifyHMAC":                 "keys:verify",
	"GenerateRandom":             "keys:verify",
	"Hash":                       "keys:verify",
	"GetPublicKey":               "keys:get",
	"RevokeKey":                  "keys:delete",
	"UpdateKeyStatus":            "keys:rotate",
	"GetKeyMetadata":             "keys:get",
	"UpdateKeyMetadata":          "keys:rotate",
	"SetKeyPolicy":               "keys:rotate",
	"GetKeyPolicy":               "keys:get",
	"DeleteKeyPolicy":            "keys:delete",
	"SetKeyRotationPolicy":       "keys:rotate",
	"GetKeyRotationPolicy":       "keys:get",
	"DeleteKeyRotationPolicy":    "keys:delete",
	"GetSupportedAlgorithms":     "keys:list",
	"BackendStatus":              "backends:read",
	"BackendTest":                "backends:read",
	"SetKeySafety":               "keys:rotate",
	"ClearKeySafety":             "keys:rotate",
	"SafetyCheck":                "keys:get",
	"SafetyReport":               "keys:get",
	"EnrollDevice":               "certs:issue",
	"ExportKey":                  "keys:export",
	"ExportKeyMaterial":          "keys:export",
	"ExportPIVCertificate":       "piv:read",
	"FrostAggregate":             "keys:sign",
	"FrostDeleteKey":             "keys:delete",
	"FrostGenerateKey":           "keys:create",
	"FrostGenerateNonces":        "keys:sign",
	"FrostGetKey":                "keys:get",
	"FrostImportKey":             "keys:import",
	"FrostListKeys":              "keys:list",
	"FrostSignRound":             "keys:sign",
	"FrostVerify":                "keys:verify",
	"GenerateCRL":                "certs:read",
	"GenerateKey":                "keys:create",
	"GeneratePIVCSR":             "piv:use",
	"GeneratePIVKey":             "piv:write",
	"GetBackendInfo":             "backends:read",
	"GetCABundle":                "certs:read",
	"GetCACertificate":           "certs:read",
	"GetCert":                    "certs:read",
	"GetCertChain":               "certs:read",
	"GetImportParameters":        "keys:import",
	"GetKey":                     "keys:get",
	"GetLockoutStatus":           "pin:read",
	"GetPIVCertificate":          "piv:read",
	"GetTLSCertificate":          "certs:read",
	"GetTenant":                  "tenants:read",
	"GetUser":                    "users:read",
	"ImportKey":                  "keys:import",
	"ImportPIVCertificate":       "piv:write",
	"IsRevoked":                  "certs:read",
	"IssueAKCertificate":         "certs:issue",
	"IssueCertificate":           "certs:issue",
	"IssueEKCertificate":         "certs:issue",
	"IssueLAKCertificate":        "certs:issue",
	"ListBackends":               "backends:list",
	"ListCerts":                  "certs:list",
	"ListKeys":                   "keys:list",
	"ListPIVSlots":               "piv:read",
	"ListTenants":                "tenants:list",
	"ListUserCredentials":        "users:read",
	"ListUsers":                  "users:list",
	"PasswordAdd":                "passwords:write",
	"PasswordDelete":             "passwords:delete",
	"PasswordGenerate":           "passwords:generate",
	"PasswordGet":                "passwords:read",
	"PasswordList":               "passwords:read",
	"PasswordStoreLock":          "passwords:lock",
	"PasswordStoreSetAccessMode": "passwords:write",
	"PasswordStoreStatus":        "passwords:read",
	"PasswordStoreUnlock":        "passwords:unlock",
	"PasswordUpdate":             "passwords:write",
	"PasswordVaultEnroll":        "passwords:unlock",
	"PasswordVaultRecover":       "passwords:unlock",
	"PasswordVaultRemoveFactor":  "passwords:unlock",
	"PasswordVaultRotate":        "passwords:unlock",
	"PasswordVaultStatus":        "passwords:read",
	// TPM policy management (pkg/tpmpolicy) -- pkg/auth.ResourceTPMPolicy,
	// a resource family go-qrdb's canonical registry does not declare
	// upstream; xkms owns it and scopes it in
	// pkg/apimodule/module_scopes.go.
	"TPMPolicyCreate":          "tpm_policy:create",
	"TPMPolicyGet":             "tpm_policy:get",
	"TPMPolicyList":            "tpm_policy:list",
	"TPMPolicyUpdate":          "tpm_policy:update",
	"TPMPolicyRevoke":          "tpm_policy:revoke",
	"TPMPolicyVerify":          "tpm_policy:verify",
	"TPMPolicyDelete":          "tpm_policy:delete",
	"TPMPolicyObjects":         "tpm_policy:get",
	"TPMPolicySetAutoUnseal":   "tpm_policy:update",
	"TPMPolicySetDescription":  "tpm_policy:update",
	"TPMObjectPolicy":          "tpm_policy:get",
	"TPMPolicyRotateAuthority": "tpm_policy:rotate",
	// Server-side OIDC credentials (pkg/oidc/credential) --
	// pkg/auth.ResourceOIDCCredentials, an xkms-owned resource family. A
	// login change (import, refresh, device login) is an update; reading a
	// current access token is its own action, token.
	"OIDCCredentialCreate":         "oidc_credentials:create",
	"OIDCCredentialImport":         "oidc_credentials:update",
	"OIDCCredentialGet":            "oidc_credentials:get",
	"OIDCCredentialList":           "oidc_credentials:list",
	"OIDCCredentialDelete":         "oidc_credentials:delete",
	"OIDCCredentialRefresh":        "oidc_credentials:update",
	"OIDCCredentialGetAccessToken": "oidc_credentials:token",
	"OIDCCredentialDeviceStart":    "oidc_credentials:update",
	"OIDCCredentialDevicePoll":     "oidc_credentials:update",

	// Attestation Verifier (go-xkms#1608) -- the trust anchors, signed
	// CoRIM reference values and quote appraisal of pkg/attestation/appraisal.
	"PutAttestationEndorsement":        "attestation_endorsements:create",
	"ListAttestationEndorsements":      "attestation_endorsements:list",
	"DeleteAttestationEndorsement":     "attestation_endorsements:delete",
	"PutAttestationReferenceValues":    "attestation_reference_values:create",
	"GetAttestationReferenceValues":    "attestation_reference_values:get",
	"ListAttestationReferenceValues":   "attestation_reference_values:list",
	"DeleteAttestationReferenceValues": "attestation_reference_values:delete",
	"AppraiseAttestationQuote":         "attestation_verifier:verify",

	// Repository signing keys (go-xkms#1697) --
	// pkg/auth.ResourceAttestationSigningKeys, an xkms-owned resource family.
	// Changing a binding is bind; reading one or resolving a repository's
	// key is get.
	"SetSigningKeyBinding":     "attestation_signing_keys:bind",
	"GetSigningKeyBinding":     "attestation_signing_keys:get",
	"ListSigningKeyBindings":   "attestation_signing_keys:list",
	"DeleteSigningKeyBinding":  "attestation_signing_keys:bind",
	"ResolveSigningKey":        "attestation_signing_keys:get",
	"SignCoRIM":                "attestation_signing_keys:sign",
	"SignImage":                "attestation_signing_keys:sign",
	"PeerAttestationChallenge": "peer_attestation:challenge",
	"SubmitPeerAttestation":    "peer_attestation:submit",
	// A tenant's TPM mode and vTPM (system scope only; tenants:set_tpm_mode
	// is a cross-tenant permission xkms declares).
	"GetTenantTPMMode": "tenants:read",
	"SetTenantTPMMode": "tenants:set_tpm_mode",
	"TenantVTPMStatus": "tenants:read",
	"TenantVTPMStart":  "tenants:set_tpm_mode",
	"TenantVTPMStop":   "tenants:set_tpm_mode",
	// The platform trust-root store (pkg/attestation/truststore) --
	// pkg/auth.ResourceTrustRoots, an xkms-owned, system-scope family.
	// Quarantine reclassifies a root, so it is an update.
	"TrustRootList":       "trust_roots:list",
	"TrustRootGet":        "trust_roots:get",
	"TrustRootImport":     "trust_roots:import",
	"TrustRootQuarantine": "trust_roots:update",
	"TrustRootRemove":     "trust_roots:delete",
	// CA transparency log reads (docs/transparency-log).
	"GetTransparencyLogHead":             "vlog:head",
	"GetTransparencyLogEntry":            "vlog:get",
	"GetTransparencyLogInclusionProof":   "vlog:proof",
	"GetTransparencyLogConsistencyProof": "vlog:proof",
	"AppendTransparencyLogExternal":      "vlog:append",
	// PKCS#11 remote-state RPCs persist a token's key/object state, so they
	// gate on the keys resource with the same per-verb CRUD actions REST's
	// /api/v1/pkcs11state/* routes carry (go-xkms#1249): create for the two
	// unconditional/conditional puts, update for the compare-and-swap,
	// delete for both the guarded and unguarded deletes, get/list for the
	// two reads.
	"PKCS11StateDelete":      "keys:delete",
	"PKCS11StateGet":         "keys:get",
	"PKCS11StateList":        "keys:list",
	"PKCS11StatePut":         "keys:create",
	"PKCS11StatePutIfAbsent": "keys:create",
	"PKCS11StateCAS":         "keys:update",
	"PKCS11StateCAD":         "keys:delete",
	// The platform-sealed store persists key-protection material sealed to
	// the host's hardware, so it gates on the same keys resource and the
	// same per-verb model as the PKCS#11 remote-state RPCs above: Put stores
	// a new value under a name (create, matching PKCS11StatePut), Reseal
	// re-wraps an existing value in place without changing it (update), and
	// Status reports store-wide state the same way Get reports one secret's.
	"SealStorePut":    "keys:create",
	"SealStoreGet":    "keys:get",
	"SealStoreDelete": "keys:delete",
	"SealStoreList":   "keys:list",
	"SealStoreReseal": "keys:update",
	"SealStoreStatus": "keys:get",
	// The audit chain records who did what to the rest of this API, so
	// reading it carries its own permission rather than riding on keys:* or
	// users:*. There is no emit gate because there is no emit RPC.
	// Whole-node backup/restore — service_backup.go (owner ruling
	// 2026-09-30, go-xkms#728). Mirrors go-qrdb's own backup:* permission
	// family verbatim; restore is gated separately because it overwrites
	// live shard state.
	"ResetLockout":             "pin:write",
	"RevokeCertificate":        "certs:revoke",
	"RotateKey":                "keys:rotate",
	"CreateOTAImageKey":        "keys:create",
	"RotateOTAImageKey":        "keys:rotate",
	"SignOTAImage":             "keys:sign",
	"ExportOTAImageKey":        "keys:get",
	"ListKeyVersions":          "keys:list",
	"EnableKeyVersion":         "keys:rotate",
	"DisableKeyVersion":        "keys:rotate",
	"RetireKeyVersion":         "keys:delete",
	"EnableAllKeyVersions":     "keys:rotate",
	"DisableAllKeyVersions":    "keys:rotate",
	"RotateScopeKeys":          "keys:rotate",
	"SaveCert":                 "certs:enroll",
	"SaveCertChain":            "certs:enroll",
	"Seal":                     "keys:encrypt",
	"SetSOPIN":                 "pin:write",
	"SetUserPIN":               "pin:write",
	"Sign":                     "keys:sign",
	"SignCSR":                  "certs:issue",
	"SignTCGCSR":               "certs:issue",
	"StorePIVCertificate":      "piv:write",
	"Unseal":                   "keys:decrypt",
	"UnwrapKey":                "keys:unwrap",
	"UnwrapKeyByID":            "keys:unwrap",
	"UpdateTenantEntitlements": "tenants:set_entitlements",
	"UpdateTenantQuotas":       "tenants:set_quotas",
	"Verify":                   "keys:verify",
	"VerifySOPIN":              "pin:read",
	"VerifyUserPIN":            "pin:read",
	"WrapKey":                  "keys:wrap",
	"WrapKeyByID":              "keys:wrap",
	"EnableUser":               "users:enable",
	"DisableUser":              "users:disable",
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
