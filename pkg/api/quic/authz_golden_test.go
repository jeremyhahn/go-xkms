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

package quic

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/authzscan"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// authzSeams are the authorization gates this package exposes.
//
//   - (*Server).authorize(w, r, resource, action)
//   - (*Server).authorizeCeremony(w, r, action), which pins the resource to the
//     first-boot ceremony.
var authzSeams = []authzscan.Seam{
	{Method: "authorize", Args: 4, ResourceArg: 2, ActionArg: 3},
	{Method: "authorizeCeremony", Args: 3, ResourceArg: -1, ActionArg: 2, FixedResource: "ResourceCeremony"},
}

// goldenHandlerPermissions is the complete, literal resource:action pair every
// authorized QUIC handler requires, keyed by the function that holds the gate.
// A function holding several gates is keyed with a "#N" suffix in call order.
//
// The strings are spelled out here rather than built from the
// auth.Resource*/auth.Action* constants on purpose: this table is the wire
// contract go-qrdb decides against, so it must fail if a constant is retyped,
// repointed, or swapped for a different one. It is the QUIC counterpart of
// pkg/api/mcp's goldenMethodPermissions and pins the same vocabulary.
//
// The two "<operationForMethod>" entries are the method-derived password-vault
// routes; the action they resolve to is pinned exhaustively by
// TestOperationForMethod_MatchWireContract below.
var goldenHandlerPermissions = map[string]string{
	"handleAsymmetricEncrypt":           "keys:encrypt",
	"handleAttestKey":                   "keys:get",
	"handleBackendOperations":           "backends:read",
	"handleBarrierDeleteRecoveryKeys":   "seal:generate_recovery",
	"handleBarrierEnableEncryption":     "seal:enable_encryption",
	"handleBarrierGenerateRecoveryKeys": "seal:generate_recovery",
	"handleBarrierGenerateRootToken":    "seal:rotate_root_key",
	"handleBarrierHasRecoveryKeys":      "seal:status",
	"handleBarrierInitialize":           "seal:bootstrap",
	"handleBarrierInitializeShamir":     "seal:initialize_shamir",
	"handleBarrierRecoverWithKeys":      "seal:recover_with_keys",
	"handleBarrierRekey":                "seal:rekey",
	"handleBarrierSeal":                 "seal:seal",
	"handleBarrierStatus":               "seal:status",
	"handleBarrierUnseal":               "seal:unseal",
	"handleBarrierUnsealShare":          "barrier:unseal-share",
	"handleBarrierUnsealShares":         "seal:unseal",
	"handleCanSeal":                     "keys:get",
	"handleCertExists":                  "certs:read",
	"handleChangeSOPIN":                 "pin:write",
	"handleChangeUserPIN":               "pin:write",
	"handleClaimCertBegin":              "ceremony:claim_cert",
	"handleClaimCertComplete":           "ceremony:claim_cert",
	"handleClaimShareBegin":             "ceremony:claim_share_begin",
	"handleClaimShareComplete":          "ceremony:claim_share_complete",
	"handleCopyKey":                     "keys:create",
	"handleCredentialStrategy":          "credentials:strategy",
	"handleCredentialSubmit":            "credentials:submit",
	"handleDecrypt":                     "keys:decrypt",
	"handleDeleteCert":                  "certs:revoke",
	"handleDeleteKey":                   "keys:delete",
	"handleDeletePIVCertificate":        "piv:delete",
	"handleDeleteShare":                 "barrier:unseal-share",
	"handleDeriveKeyECDH":               "keys:derive",
	"handleEncrypt":                     "keys:encrypt",
	"handleEnrollDevice":                "certs:generate",
	"handleExportKey":                   "keys:export",
	"handleExportKeyMaterial":           "keys:export",
	"handleFrostAggregate":              "keys:sign",
	"handleFrostDeleteKey":              "keys:delete",
	"handleFrostGenerateKey":            "keys:create",
	"handleFrostGenerateNonces":         "keys:sign",
	"handleFrostGetKey":                 "keys:get",
	"handleFrostImport":                 "keys:import",
	"handleFrostListKeys":               "keys:list",
	"handleFrostSignRound":              "keys:sign",
	"handleFrostVerify":                 "keys:verify",
	"handleGenerateCRL":                 "certs:read",
	"handleGenerateKey":                 "keys:create",
	"handleGetCABundle":                 "certs:read",
	"handleGetCACertificate":            "certs:read",
	"handleGetCert":                     "certs:read",
	"handleGetCertChain":                "certs:read",
	"handleGetImportParameters":         "keys:import",
	"handleGetImportParams":             "keys:import",
	"handleGetInitStatus":               "ceremony:status",
	"handleGetKey":                      "keys:get",
	"handleGetLockoutStatus":            "pin:read",
	"handleGetPIVCertificate":           "piv:read",
	"handleGetShare":                    "ceremony:status",
	"handleImportKey":                   "keys:import",
	"handleIsRevoked":                   "certs:read",
	"handleIssueAKCertificate":          "certs:generate",
	"handleIssueCertificate":            "certs:generate",
	"handleIssueEKCertificate":          "certs:generate",
	"handleListBackends":                "backends:list",
	"handleListCerts":                   "certs:list",
	"handleListKeys":                    "keys:list",
	"handleListShares":                  "ceremony:status",
	"handlePIVExportCertificate":        "piv:read",
	"handlePIVGenerateCSR":              "piv:use",
	"handlePIVGenerateKey":              "piv:write",
	"handlePIVImportCertificate":        "piv:write",
	"handlePIVSlots":                    "piv:read",
	"handleQueryAudit":                  "audit:read",
	"handleResetLockout":                "pin:write",
	"handleRevokeCertificate":           "certs:revoke",
	"handleRotateKey":                   "keys:rotate",
	"handleSSHAddAuthorized":            "ssh:write",
	"handleSSHAddKnownHost":             "ssh:write",
	"handleSSHDeleteKey":                "ssh:delete",
	"handleSSHEmit":                     "ssh:read",
	"handleSSHExportPublic":             "ssh:read",
	"handleSSHGenerate":                 "ssh:write",
	"handleSSHGetAuthorized":            "ssh:read",
	"handleSSHGetKey":                   "ssh:read",
	"handleSSHImport":                   "ssh:write",
	"handleSSHListAuthorized":           "ssh:read",
	"handleSSHListKeys":                 "ssh:read",
	"handleSSHListKnownHosts":           "ssh:read",
	"handleSSHRemoveAuthorized":         "ssh:delete",
	"handleSSHRemoveKnownHost":          "ssh:delete",
	"handleSSHSign":                     "ssh:write",
	"handleSSHVerifyAuthorized":         "ssh:read",
	"handleSSHVerifyKnownHost":          "ssh:read",
	"handleSaveCert":                    "certs:generate",
	"handleSaveCertChain":               "certs:generate",
	"handleSeal":                        "keys:encrypt",
	"handleSetSOPIN":                    "pin:write",
	"handleSetUserPIN":                  "pin:write",
	"handleShareCollectionStatus":       "ceremony:status",
	"handleSign":                        "keys:sign",
	"handleSignCSR":                     "certs:generate",
	"handleSignCSRInit":                 "ceremony:sign_csr",
	"handleSignTCGCSR":                  "certs:generate",
	"handleStorePIVCertificate":         "piv:write",
	"handleSubmitShare":                 "barrier:unseal-share",
	"handleTLSCertificate":              "certs:read",
	"handleUnseal":                      "keys:decrypt",
	"handleUnwrapKey":                   "keys:unwrap",
	"handleUnwrapKeyByID":               "keys:unwrap",
	"handleVerify":                      "keys:verify",
	"handleVerifySOPIN":                 "pin:read",
	"handleVerifyUserPIN":               "pin:read",
	"handleWrapKey":                     "keys:wrap",
	"handleWrapKeyByID":                 "keys:wrap",
	"setupPasswordRoutes#0":             "passwords:<operationForMethod>",
	"setupPasswordRoutes#1":             "passwords:unlock",
	"setupPasswordRoutes#2":             "passwords:lock",
	"setupPasswordRoutes#3":             "passwords:read",
	"setupPasswordRoutes#4":             "passwords:generate",
	"setupPasswordRoutes#5":             "passwords:<operationForMethod>",
	// The PKCS#11 state routes share one authorize call in a helper closure
	// whose action is a per-route parameter, so the scanner records the pair as
	// keys:<action> — the same dynamic-action shape as the password vault's
	// <operationForMethod> entries above. The concrete per-endpoint actions
	// (put/put-if-absent/delete = write, get/list = read) are literals at each
	// call site in setupPKCS11StateRoutes.
	"setupPKCS11StateRoutes": "keys:<action>",
}

// TestHandlerPermissions_MatchWireContract pins the resource:action pair of
// EVERY authorized handler against the literal wire contract. The scan reads
// this package's own source — including the build-tagged FROST handlers — so a
// gate that is added, removed, or repointed fails here. The check runs in both
// directions and asserts the count, so neither a changed pair nor an added or
// dropped gate can slip through.
func TestHandlerPermissions_MatchWireContract(t *testing.T) {
	sites, err := authzscan.Scan(".", authzSeams)
	require.NoError(t, err, "scanning this package for authorization gates must succeed")

	require.Len(t, sites, len(goldenHandlerPermissions),
		"an authorization gate was added to or removed from this package without updating the wire contract")

	found := make(map[string]string, len(sites))
	for _, site := range sites {
		_, dup := found[site.Key]
		require.False(t, dup, "duplicate gate key %q at %s", site.Key, site.Pos)
		found[site.Key] = site.Pair()
	}

	for handler, want := range goldenHandlerPermissions {
		got, ok := found[handler]
		require.True(t, ok, "handler %q lost its authorization gate", handler)
		assert.Equal(t, want, got, "handler %q", handler)
	}

	for handler, got := range found {
		want, ok := goldenHandlerPermissions[handler]
		require.True(t, ok, "handler %q gained an authorization gate without a wire-contract entry", handler)
		assert.Equal(t, want, got, "handler %q", handler)
	}
}

// TestHandlerPermissions_NoRawLiterals proves no gate in this package spells
// its resource or action as a string literal. authzscan.Scan returns a
// *authzscan.RawLiteralError the moment it sees one, so a successful scan is
// the proof. This is the regression guard: a literal that reappears here is a
// silent authorization change, because it stops matching the qrdb grant with
// no compile error.
func TestHandlerPermissions_NoRawLiterals(t *testing.T) {
	sites, err := authzscan.Scan(".", authzSeams)
	require.NoError(t, err, "every gate must name a pkg/auth constant, never a string literal")
	require.NotEmpty(t, sites)
}

// TestOperationForMethod_MatchWireContract pins the wire values behind the two
// "<operationForMethod>" entries in the golden table. TestOperationForMethod
// already covers the HTTP-method mapping itself; this asserts the part the
// golden table depends on — that the helper returns the canonical pkg/auth
// constants, and that no verb can reach an action outside read/write/delete.
func TestOperationForMethod_MatchWireContract(t *testing.T) {
	assert.Equal(t, auth.ActionRead, operationForMethod(http.MethodGet))
	assert.Equal(t, auth.ActionWrite, operationForMethod(http.MethodPost))
	assert.Equal(t, auth.ActionDelete, operationForMethod(http.MethodDelete))

	// An unrecognized verb must fall back to the least-privileged action.
	assert.Equal(t, auth.ActionRead, operationForMethod("BREW"))
	assert.Equal(t, auth.ActionRead, operationForMethod(""))

	allowed := map[string]struct{}{
		auth.ActionRead: {}, auth.ActionWrite: {}, auth.ActionDelete: {},
	}
	for method, action := range methodActions {
		_, ok := allowed[action]
		assert.True(t, ok, "method %q maps to unexpected action %q", method, action)
	}
}
