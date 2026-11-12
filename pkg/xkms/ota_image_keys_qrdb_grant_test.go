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
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// otaQrdbPermissions are the OTA permissions the ota-image-keys row takes
// from go-qrdb's vocabulary (docs/SPEC.md, ota-image-keys). go-qrdb
// registers both and grants them to the Admin built-in role
// (pkg/permission/builtin_role_grants.go, registerAdminGrants).
var otaQrdbPermissions = []string{"ota:activate", "ota:confirm"}

// TestOTAImageKeys_QrdbGrantsOTAPermissionsToAdmin pins the go-qrdb
// registration the row depends on: a qrdb bump that drops either grant
// fails here.
func TestOTAImageKeys_QrdbGrantsOTAPermissionsToAdmin(t *testing.T) {
	for _, raw := range otaQrdbPermissions {
		p, err := qrdbsdk.ParsePermission(raw)
		if err != nil {
			t.Fatalf("ParsePermission(%q): %v", raw, err)
		}
		if !qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAdmin, p) {
			t.Errorf("go-qrdb does not grant %q to the %s role", raw, qrdbsdk.PermissionRoleAdmin)
		}
		for _, role := range []string{
			qrdbsdk.PermissionRoleOperator,
			qrdbsdk.PermissionRoleUser,
			qrdbsdk.PermissionRoleAuditor,
		} {
			if qrdbsdk.HasPermissionRoleGrant(role, p) {
				t.Errorf("go-qrdb grants %q to the non-admin %s role", raw, role)
			}
		}
	}
}

// TestOTAImageKeys_AuthDeclaresNoOTAVocabulary asserts that go-xkms's one
// authorization vocabulary (pkg/auth/permissions.go) declares no OTA
// resource, action or role of its own: the OTA permissions are go-qrdb's.
func TestOTAImageKeys_AuthDeclaresNoOTAVocabulary(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "../auth/permissions.go", nil, 0)
	if err != nil {
		t.Fatalf("parse pkg/auth/permissions.go: %v", err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.ValueSpec:
			for _, name := range v.Names {
				// Case-sensitive: "Rotate" is not an OTA name.
				if strings.Contains(name.Name, "OTA") {
					t.Errorf("pkg/auth declares %s; OTA permissions come from go-qrdb", name.Name)
				}
			}
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			s, uerr := strconv.Unquote(v.Value)
			if uerr != nil {
				return true
			}
			if s == "ota" || strings.HasPrefix(s, "ota:") {
				t.Errorf("pkg/auth declares the string %q; OTA permissions come from go-qrdb", s)
			}
		}
		return true
	})
}
