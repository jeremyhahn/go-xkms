package buildgates

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// qrdbImplPrefix is go-qrdb's implementation tree. Production code reaches
// go-qrdb through its SDK (github.com/jeremyhahn/go-qrdb/sdk/go) only.
const qrdbImplPrefix = "github.com/jeremyhahn/go-qrdb/pkg/"

// qrdbImplImportAllowList names the implementation imports that stay until the
// go-qrdb SDK exports what the file uses. Each entry is a missing SDK export;
// drop the entry when the SDK tag that exports it is pinned.
var qrdbImplImportAllowList = map[string]map[string]string{
	"../../pkg/auth/node_users.go": {
		// BLOCKED: go-qrdb SDK export user.CertActivator,
		// user.ErrActivationUnsupported, user.AccountNotPendingError.
		"github.com/jeremyhahn/go-qrdb/pkg/user": "certificate-bound activation",
	},
	"../../pkg/xkms/servicer_invite.go": {
		// BLOCKED: go-qrdb SDK export user.AccountNotPendingError.
		"github.com/jeremyhahn/go-qrdb/pkg/user": "invitation redemption of a non-pending account",
	},
}

// TestProductionCodeImportsQrdbOnlyThroughSDK parses the files that bind
// qrdb tenants and users and fails on any go-qrdb implementation import the
// allow-list does not name.
func TestProductionCodeImportsQrdbOnlyThroughSDK(t *testing.T) {
	for _, path := range []string{
		"../../pkg/auth/node_users.go",
		"../../pkg/webauthn/qrdb_userstore.go",
		"../../pkg/xkms/servicer_invite.go",
	} {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, spec := range f.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: import %s: %v", path, spec.Path.Value, err)
			}
			if !strings.HasPrefix(imp, qrdbImplPrefix) {
				continue
			}
			if _, ok := qrdbImplImportAllowList[path][imp]; ok {
				continue
			}
			t.Errorf("%s imports %s; use the go-qrdb SDK (github.com/jeremyhahn/go-qrdb/sdk/go)", path, imp)
		}
	}
}
