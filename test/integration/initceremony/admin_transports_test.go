// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration && initceremony

package initceremony

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// initAdmin is the administrator `xkmsd init` issued: its credential files
// and the username its certificate names.
type initAdmin struct {
	certPath string
	keyPath  string
	username string
}

// loadInitAdmin reads the admin credential init wrote to dataDir.
func loadInitAdmin(t *testing.T, dataDir string) initAdmin {
	t.Helper()
	admin := initAdmin{
		certPath: filepath.Join(dataDir, "admin-cert.pem"),
		keyPath:  filepath.Join(dataDir, "admin-key.pem"),
	}
	certPEM, err := os.ReadFile(admin.certPath)
	if err != nil {
		t.Fatalf("read admin certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("admin certificate %s holds no PEM block", admin.certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse admin certificate: %v", err)
	}
	admin.username = cert.Subject.CommonName
	return admin
}

// adminTarget is one protocol xkmsd serves, as the SDK and xkmsctl reach it.
type adminTarget struct {
	protocol xkms.Protocol
	// address is the SDK BackendConfig.Address.
	address string
	// server is the xkmsctl --server URL.
	server string
}

// adminTargets lists every client protocol writeMinimalConfig enables. The
// listeners are IPv4, so the targets name 127.0.0.1 rather than localhost,
// which resolves to ::1 first.
func adminTargets(ports nodePorts) []adminTarget {
	rest := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.rest))
	grpc := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.grpc))
	mcp := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.mcp))
	return []adminTarget{
		{protocol: xkms.ProtocolREST, address: "https://" + rest, server: "https://" + rest},
		{protocol: xkms.ProtocolGRPC, address: grpc, server: "grpcs://" + grpc},
		{protocol: xkms.ProtocolQUIC, address: rest, server: "quic://" + rest},
		{protocol: xkms.ProtocolMCP, address: mcp, server: "mcps://" + mcp},
		{protocol: xkms.ProtocolUnix, address: ports.unixSocket, server: "unix://" + ports.unixSocket},
	}
}

// adminOnlyPermission is the permission the user listing needs; the system
// admin role holds it and an ordinary user does not.
const adminOnlyPermission = "users:list"

// listedUser is the part of a listed user account the assertions read.
type listedUser struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

// assertAdminOnEveryTransport proves the init-issued admin credential
// authenticates, through the Go SDK and through the xkmsctl binary, on every
// protocol the running xkmsd serves, and that the same protocol refuses a
// caller that presents no certificate (#794).
func assertAdminOnEveryTransport(t *testing.T, xkmsctlBin string, proc *xkmsdProcess, ports nodePorts, admin initAdmin) {
	t.Helper()
	for _, target := range adminTargets(ports) {
		t.Run(string(target.protocol), func(t *testing.T) {
			t.Run("sdk", func(t *testing.T) {
				assertListsAdmin(t, sdkListUsers(t, target, proc.spkiPin, admin), admin)
			})
			t.Run("sdk_refuses_anonymous", func(t *testing.T) {
				assertSDKRefusesAnonymous(t, target, proc.spkiPin)
			})
			t.Run("xkmsctl", func(t *testing.T) {
				assertListsAdmin(t, xkmsctlListUsers(t, xkmsctlBin, target, proc.spkiPin, admin), admin)
			})
		})
	}
}

// newSDKClient connects a Go SDK client to target, pinning the server's
// SPKI, and presenting admin's certificate when admin is non-nil.
func newSDKClient(t *testing.T, ctx context.Context, target adminTarget, spkiPin string, admin *initAdmin) (xkms.Client, error) {
	t.Helper()
	cfg := &xkms.BackendConfig{
		Protocol:   target.protocol,
		Address:    target.address,
		TLSEnabled: true,
		SPKIPin:    spkiPin,
	}
	if admin != nil {
		cfg.TLSCertFile = admin.certPath
		cfg.TLSKeyFile = admin.keyPath
	}
	client, err := xkms.New(cfg)
	if err != nil {
		t.Fatalf("new %s SDK client: %v", target.protocol, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, client.Connect(ctx)
}

// sdkListUsers lists the user accounts through the Go SDK as admin.
func sdkListUsers(t *testing.T, target adminTarget, spkiPin string, admin initAdmin) []listedUser {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := newSDKClient(t, ctx, target, spkiPin, &admin)
	if err != nil {
		t.Fatalf("connect %s as the init admin: %v", target.protocol, err)
	}
	resp, err := client.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users over %s as the init admin: %v", target.protocol, err)
	}
	users := make([]listedUser, 0, len(resp.Users))
	for _, u := range resp.Users {
		users = append(users, listedUser{Username: u.Username, Roles: u.Roles})
	}
	return users
}

// assertSDKRefusesAnonymous proves target authenticates its callers: the same
// read without a client certificate must fail.
func assertSDKRefusesAnonymous(t *testing.T, target adminTarget, spkiPin string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := newSDKClient(t, ctx, target, spkiPin, nil)
	if err != nil {
		return
	}
	if _, err := client.ListUsers(ctx); err == nil {
		t.Fatalf("list users over %s without a client certificate succeeded; want it refused", target.protocol)
	}
}

// xkmsctlListUsers runs `xkmsctl user list` against target as admin and
// decodes its JSON output.
func xkmsctlListUsers(t *testing.T, bin string, target adminTarget, spkiPin string, admin initAdmin) []listedUser {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A fresh HOME and working directory keep the operator's ~/.xkms.yaml and
	// the relative default key directory out of the run.
	home := t.TempDir()
	cmd := exec.CommandContext(ctx, bin,
		"--transport", string(target.protocol),
		"--server", target.server,
		"--tls-cert", admin.certPath,
		"--tls-key", admin.keyPath,
		"--spki-pin", spkiPin,
		"--output", "json",
		"user", "list",
	)
	cmd.Dir = home
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stderr = &testLogWriter{t: t, prefix: "xkmsctl: "}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("xkmsctl user list over %s as the init admin: %v\n%s", target.protocol, err, out)
	}

	var listed struct {
		Users []listedUser `json:"users"`
	}
	if err := json.Unmarshal(out, &listed); err != nil {
		t.Fatalf("decode xkmsctl user list output over %s: %v\n%s", target.protocol, err, out)
	}
	return listed.Users
}

// assertListsAdmin proves the listing names the init admin with the admin
// role. Listing users is an administrator read, so the listing itself shows
// the server authenticated and authorized the caller as an administrator.
func assertListsAdmin(t *testing.T, users []listedUser, admin initAdmin) {
	t.Helper()
	for _, u := range users {
		if u.Username == admin.username && slices.Contains(u.Roles, qrdbsdk.RoleNameAdmin) {
			return
		}
	}
	t.Fatalf("user listing %+v has no %q with role %q", users, admin.username, qrdbsdk.RoleNameAdmin)
}
