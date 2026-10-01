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

//go:build integration

// Package oidccredentials is the end-to-end suite of server-side OIDC
// credentials. TestMain starts a real xkmsd through the shared xkmsdtest
// harness, serving every network transport (Unix gRPC, REST, gRPC, QUIC,
// MCP) over TLS with a passphrase barrier initialized through the pre-boot
// sealed-window listener, and the tests drive the real xkey and xkmsctl
// binaries against it. The lease-contention test runs credential services
// over a real raft qrdb node. Run it in the devcontainer:
// make integration-test-oidc-credentials.
package oidccredentials

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/xkmsdtest"
)

// env is the running xkmsd and the binaries driven against it.
var env struct {
	xkey      string
	xkmsctl   string
	caFile    string
	urls      map[string]string
	adminCert string
	adminKey  string
	token     string
	// admin is an HTTPS client presenting the admin credential.
	admin *http.Client
}

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "oidc credentials integration:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// run sets the suite up, runs it, and tears the server down.
func run(m *testing.M) (code int, err error) {
	work, err := os.MkdirTemp("", "oidc-credentials-it-")
	if err != nil {
		return 0, err
	}
	defer func() {
		if rmErr := os.RemoveAll(work); rmErr != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", rmErr)
		}
	}()

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		return 0, err
	}
	bin := filepath.Join(work, "bin")
	xkmsd := filepath.Join(bin, "xkmsd")
	env.xkmsctl = filepath.Join(bin, "xkmsctl")
	env.xkey = filepath.Join(bin, "xkey")
	const tags = "codec_cbor codec_json codec_msgpack"
	for _, b := range []struct{ dir, tags, out, pkg string }{
		{root, tags, xkmsd, "./cmd/xkmsd"},
		{root, tags, env.xkmsctl, "./cmd/xkmsctl"},
		// pkcs11: the login test holds its PIV key on a SoftHSM token.
		{filepath.Join(root, "xkey"), tags + " pkcs11", env.xkey, "./cmd/xkey"},
	} {
		if err := xkmsdtest.Build(b.dir, b.tags, b.out, b.pkg); err != nil {
			return 0, err
		}
	}

	server, err := xkmsdtest.Start(xkmsd, filepath.Join(work, "xkmsd"), xkmsdtest.WithAllTransports())
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := server.Close(); closeErr != nil {
			fmt.Fprintln(os.Stderr, "stop xkmsd:", closeErr)
		}
	}()
	env.caFile, env.urls = server.CAFile, server.URLs
	env.adminCert, env.adminKey = server.AdminCert, server.AdminKey
	if err := authBootstrap(server); err != nil {
		return 0, &xkmsdtest.StepError{Step: "authenticate as the first-boot admin", Err: err, Log: server.LogTail(40)}
	}

	code = m.Run()
	if code != 0 {
		fmt.Fprintln(os.Stderr, "xkmsd log tail:\n"+server.LogTail(60))
	}
	return code, nil
}

// xkmsctl runs xkmsctl against transport's URL as the first-boot admin.
func xkmsctl(transport string, args ...string) (string, error) {
	full := append([]string{"--server", env.urls[transport], "--tls-ca", env.caFile,
		"--tls-cert", env.adminCert, "--tls-key", env.adminKey}, args...)
	cmd := exec.Command(env.xkmsctl, full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// xkey runs xkey with XKMSD_URL set to transport's URL (empty transport: no
// xkmsd, xkey's local backend) and an isolated home.
func xkey(t *testing.T, transport, stdin string, args ...string) (string, error) {
	t.Helper()
	home := t.TempDir()
	vars := append(xkeyHome(home),
		"XKMSD_TLS_CA="+env.caFile,
		"XKMSD_TOKEN="+env.token,
		"XKMSD_TLS_CERT="+env.adminCert,
		"XKMSD_TLS_KEY="+env.adminKey,
	)
	if transport != "" {
		vars = append(vars, "XKMSD_URL="+env.urls[transport])
	} else {
		vars = append(vars, "XKMSD_URL=")
	}
	return runXKey(vars, stdin, args...)
}

// xkeyHome is the environment that makes home xkey's whole home.
func xkeyHome(home string) []string {
	return []string{"HOME=" + home, "XKEY_HOME=" + home, "XKEY_DATA_DIR=" + filepath.Join(home, "data")}
}

// runXKey runs xkey with vars added to the environment.
func runXKey(vars []string, stdin string, args ...string) (string, error) {
	cmd := exec.Command(env.xkey, args...)
	cmd.Env = append(os.Environ(), vars...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
