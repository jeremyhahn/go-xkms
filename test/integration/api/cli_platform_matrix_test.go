//go:build integration

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

package integration

// The ordered workflows of the CLI matrix (#2321 slice e): platform,
// cluster/rebalance and bootstrap. Each (family, transport) cell runs its
// commands in definition order with their setup, or skips each command with
// the reason commands.MatrixSkipReason names.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/test/integration/api/commands"
)

// oneNodeReason is why add, remove and execute skip on a one-node cluster.
const oneNodeReason = "one-node cluster: no second replica to add, remove or move shards to"

// spareReplicaEnv names a replica (id@host:port) a multi-node cluster test
// may remove and add back.
const spareReplicaEnv = "XKMS_TEST_CLUSTER_SPARE_REPLICA"

// cellStep returns the overrides for one command of a workflow cell, or a
// non-empty skip reason decided at run time.
type cellStep func(t *testing.T, cmd commands.CommandDefinition) (map[string]string, string)

// runWorkflowCell runs the commands of family on protocol in order. A
// command that fails stops the cell: every later one depends on it.
func runWorkflowCell(t *testing.T, runner *commands.TestRunner, protocol commands.ProtocolType,
	family commands.CommandCategory, step cellStep, check func(*testing.T, *commands.TestResult)) {
	t.Helper()
	tags := enabledBuildTags()
	available := protocol == commands.ProtocolEmbedded || isProtocolAvailable(t, runner, protocol)
	for _, cmd := range commands.CommandsByCategory(family) {
		ok := t.Run(cmd.Name, func(t *testing.T) {
			if reason, skip := commands.MatrixSkipReason(cmd, protocol, tags); skip {
				t.Skipf("(%s, %s): %s", family, protocol, reason)
			}
			if !available {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}
			overrides, reason := step(t, cmd)
			if reason != "" {
				t.Skipf("(%s, %s): %s", family, protocol, reason)
			}
			result := runner.RunCommandTest(t, protocol, cmd, overrides)
			if !result.Passed {
				t.Fatalf("%s on %s: %s\nstdout: %s\nstderr: %s",
					cmd.Name, protocol, result.Message, result.Stdout, result.Stderr)
			}
			if check != nil {
				check(t, result)
			}
		})
		if !ok {
			return
		}
	}
}

// TestCLIPlatformMatrix runs platform put, get, list, reseal, status and
// delete in order on every transport, against one secret per transport.
func TestCLIPlatformMatrix(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			r := runner.WithKeyDir(commands.CreateTempKeyDir(t))
			secret := fmt.Sprintf("it-platform-%s-%d", protocol, time.Now().UnixNano())
			step := func(*testing.T, commands.CommandDefinition) (map[string]string, string) {
				return map[string]string{commands.ArgPlatformSecret: secret}, ""
			}
			check := func(t *testing.T, res *commands.TestResult) {
				out := res.Stdout + res.Stderr
				switch res.Command.Name {
				case "platform-get":
					assertContains(t, out, "it-platform-value", "get returns the value put stored")
				case "platform-list":
					assertContains(t, out, secret, "list names the secret put stored")
				}
			}
			runWorkflowCell(t, r, protocol, commands.CategoryPlatform, step, check)
		})
	}
}

// clusterMembers parses the member count "cluster status" prints.
var clusterMembers = regexp.MustCompile(`(?:Members:\s+|"member_count":\s*)(\d+)`)

// TestCLIClusterMatrix runs cluster status, members, add, remove and
// rebalance stats, plan, execute, report in order on every transport the
// qrdb control plane serves. add, remove and execute skip on a one-node
// cluster, naming that reason.
func TestCLIClusterMatrix(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			members := -1
			planFile := filepath.Join(t.TempDir(), "rebalance-plan.json")
			spare := os.Getenv(spareReplicaEnv)

			step := func(t *testing.T, cmd commands.CommandDefinition) (map[string]string, string) {
				switch cmd.Name {
				case "cluster-add", "cluster-remove":
					if members < 2 {
						return nil, fmt.Sprintf("%s (members=%d)", oneNodeReason, members)
					}
					id, addr, found := strings.Cut(spare, "@")
					if !found {
						return nil, "no spare replica to remove and add back (set " + spareReplicaEnv + "=id@host:port)"
					}
					return map[string]string{"replica-id": id, "raft-address": addr}, ""
				case "rebalance-execute":
					if members < 2 {
						return nil, fmt.Sprintf("%s (members=%d)", oneNodeReason, members)
					}
					return map[string]string{"plan": planFile}, ""
				case "rebalance-plan":
					return map[string]string{"out": planFile}, ""
				}
				return nil, ""
			}
			check := func(t *testing.T, res *commands.TestResult) {
				if res.Command.Name != "cluster-status" {
					return
				}
				m := clusterMembers.FindStringSubmatch(res.Stdout)
				if m == nil {
					t.Fatalf("cluster status printed no member count: %s", res.Stdout)
				}
				members, _ = strconv.Atoi(m[1])
			}
			// The cluster commands run before rebalance, so the member count
			// is known when rebalance execute decides whether to run.
			runWorkflowCell(t, runner, protocol, commands.CategoryCluster, step, check)
			runWorkflowCell(t, runner, protocol, commands.CategoryRebalance, step, nil)
		})
	}
}

// TestCLIBootstrapMatrix runs bootstrap show-keys on every transport and
// the local bootstrap verbs once, on the embedded cell: key generation then
// display, SPKI pins and TLSA records of a fresh certificate, and auto
// against the REST listener pinned by its leaf certificate.
func TestCLIBootstrapMatrix(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			dir := t.TempDir()
			certFile := filepath.Join(dir, "cert.pem")
			noiseKey := filepath.Join(dir, "noise.key")
			p256Key := filepath.Join(dir, "p256.key")
			bundle := filepath.Join(dir, "bundle.pem")

			step := func(t *testing.T, cmd commands.CommandDefinition) (map[string]string, string) {
				switch cmd.Name {
				case "bootstrap-noise-generate-key":
					return map[string]string{"output": noiseKey}, ""
				case "bootstrap-noise-show-key":
					return map[string]string{"key-file": noiseKey}, ""
				case "bootstrap-noise-generate-p256-key":
					return map[string]string{"output": p256Key}, ""
				case "bootstrap-noise-show-p256-key":
					return map[string]string{"key-file": p256Key}, ""
				case "bootstrap-noise-show-spki-pin", "bootstrap-spki-show-pin", "bootstrap-dane-generate-tlsa":
					writeSelfSignedCert(t, certFile)
					return map[string]string{"cert-file": certFile}, ""
				case "bootstrap-auto":
					serverURL, pin, reason := restLeafPin(t, runner)
					if reason != "" {
						return nil, reason
					}
					return map[string]string{"server-url": serverURL, "spki-pin": pin, "bundle-output": bundle}, ""
				}
				return nil, ""
			}
			check := func(t *testing.T, res *commands.TestResult) {
				if res.Command.Name != "bootstrap-auto" {
					return
				}
				pemBytes, err := os.ReadFile(bundle)
				if err != nil || !strings.Contains(string(pemBytes), "CERTIFICATE") {
					t.Fatalf("bootstrap auto wrote no CA bundle to %s: %v", bundle, err)
				}
			}
			runWorkflowCell(t, runner, protocol, commands.CategoryBootstrap, step, check)
		})
	}
}

// writeSelfSignedCert writes a fresh self-signed P-256 certificate to path
// once.
func writeSelfSignedCert(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kms.example.com"},
		DNSNames:     []string{"kms.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
}

// restLeafPin returns the REST listener URL and the hex SHA-256 SPKI pin of
// its leaf certificate, verified against the integration CA, or why bootstrap
// auto cannot pin it.
func restLeafPin(t *testing.T, runner *commands.TestRunner) (string, string, string) {
	t.Helper()
	u, err := url.Parse(runner.RESTBaseURL)
	if err != nil || u.Scheme != "https" {
		return "", "", "REST listener is not HTTPS; bootstrap auto pins a TLS leaf"
	}
	caFile := runner.TLSCACert
	if caFile == "" {
		caFile = os.Getenv("KEYSTORE_TLS_CA")
	}
	if caFile == "" {
		caFile = "/etc/xkms/certs/ca.crt"
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read integration CA %s: %v", caFile, err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		RootCAs:    pool,
		ServerName: u.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("TLS dial %s: %v", host, err)
	}
	defer conn.Close()
	leaf := conn.ConnectionState().PeerCertificates[0]
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return runner.RESTBaseURL, hex.EncodeToString(sum[:]), ""
}
