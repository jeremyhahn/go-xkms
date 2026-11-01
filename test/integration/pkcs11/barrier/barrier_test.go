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

//go:build integration && pkcs11 && pkcs11_barrier

// Package barrier is the reboot-equivalent end-to-end test of the
// TPM-sealed PKCS#11 barrier PIN (go-xkms#811): the operator seals the
// token's user PIN under the Platform SRK with `xkmsd seal-pkcs11-pin`, and
// every later start of xkmsd releases it from the TPM and logs in to the
// token without a PIN in its configuration. The TPM is an external swtpm
// that outlives each xkmsd process, so a restart sees the same TPM state a
// reboot would; the token is a SoftHSM 2.7.0 slot.
//
// Run through `make integration-test-pkcs11-barrier`, which starts the swtpm
// and the SoftHSM image with docker compose.
package barrier

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tcptpm "github.com/google/go-tpm/tpm2/transport/tcp"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11strategy"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
	"github.com/jeremyhahn/go-xkms/test/integration/xkmsdtest"
)

const (
	// xkmsdTags builds xkmsd with the PKCS#11 node-seal strategy compiled in.
	xkmsdTags = "codec_cbor codec_json codec_msgpack pkcs11"

	// platformPCR and platformPCRBank are the platform PCR policy the PIN is
	// sealed under: a one-PCR board set holding boot PCR 7.
	platformPCR     = 7
	platformPCRBank = "sha256"

	tokenLabel   = "xkms-barrier"
	bootTimeout  = 2 * time.Minute
	stopTimeout  = 30 * time.Second
	logTailLines = 40
)

// TestPKCS11BarrierPINSurvivesRestartAndFailsClosedOnPCRChange seals the
// token PIN once, starts xkmsd twice against the same TPM and token and
// requires the barrier to unseal unattended both times, then extends the
// platform PCR and requires the next start to refuse to run.
func TestPKCS11BarrierPINSurvivesRestartAndFailsClosedOnPCRChange(t *testing.T) {
	tpmHost := os.Getenv("TPM2_SIMULATOR_HOST")
	require.NotEmpty(t, tpmHost, "TPM2_SIMULATOR_HOST names the swtpm this test seals under")
	tpmPort, err := strconv.Atoi(os.Getenv("TPM2_SIMULATOR_PORT"))
	require.NoError(t, err, "TPM2_SIMULATOR_PORT is the swtpm command port")

	dir := t.TempDir()
	bin := filepath.Join(dir, "xkmsd")
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	require.NoError(t, err)
	require.NoError(t, xkmsdtest.Build(root, xkmsdTags, bin, "./cmd/xkmsd"))

	// Provision sets SOFTHSM2_CONF for this process; every xkmsd started
	// below inherits it and so sees the same token.
	token := softhsmtest.Provision(t, tokenLabel)
	cfgPath, url, data := writeConfig(t, dir, tpmHost, tpmPort, token)

	sealPIN(t, bin, cfgPath, token.UserPIN)

	for boot := 1; boot <= 2; boot++ {
		srv := startXkmsd(t, bin, cfgPath, filepath.Join(dir, fmt.Sprintf("boot-%d.log", boot)))
		requireUnsealed(t, srv, url, data)
		require.NoError(t, srv.stop(), "boot %d: stopping xkmsd\n%s", boot, srv.logTail())
	}

	extendPlatformPCR(t, tpmHost, tpmPort)

	srv := startXkmsd(t, bin, cfgPath, filepath.Join(dir, "boot-3.log"))
	exitErr := srv.waitExit(t)
	var exit *exec.ExitError
	require.ErrorAs(t, exitErr, &exit, "xkmsd must refuse to start once the platform PCR moved\n%s", srv.logTail())
	require.Contains(t, srv.logContents(), "building the PKCS#11 node seal",
		"xkmsd must stop at the node seal, not later\n%s", srv.logTail())

	// The process only reports the node-seal step. Resolve the same seal
	// in-process to pin down the cause: the TPM, not the token, refused.
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	res, err := embeddednode.ResolveNodeSeal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.False(t, res.Enabled)
	var nodeErr *embeddednode.NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	var buildErr *pkcs11strategy.BuildError
	require.ErrorAs(t, err, &buildErr)
	var refused *preseal.RefusedError
	require.ErrorAs(t, err, &refused)
	require.Equal(t, preseal.PKCS11PIN, refused.Name)
}

// writeConfig writes an xkmsd configuration whose barrier is the PKCS#11
// node seal. Neither the TPM nor the PKCS#11 backend is enabled as a key
// backend, and no PIN appears anywhere in it: the node seal reads the TPM
// connection from backends.tpm2 and the token from backends.pkcs11 and
// takes the PIN from the preseal store. It returns the configuration path,
// the REST URL and the data directory, where first boot writes the admin
// credential.
func writeConfig(t *testing.T, dir, tpmHost string, tpmPort int, token softhsmtest.Token) (cfgPath, url, data string) {
	t.Helper()
	port := freePort(t)
	data = filepath.Join(dir, "data")
	require.NoError(t, os.MkdirAll(data, 0o700))

	// No tls.cert_file: xkmsd persists its own bootstrap certificate under
	// <data>/unified-tls, the only anchor xkmsdtest.AdminClient trusts
	// (pkg/server buildUnifiedTLSConfig skips ensureBootstrapCert for an
	// operator-supplied certificate).
	cfg := fmt.Sprintf(`server:
  host: "localhost"
  rest_port: %[1]d
protocols:
  unix: false
  rest: true
  grpc: false
  quic: false
  mcp: false
tls:
  enabled: true
  server_cn: localhost
  min_version: TLS1.3
  client_auth: verify
auth:
  enabled: true
  type: composite
  piv_login:
    enabled: true
    allow_unattested: true
ca:
  enabled: true
  identity:
    - subject:
        cn: "pkcs11 barrier Root CA"
        organization: "XKMS Tests"
      valid: 10
      keys:
        - algorithm: "ECDSA"
          ecc-curve: "P-256"
          key_type: "CA"
      keystore-type: "software"
      is-root: true
  selected-ca: 0
  default-validity-days: 365
logging:
  level: info
  format: json
datastore:
  engine: file
  path: %[2]s
default_backend: software
backends:
  software:
    enabled: true
    path: %[2]s/software
  tpm2:
    enabled: false
    use_simulator: true
    simulator_host: %[3]q
    simulator_port: %[4]d
    platform-pcrs: [%[7]d]
    platform-pcr-bank: %[8]q
  pkcs11:
    enabled: false
    library: %[5]s
    token: %[6]q
barrier:
  enabled: true
  strategy: pkcs11
`, port, data, tpmHost, tpmPort, token.Library, token.Label, platformPCR, platformPCRBank)

	cfgPath = filepath.Join(dir, "xkmsd.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))
	return cfgPath, fmt.Sprintf("https://localhost:%d", port), data
}

// sealPIN runs the operator step: `xkmsd seal-pkcs11-pin` with the PIN on
// stdin.
func sealPIN(t *testing.T, bin, cfgPath, pin string) {
	t.Helper()
	cmd := exec.Command(bin, "seal-pkcs11-pin", "--config", cfgPath)
	cmd.Stdin = strings.NewReader(pin + "\n")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "xkmsd seal-pkcs11-pin:\n%s", out)
}

// requireUnsealed waits for the server to answer and requires its barrier
// to be initialized and unsealed with no operator input. The node unseals
// before it serves, so there is no sealed window: the barrier status comes
// from the unsealed node, which answers only the first-boot administrator.
func requireUnsealed(t *testing.T, srv *xkmsd, url, data string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), bootTimeout)
	defer cancel()
	go func() {
		select {
		case <-srv.exited:
			cancel()
		case <-ctx.Done():
		}
	}()
	client, err := xkmsdtest.AdminClient(ctx, url, data)
	require.NoError(t, err, "building the admin client\n%s", srv.logTail())
	state, err := xkmsdtest.ReadBarrierState(ctx, client, url)
	require.NoError(t, err, "reading the barrier state\n%s", srv.logTail())
	require.True(t, state.Initialized(), "the PKCS#11 node seal initializes the barrier on first boot")
	require.False(t, state.Sealed, "the PKCS#11 node seal must unseal unattended\n%s", srv.logTail())
}

// extendPlatformPCR changes the platform PCR on the swtpm, standing in for
// a boot that measured something different. It reads the PCR back over a
// fresh connection, so a transport that reset the TPM on connect would fail
// here rather than make the refusal below vacuous.
func extendPlatformPCR(t *testing.T, host string, port int) {
	t.Helper()
	before := readPlatformPCR(t, host, port)

	tpm := openTPM(t, host, port)
	digest := sha256.Sum256([]byte("go-xkms#811: an unexpected boot measurement"))
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(platformPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: digest[:]}},
		},
	}.Execute(tpm)
	require.NoError(t, err)
	require.NoError(t, tpm.Close())

	require.NotEqual(t, before, readPlatformPCR(t, host, port), "the PCR extension must persist across connections")
}

func readPlatformPCR(t *testing.T, host string, port int) []byte {
	t.Helper()
	tpm := openTPM(t, host, port)
	rsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(platformPCR),
			}},
		},
	}.Execute(tpm)
	require.NoError(t, err)
	require.NoError(t, tpm.Close())
	require.Len(t, rsp.PCRValues.Digests, 1)
	return rsp.PCRValues.Digests[0].Buffer
}

// openTPM connects the way pkg/tpm2 does: the platform port is the command
// port plus one.
func openTPM(t *testing.T, host string, port int) transport.TPMCloser {
	t.Helper()
	tpm, err := tcptpm.Open(tcptpm.Config{
		CommandAddress:  net.JoinHostPort(host, strconv.Itoa(port)),
		PlatformAddress: net.JoinHostPort(host, strconv.Itoa(port+1)),
	})
	require.NoError(t, err)
	return tpm
}

// xkmsd is one running xkmsd process.
type xkmsd struct {
	cmd    *exec.Cmd
	log    string
	exited chan struct{}
	err    error
}

// startXkmsd starts xkmsd on cfgPath with its output in logPath.
func startXkmsd(t *testing.T, bin, cfgPath, logPath string) *xkmsd {
	t.Helper()
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	srv := &xkmsd{
		cmd:    exec.Command(bin, "-config", cfgPath),
		log:    logPath,
		exited: make(chan struct{}),
	}
	srv.cmd.Dir = filepath.Dir(cfgPath)
	srv.cmd.Stdout = logFile
	srv.cmd.Stderr = logFile
	require.NoError(t, srv.cmd.Start())
	go func() {
		srv.err = errors.Join(srv.cmd.Wait(), logFile.Close())
		close(srv.exited)
	}()
	t.Cleanup(func() {
		select {
		case <-srv.exited:
		default:
			if err := srv.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("killing xkmsd: %v", err)
			}
			<-srv.exited
		}
	})
	return srv
}

// stop sends SIGTERM and waits for a clean exit, the way an init system
// stops the service before a reboot.
func (s *xkmsd) stop() error {
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-s.exited:
		return s.err
	case <-time.After(stopTimeout):
		return errors.Join(xkmsdtest.ErrTimeout, s.cmd.Process.Kill())
	}
}

// waitExit waits for a process expected to exit on its own and returns its
// exit error.
func (s *xkmsd) waitExit(t *testing.T) error {
	t.Helper()
	select {
	case <-s.exited:
		return s.err
	case <-time.After(bootTimeout):
		t.Fatalf("xkmsd kept running with a changed platform PCR\n%s", s.logTail())
		return nil
	}
}

func (s *xkmsd) logContents() string {
	out, err := os.ReadFile(s.log)
	if err != nil {
		return "reading " + s.log + ": " + err.Error()
	}
	return string(out)
}

func (s *xkmsd) logTail() string {
	lines := strings.Split(strings.TrimRight(s.logContents(), "\n"), "\n")
	if len(lines) > logTailLines {
		lines = lines[len(lines)-logTailLines:]
	}
	return strings.Join(lines, "\n")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}
