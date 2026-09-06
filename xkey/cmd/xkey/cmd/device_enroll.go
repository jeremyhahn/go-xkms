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

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

// Device enrollment file names written under the agent certificate
// directory. runDeviceConnect reads the same three names by default, so an
// enrolled device can connect without any further flags.
const (
	deviceEnrollKeyFile  = "agent-key.pem"
	deviceEnrollCSRFile  = "agent-csr.pem"
	deviceEnrollCertFile = "agent-cert.pem"
	deviceEnrollCAFile   = "ca-cert.pem"
)

// deviceEnrollMasterProbeTimeout bounds the post-issuance mTLS handshake
// against the master.
const deviceEnrollMasterProbeTimeout = 15 * time.Second

// deviceEnrollMasterSilenceWindow is how long the enrollment probe waits for
// the master to speak after the handshake. TLS 1.3 clients finish the
// handshake before the server has verified the client certificate, so a
// rejection arrives as an alert on the first read. Silence for this long
// means the master accepted the certificate.
const deviceEnrollMasterSilenceWindow = 2 * time.Second

// Device enrollment errors.
var (
	// ErrDeviceEnrollServerRequired indicates --server was not supplied.
	ErrDeviceEnrollServerRequired = errors.New("device enroll: --server is required (master address as host:port)")

	// ErrDeviceEnrollServerInvalid indicates --server is not a host:port pair.
	ErrDeviceEnrollServerInvalid = errors.New("device enroll: --server must be a host:port address")

	// ErrDeviceEnrollCodeUnsupported indicates a one-time enrollment code was
	// supplied. Code-based and admin-approved enrollment are decided by the
	// master's enrollment service, which exposes no RPC, so the code cannot be
	// redeemed from here.
	ErrDeviceEnrollCodeUnsupported = errors.New("device enroll: one-time enrollment codes are redeemed by the master's " +
		"enrollment service, which has no remote API; enroll against the xkmsd certificate authority instead " +
		"(drop --code and set --xkmsd-url or XKMSD_URL)")

	// ErrDeviceEnrollMasterUnreachable indicates the master refused or could
	// not complete a mutually authenticated connection with the freshly
	// issued certificate.
	ErrDeviceEnrollMasterUnreachable = errors.New("device enroll: the master did not accept the issued agent certificate")

	// ErrDeviceEnrollTrustAnchorInvalid indicates the CA certificate returned
	// by the certificate authority is not usable as a trust anchor.
	ErrDeviceEnrollTrustAnchorInvalid = errors.New("device enroll: the certificate authority returned an unusable trust anchor")
)

// deviceEnrollCA is the certificate authority contract the enroll command
// needs: sign the agent CSR and hand back the trust anchor. *xkmsdCA (see
// agent_ca.go) is the production implementation.
type deviceEnrollCA interface {
	SignCSR(csrPEM []byte) ([]byte, error)
	GetCACertificate() ([]byte, error)
	Close() error
}

// deviceEnrollCAFactory connects to the configured xkmsd certificate
// authority. It is a package-level variable so tests can inject a fake
// authority instead of requiring a live server.
var deviceEnrollCAFactory = func(profile string, validityDays int) (deviceEnrollCA, error) {
	return newAgentCA(profile, validityDays)
}

// deviceEnrollMasterProbe performs the mutually authenticated connection to
// the master that proves the issued certificate is accepted. It is a
// package-level variable so tests can substitute the network call.
var deviceEnrollMasterProbe = probeMasterWithClientCert

// deviceEnrollCmd enrolls this device with a master xKey instance.
var deviceEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll with a master xKey instance",
	Long: `Enroll this device as a remote agent with a master xKey instance.

Enrollment generates an agent key pair, has the xkmsd certificate authority
sign the resulting CSR, and stores the issued client certificate together
with the CA trust anchor. It then opens a mutually authenticated TLS
connection to the master to confirm the master accepts the new certificate,
so a successful run always leaves this device able to run "xkey device
connect".

The certificate authority is the xkmsd server named by --xkmsd-url or
XKMSD_URL; xkey never signs certificates locally. The master named by
--server must trust the same authority.

Files written under the agent certificate directory:
  agent-key.pem   the agent private key (0600)
  agent-csr.pem   the certificate signing request that was submitted
  agent-cert.pem  the issued certificate followed by its issuer chain
  ca-cert.pem     the certificate authority trust anchor

Examples:
  # Enroll against the xkmsd CA and verify the master accepts the result
  xkey device enroll --server master.example.com:9443 --xkmsd-url grpc://xkmsd.example.com:9090

  # Request a longer-lived certificate under a specific CA profile
  xkey device enroll --server master.example.com:9443 --cert-profile client --validity-days 365`,
	RunE: runDeviceEnroll,
}

// deviceConnectCmd connects to a previously enrolled master.
var deviceConnectCmd = &cobra.Command{
	Use:   "connect <address>",
	Short: "Connect to a paired master",
	Long: `Connect to a previously enrolled master xKey instance using
the certificate obtained during enrollment.

Examples:
  xkey device connect master.example.com:9443`,
	Args: cobra.ExactArgs(1),
	RunE: runDeviceConnect,
}

// runDeviceEnroll enrolls this device with a master xKey instance: it
// generates the agent key pair, submits the CSR to the xkmsd certificate
// authority, persists the issued certificate and trust anchor, and confirms
// the master accepts the new credentials.
func runDeviceEnroll(cmd *cobra.Command, args []string) error {
	serverAddr, _ := cmd.Flags().GetString("server")
	code, _ := cmd.Flags().GetString("code")
	name, _ := cmd.Flags().GetString("name")
	validityDays, _ := cmd.Flags().GetInt("validity-days")

	if serverAddr == "" {
		return ErrDeviceEnrollServerRequired
	}
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceEnrollServerInvalid, Cause: err}
	}
	if code != "" {
		return ErrDeviceEnrollCodeUnsupported
	}

	if name == "" {
		hostname, err := os.Hostname()
		if err != nil {
			name = "agent"
		} else {
			name = hostname
		}
	}

	logger := slog.Default()
	out := cmd.OutOrStdout()

	// Generate the agent key pair and the CSR the authority will sign.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCSRFailed, Cause: err}
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"xKey Agent"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCSRFailed, Cause: err}
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCSRFailed, Cause: err}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	_, _ = fmt.Fprintf(out, "Enrolling with master at %s...\n", serverAddr)
	_, _ = fmt.Fprintf(out, "  Agent name: %s\n", name)

	// Have the xkmsd certificate authority sign the request.
	ca, err := deviceEnrollCAFactory(agentCertProfile(cmd), validityDays)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := ca.Close(); closeErr != nil {
			logger.Warn("failed to close certificate authority client", slog.Any("error", closeErr))
		}
	}()

	certPEM, err := ca.SignCSR(csrPEM)
	if err != nil {
		return err
	}

	caPEM, err := ca.GetCACertificate()
	if err != nil {
		return err
	}

	trustPool := x509.NewCertPool()
	if !trustPool.AppendCertsFromPEM(caPEM) {
		return ErrDeviceEnrollTrustAnchorInvalid
	}

	// Persist the credentials before probing the master so a rejected probe
	// leaves the operator with material to inspect.
	certDir, err := agentCertDir()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCertWriteFailed, Cause: err}
	}
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCertWriteFailed, Cause: err}
	}

	keyPath := filepath.Join(certDir, deviceEnrollKeyFile)
	csrPath := filepath.Join(certDir, deviceEnrollCSRFile)
	certPath := filepath.Join(certDir, deviceEnrollCertFile)
	caPath := filepath.Join(certDir, deviceEnrollCAFile)

	for _, artifact := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{keyPath, keyPEM, 0600},
		{csrPath, csrPEM, 0644},
		{certPath, certPEM, 0644},
		{caPath, caPEM, 0644},
	} {
		if err := os.WriteFile(artifact.path, artifact.data, artifact.mode); err != nil {
			return &SentinelCauseError{Sentinel: ErrAgentCertWriteFailed, Cause: err}
		}
	}

	logger.Info("agent certificate issued",
		slog.String("name", name),
		slog.String("master", serverAddr),
		slog.String("certificate", certPath))

	// Confirm the master accepts the freshly issued certificate.
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCertWriteFailed, Cause: err}
	}
	if err := deviceEnrollMasterProbe(serverAddr, clientCert, trustPool); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceEnrollMasterUnreachable, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "\nEnrollment complete:\n")
	_, _ = fmt.Fprintf(out, "  Key:    %s\n", keyPath)
	_, _ = fmt.Fprintf(out, "  CSR:    %s\n", csrPath)
	_, _ = fmt.Fprintf(out, "  Cert:   %s\n", certPath)
	_, _ = fmt.Fprintf(out, "  CA:     %s\n", caPath)
	_, _ = fmt.Fprintf(out, "  Master: %s accepted the certificate\n", serverAddr)
	_, _ = fmt.Fprintf(out, "\nRun: xkey device connect %s\n", serverAddr)

	return nil
}

// probeMasterWithClientCert opens a mutually authenticated TLS 1.3
// connection to the master and reports whether the master accepted the
// client certificate.
//
// A TLS 1.3 client completes its handshake before the server has verified
// the client certificate, so acceptance cannot be read from Handshake alone:
// a rejection arrives as an alert on the first read. The probe therefore
// reads once with a short deadline. Bytes or a read timeout mean the master
// accepted the certificate; any other read error is the rejection.
func probeMasterWithClientCert(address string, clientCert tls.Certificate, roots *x509.CertPool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: deviceEnrollMasterProbeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      roots,
		ServerName:   host,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(deviceEnrollMasterSilenceWindow)); err != nil {
		return err
	}

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		// The master answered: the certificate was accepted.
		return nil
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// The master stayed silent rather than sending an alert, which also
		// means the certificate was accepted.
		return nil
	}
	return err
}

// runDeviceConnect connects to a previously enrolled master.
func runDeviceConnect(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	masterAddr := args[0]
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	tlsCA, _ := cmd.Flags().GetString("tls-ca")

	// Use default cert paths if not specified.
	certDir, err := agentCertDir()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentConnectFailed, Cause: err}
	}
	if tlsCert == "" {
		tlsCert = filepath.Join(certDir, "agent-cert.pem")
	}
	if tlsKey == "" {
		tlsKey = filepath.Join(certDir, "agent-key.pem")
	}
	if tlsCA == "" {
		tlsCA = filepath.Join(certDir, "ca-cert.pem")
	}

	clientCfg := agent.DefaultClientConfig()
	clientCfg.MasterAddress = masterAddr
	clientCfg.TLSCertFile = tlsCert
	clientCfg.TLSKeyFile = tlsKey
	clientCfg.TLSCAFile = tlsCA

	logger := slog.Default()

	client, err := agent.NewClient(clientCfg, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentConnectFailed, Cause: err}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentConnectFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Connected to master at %s\n", masterAddr)
	_, _ = fmt.Fprintf(out, "  TLS Cert: %s\n", tlsCert)

	// Wait for signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	_, _ = fmt.Fprintln(out, "\nDisconnecting...")

	return client.Disconnect()
}

func init() {
	deviceCmd.AddCommand(deviceEnrollCmd)
	deviceCmd.AddCommand(deviceConnectCmd)

	// Device enroll flags.
	deviceEnrollCmd.Flags().String("server", "", "Master server address as host:port (required)")
	deviceEnrollCmd.Flags().String("code", "", "One-time enrollment code (redeemed by the master; not supported remotely)")
	deviceEnrollCmd.Flags().String("name", "", "Agent name (default: hostname)")
	deviceEnrollCmd.Flags().String("cert-profile", agentCertProfileDefault, "CA certificate profile for the agent certificate")
	deviceEnrollCmd.Flags().Int("validity-days", 0, "Certificate validity in days (0 uses the CA default)")

	// Device connect flags.
	deviceConnectCmd.Flags().String("tls-cert", "", "TLS certificate file")
	deviceConnectCmd.Flags().String("tls-key", "", "TLS private key file")
	deviceConnectCmd.Flags().String("tls-ca", "", "TLS CA certificate file")
}
