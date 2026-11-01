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

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
)

// unifiedTLSProvider serves the unified API server's certificate through a
// GetCertificate callback so the material can rotate without restarting the
// embedded node's listeners. The node starts before the CA composes, so the
// initial certificate is either operator-supplied files or a node-local
// bootstrap self-signed keypair; once the CA is initialized and
// ensureTLSServerCert has issued the real server certificate,
// upgradeUnifiedTLSCert swaps it in.
type unifiedTLSProvider struct {
	cert atomic.Pointer[tls.Certificate]

	// clientCAs holds the pool client certificates verify against when the
	// configured client-auth mode verifies. Like the serving certificate it
	// rotates: operator-supplied CA files seed it, and the embedded CA's
	// bundle replaces it once the CA composes, so admin-mTLS clients holding
	// CA-issued certificates verify without operator-managed files.
	clientCAs atomic.Pointer[x509.CertPool]
}

// getCertificate implements tls.Config.GetCertificate.
func (p *unifiedTLSProvider) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := p.cert.Load(); c != nil {
		return c, nil
	}
	return nil, ErrNoTLSCertAvailable
}

// unifiedBootstrapCertDir is the storage-path subdirectory holding the
// bootstrap keypair, persisted so the presented certificate is stable across
// restarts (first-contact pinning flows tolerate an upgrade to the CA-issued
// certificate, not a new random identity every boot).
const unifiedBootstrapCertDir = "unified-tls"

// unifiedCABundleFile names the CA bundle persisted beside the bootstrap
// certificate when the CA-issued certificate replaces it. The bootstrap
// certificate verifies the listener only until that swap, which happens in
// memory, so a local operator holding the state directory needs this bundle
// to keep verifying the listener after it (DS-3769).
const unifiedCABundleFile = "ca-bundle.pem"

// buildUnifiedTLSConfig assembles the TLS configuration handed to the
// embedded qrdb node's server (qrdb transports are TLS-only). Certificate
// preference order: operator-supplied cert_file/key_file, else a persisted
// node-local bootstrap self-signed certificate generated on first boot.
// The returned config serves through the rotating provider so the CA-issued
// certificate replaces the bootstrap material once the CA composes.
func (s *Server) buildUnifiedTLSConfig() (*tls.Config, error) {
	provider := &unifiedTLSProvider{}

	if s.config.TLS.CertFile != "" && s.config.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
		if err != nil {
			return nil, &ErrTLSCertOp{Operation: "load unified server certificate", Err: err}
		}
		provider.cert.Store(&cert)
	} else {
		cert, err := s.ensureBootstrapCert()
		if err != nil {
			return nil, err
		}
		provider.cert.Store(cert)
	}

	// Seed the client-CA pool from operator-supplied files and the init
	// ceremony root when present; the embedded CA's bundle joins it after
	// composition (upgradeUnifiedTLSCert).
	pool, err := s.configuredClientCAs()
	if err != nil {
		return nil, err
	}
	if pool != nil {
		provider.clientCAs.Store(pool)
	}

	s.mu.Lock()
	s.unifiedTLS = provider
	s.mu.Unlock()

	cfg := &tls.Config{
		GetCertificate: provider.getCertificate,
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     parseClientAuthMode(s.config.TLS.ClientAuth),
		// qrdb's client-trust pool captures this static set when the node
		// wires the config, and verifies every client chain its mTLS
		// authenticator sees against it, so the seeded pool -- the init
		// ceremony root among it -- must be here, not only per connection.
		ClientCAs: pool,
	}
	if cfg.ClientAuth != tls.NoClientCert {
		// The client-CA pool rotates (bootstrap -> CA-issued), and
		// tls.Config.ClientCAs is fixed at handshake-config time, so each
		// connection resolves the current pool through GetConfigForClient.
		cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			conn := cfg.Clone()
			conn.GetConfigForClient = nil
			conn.ClientCAs = provider.clientCAs.Load()
			return conn, nil
		}
	}
	return cfg, nil
}

// parseClientAuthMode maps the tls.client_auth configuration value onto the
// crypto/tls client-authentication policy, identically to the legacy
// listener's mapping in buildTLSConfig.
func parseClientAuthMode(mode string) tls.ClientAuthType {
	switch mode {
	case "require", "require_and_verify":
		return tls.RequireAndVerifyClientCert
	case "verify":
		return tls.VerifyClientCertIfGiven
	case "request":
		return tls.RequestClientCert
	default:
		return tls.NoClientCert
	}
}

// caBundleSource is the subset of ca.TrustedCA that upgradeUnifiedTLSCert
// and unifiedClientCAPool need: the CA's own PEM bundle, unioned into the
// unified provider's client-CA pool alongside the operator-configured
// client CAs.
type caBundleSource interface {
	// CABundle returns the CA certificate chain in PEM format.
	CABundle() ([]byte, error)
}

// upgradeUnifiedTLSCert swaps the CA-issued server certificate into the
// unified provider once the CA has composed (called after
// ensureTLSServerCert), and installs the client-CA pool computed by
// unifiedClientCAPool -- the union of the operator-configured client CAs and
// the CA's bundle -- so both an operator-anchored mTLS client and a
// CA-issued one verify after the upgrade. bundle may be nil (no CA bundle
// source available); the serving certificate still upgrades. A failure
// leaves the previously installed client-CA pool serving -- degraded but
// available -- and is reported to the caller for logging.
func (s *Server) upgradeUnifiedTLSCert(bundle caBundleSource) error {
	s.mu.Lock()
	provider := s.unifiedTLS
	s.mu.Unlock()
	if provider == nil {
		return nil
	}
	cfg, err := s.buildTLSConfig()
	if err != nil {
		return err
	}
	if len(cfg.Certificates) == 0 {
		return ErrNoTLSCertAvailable
	}
	if bundle != nil {
		if pool, poolErr := s.unifiedClientCAPool(bundle); poolErr == nil {
			provider.clientCAs.Store(pool)
		} else {
			s.logger.Warn("unified API server: client-CA pool not upgraded",
				slog.Any("error", poolErr))
		}
		// Persisted before the swap, so a client that sees the CA-issued
		// certificate already finds the bundle that verifies it.
		if s.config.Datastore.Path != "" {
			if persistErr := s.persistUnifiedCABundle(bundle); persistErr != nil {
				s.logger.Warn("unified API server: CA bundle not persisted beside the bootstrap TLS certificate",
					slog.Any("error", persistErr))
			}
		}
	}
	provider.cert.Store(&cfg.Certificates[0])
	s.logger.Info("unified API server: CA-issued TLS certificate installed",
		"cn", s.config.TLS.ServerCN)
	return nil
}

// persistUnifiedCABundle writes the CA bundle that verifies the CA-issued
// serving certificate to unifiedCABundleFile, beside the persisted bootstrap
// certificate and with the same owner-only permissions.
func (s *Server) persistUnifiedCABundle(bundle caBundleSource) error {
	bundlePEM, err := bundle.CABundle()
	if err != nil {
		return &ErrTLSCertOp{Operation: "load CA bundle to persist", Err: err}
	}
	dir := filepath.Join(s.config.Datastore.Path, unifiedBootstrapCertDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return &ErrTLSCertOp{Operation: "create unified TLS directory", Err: err}
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, unifiedCABundleFile), bundlePEM, 0o600); err != nil {
		return &ErrTLSCertOp{Operation: "persist unified CA bundle", Err: err}
	}
	return nil
}

// unifiedClientCAPool builds the client-CA pool the unified provider
// verifies mTLS clients against once the CA has composed: the union of the
// operator-configured client CAs (tls.ca_file plus tls.client_cas, resolved
// through loadClientCAsUnion -- the same helper buildTLSConfig uses at
// startup, so the two call sites can never disagree on what "configured
// client CAs" means) and the CA's own bundle.
//
// Before this, upgradeUnifiedTLSCert replaced the pool outright with the CA
// bundle alone: once the CA composed, an mTLS client anchored only by an
// operator-configured client CA silently stopped verifying, even though
// tls.client_cas still named that CA (go-xkms#794).
func (s *Server) unifiedClientCAPool(bundle caBundleSource) (*x509.CertPool, error) {
	configured, err := s.configuredClientCAs()
	if err != nil {
		return nil, err
	}

	pool := configured
	if pool == nil {
		pool = x509.NewCertPool()
	} else {
		pool = pool.Clone()
	}

	bundlePEM, err := bundle.CABundle()
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "load CA bundle for the unified client-CA pool", Err: err}
	}
	if len(bundlePEM) > 0 && !pool.AppendCertsFromPEM(bundlePEM) {
		return nil, &ErrCertParse{}
	}
	return pool, nil
}

// ensureBootstrapCert loads the persisted node-local bootstrap keypair or
// generates and persists a new one (ECDSA P-256, self-signed, SANs covering
// the configured host, the server CN, localhost and the loopback
// addresses). It exists so the unified server can terminate TLS before the
// CA composes without demanding operator-managed files.
func (s *Server) ensureBootstrapCert() (*tls.Certificate, error) {
	dir := filepath.Join(s.config.Datastore.Path, unifiedBootstrapCertDir)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cn := s.config.TLS.ServerCN
	if cn == "" {
		cn = "xkmsd-bootstrap"
	}
	dnsNames, ips := s.serverCertSANs(cn, true)

	// A persisted certificate is reused only while it still presents exactly
	// the names configuration asks for. A node whose tls.include_localhost_sans,
	// server.host or tls.extra_sans changed after first boot must not keep
	// serving the old set for the rest of the certificate's year (#140).
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil &&
			time.Now().Before(leaf.NotAfter.Add(-24*time.Hour)) {
			if certSANsMatch(leaf, dnsNames, ips) {
				s.logger.Info("unified API server: serving persisted bootstrap TLS certificate until the CA composes")
				return &cert, nil
			}
			s.logger.Info("unified API server: persisted bootstrap TLS certificate no longer presents the configured SANs; regenerating",
				"have_dns", leaf.DNSNames, "want_dns", dnsNames)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "generate bootstrap TLS key", Err: err}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "generate bootstrap TLS serial", Err: err}
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "create bootstrap TLS certificate", Err: err}
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "encode bootstrap TLS key", Err: err}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Persist when a storage path exists (memory-backed test nodes skip);
	// a persistence failure degrades to an ephemeral certificate rather
	// than refusing to serve, but the failure is no longer silent: it is
	// logged so an operator can see why the bootstrap identity is not
	// stable across restarts.
	if s.config.Datastore.Path != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			s.logger.Warn("unified API server: failed to create bootstrap TLS certificate directory; serving an ephemeral certificate",
				slog.Any("error", &ErrTLSCertOp{Operation: "create bootstrap TLS certificate directory", Err: err}))
		} else {
			var certErr, keyErr error
			if err := fsutil.WriteFileAtomic(certPath, certPEM, 0o600); err != nil {
				certErr = &ErrTLSCertOp{Operation: "persist bootstrap TLS certificate", Err: err}
			}
			if err := fsutil.WriteFileAtomic(keyPath, keyPEM, 0o600); err != nil {
				keyErr = &ErrTLSCertOp{Operation: "persist bootstrap TLS key", Err: err}
			}
			if writeErr := errors.Join(certErr, keyErr); writeErr != nil {
				s.logger.Warn("unified API server: failed to persist bootstrap TLS certificate; serving an ephemeral certificate until next restart",
					slog.Any("error", writeErr))
			}
		}
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "assemble bootstrap TLS certificate", Err: err}
	}
	s.logger.Info("unified API server: generated bootstrap TLS certificate; the CA-issued certificate installs after composition",
		"cn", cn)
	return &cert, nil
}

// certSANsMatch reports whether leaf presents exactly the DNS and IP SAN sets
// configuration asks for, as sets: order does not matter, a name the
// configuration no longer wants or one it now wants and the certificate lacks
// both mean the certificate must be reissued.
func certSANsMatch(leaf *x509.Certificate, dns []string, ips []net.IP) bool {
	if len(leaf.DNSNames) != len(dns) || len(leaf.IPAddresses) != len(ips) {
		return false
	}
	wantDNS := make(map[string]struct{}, len(dns))
	for _, d := range dns {
		wantDNS[d] = struct{}{}
	}
	for _, d := range leaf.DNSNames {
		if _, ok := wantDNS[d]; !ok {
			return false
		}
	}
	for _, have := range leaf.IPAddresses {
		found := false
		for _, want := range ips {
			if have.Equal(want) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// serverCertSANs is the SAN set a locally issued server certificate carries,
// built from configuration alone: the server CN, the loopback names when
// tls.include_localhost_sans says so, server.host, the cluster peer hosts
// and tls.extra_sans. Both issuance paths call this so they can never
// disagree on what configuration asks for.
//
// nodeLocal adds the machine's own hostname, and is set only for the
// bootstrap certificate, which each node generates for itself. The CA-issued
// certificate lives in replicated storage keyed by CN and is shared by every
// node, so its SAN set must be identical wherever it is computed: with the
// hostname in it, each node would judge the shared certificate stale, retire
// it and reissue it for its own name, and the cluster would churn. A node
// that clients dial by a name outside server.host and the peer list names it
// in tls.extra_sans.
func (s *Server) serverCertSANs(serverCN string, nodeLocal bool) (dns []string, ips []net.IP) {
	return localCertSANs(serverCN, s.config.Server.Host, s.config.TLS.IncludeLocalhostSANs, nodeLocal,
		append(s.clusterPeerHosts(), s.config.TLS.ExtraSANs...)...)
}

// localCertSANs builds the SAN set a locally issued server certificate must
// cover: the configured server CN, localhost plus the loopback addresses
// when includeLoopback is set, the machine's own hostname when
// includeHostname is set, the configured listen host, and any extra hosts
// the caller supplies (the cluster peer hostnames — the CA-issued
// certificate lives in replicated storage keyed by CN, so one shared
// certificate serves every node and must verify for each node's name).
// Clients dial nodes by hostname, so a certificate that only covers
// localhost fails verification for every remote client. No name here is a
// literal the configuration cannot switch off: the loopback set is
// tls.include_localhost_sans, and a wildcard address is never a SAN (#140).
func localCertSANs(serverCN, host string, includeLoopback, includeHostname bool, extraHosts ...string) (dns []string, ips []net.IP) {
	dns = []string{}
	ips = []net.IP{}
	if includeLoopback {
		dns = append(dns, "localhost")
		ips = append(ips, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	}
	addDNS := func(name string) {
		if name == "" || net.ParseIP(name) != nil {
			return
		}
		for _, d := range dns {
			if d == name {
				return
			}
		}
		dns = append(dns, name)
	}
	addIP := func(ip net.IP) {
		for _, existing := range ips {
			if existing.Equal(ip) {
				return
			}
		}
		ips = append(ips, ip)
	}
	addHost := func(h string) {
		if h == "" {
			return
		}
		if ip := net.ParseIP(h); ip != nil {
			// A bind host of 0.0.0.0 or :: says "every interface"; it is
			// not an address a client dials and never a name a certificate
			// presents.
			if ip.IsUnspecified() {
				return
			}
			addIP(ip)
			return
		}
		addDNS(h)
	}
	// The CN is classified like every other name: an operator who sets
	// tls.server_cn to an address gets an IP SAN, which is what a client
	// dialing that address verifies against, not the Common Name.
	addHost(serverCN)
	if includeHostname {
		if hostname, err := os.Hostname(); err == nil {
			addDNS(hostname)
		}
	}
	addHost(host)
	for _, h := range extraHosts {
		addHost(h)
	}
	return dns, ips
}

// clusterPeerHosts returns the hostnames (or IPs) of the configured cluster
// peers, with the Raft port stripped. The shared TLS server certificate must
// carry every peer's name because the certificate replicates to all nodes.
// A malformed peer list yields no extra SANs; peer validation happens at
// node construction, not here.
func (s *Server) clusterPeerHosts() []string {
	if !s.config.Cluster.Enabled {
		return nil
	}
	members, err := s.config.Cluster.Members()
	if err != nil {
		return nil
	}
	hosts := make([]string, 0, len(members))
	for _, addr := range members {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		hosts = append(hosts, host)
	}
	return hosts
}
