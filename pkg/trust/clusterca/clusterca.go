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

// Package clusterca is the canonical Raft cluster-node identity provisioner
// for the stack. It resolves the mutual-TLS material a clustered qrdb node
// needs at construction time, under a single precedence:
//
//  1. Explicit operator PEM files (Options.RaftTLSFiles).
//  2. ACME-attested enrollment (Options.ACME): the TrustedCA is the cluster
//     CA; the first node pre-stages the CA hierarchy and issues its own
//     transport certificate in-process, joining nodes fetch the trust anchor
//     via truststrap (Noise NK / SPKI / DANE / Direct) and enroll through
//     ACME enroll-01 TPM attestation. Node certificates carry a SPIFFE node
//     SAN and key-provenance OIDs.
//  3. Local-CA mode (default, ACME unset): the TrustedCA issues a leaf for
//     the node key on Options.KeyBackend (a TPM/HSM-held key, or the
//     software backend when unset) through its crypto.Signer, on the first
//     node only.
//
// The TrustedCA is the cluster CA in modes 2 and 3, and no mode writes a
// cluster CA private key (ca-key.pem) to disk.
//
// Every consumer (xkms pkg/server, go-quicbaas) routes through this one
// package — mirroring pkg/trust/bootstrap — so cluster identity logic is
// never reimplemented downstream. The composition root injects small seams
// (backend resolver, CA issuer) and receives a qrdb RaftMTLSConfig ready for
// qrdb's WithRaftMTLS.
package clusterca

import (
	"context"
	"crypto/x509"
	"log/slog"
	"os"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// CAIssuer is the minimal certificate-authority surface the provisioner
// needs. The concrete *ca.CA satisfies it; go-quicbaas's TrustedCA instance
// satisfies the subset it uses (IssuerForIdentity is consulted only when
// ClusterCACN is set, via the ca.IdentityIssuer assertion).
type CAIssuer interface {
	SignCSR(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error)
	CABundle() ([]byte, error)
	CACertificate() (*x509.Certificate, error)
}

// ExplicitFiles holds operator-supplied PEM file paths (precedence 1). All
// three must be set for the mode to engage.
type ExplicitFiles struct {
	// CACertFile is the PEM file containing the cluster trust anchor(s).
	CACertFile string

	// CertFile is the PEM file containing this node's certificate (chain).
	CertFile string

	// KeyFile is the PEM file containing this node's private key.
	KeyFile string
}

// Enabled reports whether all three file paths are configured.
func (f *ExplicitFiles) Enabled() bool {
	return f != nil && f.CACertFile != "" && f.CertFile != "" && f.KeyFile != ""
}

// ACMEOptions configures ACME-attested enrollment (precedence 2).
type ACMEOptions struct {
	// DirectoryURL is the ACME directory endpoint of an existing cluster
	// node. Required on JOINING nodes; ignored on the first node, which
	// issues in-process.
	DirectoryURL string

	// ChallengePort is the local HTTP port served during the enroll-01
	// credential exchange (the ACME server dials back to it). Defaults to
	// "8080", matching the server default.
	ChallengePort string

	// ChallengeHost is the host the enroll-01 listener binds. Empty binds
	// every interface; the composition root passes the daemon's own bind
	// host so this listener binds what every other daemon listener binds.
	ChallengeHost string
}

// Options holds the provisioning parameters. The composition root populates
// this from its own configuration plus two injected seams (Backends, CA).
type Options struct {
	// RaftAddress is this node's Raft address (host:port) — the SPIFFE node
	// identity, and the value a joiner presents, whole, as its ACME order's
	// permanent-identifier. The cluster CA stamps the node URI only when it
	// finds exactly this string in its membership, and its enroll-01
	// challenge dials the host part on the challenge port.
	RaftAddress string

	// NodeID is this node's replica ID (names the node key).
	NodeID uint64

	// TrustDomain is the cluster SPIFFE trust domain.
	TrustDomain string

	// Members is the configured cluster membership (replicaID → raftAddr).
	Members map[uint64]string

	// DataDir is the cluster identity cache directory
	// (e.g. {Storage.Path}/cluster-ca).
	DataDir string

	// RaftTLSFiles engages precedence 1 when fully set.
	RaftTLSFiles *ExplicitFiles

	// ACME engages attested mode (precedence 2) when non-nil; nil selects
	// local-CA mode (precedence 3).
	ACME *ACMEOptions

	// KeyBackend names the backend holding this node's transport key
	// ("tpm2" / "pkcs11" / "" = software).
	KeyBackend string

	// Bootstrap configures the truststrap join methods a JOINING node uses
	// to fetch the trust anchor (Noise NK / SPKI / DANE / Direct).
	Bootstrap clusterenroll.BootstrapOptions

	// Advertise configures the Noise NK bootstrap server the founding node
	// starts for peer enrollment, on first issuance and on cached restarts.
	Advertise clusterenroll.AdvertiseOptions

	// Backends resolves the cluster CA's key backends by store type (the CA
	// key custody). The composition root supplies a resolver that is safe to
	// call BEFORE its full service registry exists (constructed directly from
	// configuration).
	Backends func(name string) (xkms.Backend, error)

	// NodeKeyBackends resolves the backend named by KeyBackend that holds
	// this node's transport key, independent of the CA key custody (see
	// NewNodeKeyBackends). It must refuse a name it has no backend for.
	NodeKeyBackends func(name string) (xkms.Backend, error)

	// CA is the running TrustedCA instance, when one is already initialized
	// at provisioning time (e.g. a composition root without the embedded-
	// storage boot cycle). Nil on an xkmsd first boot, where the CA is
	// pre-staged from CAConfig instead.
	CA CAIssuer

	// CAConfig enables the first-node pre-stage: the full CA identity
	// hierarchy to generate before the datastore exists. Nil disables
	// pre-staging (the first node then requires CA to be set).
	CAConfig *ca.MultiIdentityCAConfig

	// ClusterCACN names the CA identity (intermediate) that issues transport
	// certificates. Empty selects the CA's issuing identity.
	ClusterCACN string
}

// Result is the provisioning outcome.
type Result struct {
	// MTLS is the material for qrdb's WithRaftMTLS: CACert is the cluster
	// trust-anchor pool and Certificate the node's (possibly signer-backed)
	// certificate chain.
	MTLS *qrdbnode.RaftMTLSConfig

	// Advertiser is the running Noise NK bootstrap server on the founding
	// node of a multi-node cluster, on every boot (nil otherwise). The caller must Stop() it during shutdown.
	Advertiser *clusterenroll.Advertiser
}

// Provisioner resolves cluster-node mTLS material per the package precedence.
// localCAMode names precedence 3 in errors and logs: the local TrustedCA
// issues this node's leaf, whatever backend holds the node key.
const localCAMode = "local-ca"

type Provisioner struct {
	opts   *Options
	logger *slog.Logger
}

// New validates the options and returns a Provisioner. Mode-dependent
// requirements fail fast here, not at Provision time.
func New(opts *Options, logger *slog.Logger) (*Provisioner, error) {
	if opts == nil {
		return nil, &ErrMissingOption{Field: "Options", Mode: "any"}
	}
	if logger == nil {
		logger = slog.Default()
	}
	if opts.RaftTLSFiles.Enabled() {
		return &Provisioner{opts: opts, logger: logger}, nil
	}
	if opts.RaftAddress == "" {
		return nil, &ErrMissingOption{Field: "RaftAddress", Mode: "auto-enrollment"}
	}
	if opts.DataDir == "" {
		return nil, &ErrMissingOption{Field: "DataDir", Mode: "auto-enrollment"}
	}
	if opts.ACME != nil {
		if opts.Backends == nil {
			return nil, &ErrMissingOption{Field: "Backends", Mode: "acme"}
		}
		if opts.CA == nil && opts.CAConfig == nil && !opts.Bootstrap.HasFlags() {
			return nil, &ErrMissingOption{Field: "CA or CAConfig", Mode: "acme first-node"}
		}
		if opts.ACME.ChallengePort == "" {
			opts.ACME.ChallengePort = "8080"
		}
	}
	if opts.ACME == nil {
		if opts.Backends == nil {
			return nil, &ErrMissingOption{Field: "Backends", Mode: localCAMode}
		}
		// Local-CA mode issues from the local TrustedCA, which a joining
		// node does not hold; it enrolls through ACME instead.
		if opts.Bootstrap.HasFlags() {
			return nil, &ErrLocalCAJoin{KeyBackend: opts.KeyBackend}
		}
		if opts.CA == nil && opts.CAConfig == nil {
			return nil, &ErrMissingOption{Field: "CA or CAConfig", Mode: localCAMode}
		}
	}
	if opts.NodeKeyBackends == nil {
		return nil, &ErrMissingOption{Field: "NodeKeyBackends", Mode: "auto-enrollment"}
	}
	return &Provisioner{opts: opts, logger: logger}, nil
}

// Provision resolves the node's mTLS material per the package precedence.
func (p *Provisioner) Provision(ctx context.Context) (*Result, error) {
	if p.opts.RaftTLSFiles.Enabled() {
		return p.provisionFromFiles()
	}
	// Every auto-enrolled mode (software, hardware-key, ACME-attested)
	// issues from the TrustedCA through its crypto.Signer; no mode writes
	// a cluster CA private key to disk (go-xkms#1381).
	return p.provisionTrustedCA(ctx)
}

// provisionFromFiles loads operator-supplied PEM material (precedence 1).
func (p *Provisioner) provisionFromFiles() (*Result, error) {
	f := p.opts.RaftTLSFiles
	caCert, err := os.ReadFile(f.CACertFile)
	if err != nil {
		return nil, &ErrFileRead{Field: "CACertFile", Path: f.CACertFile, Err: err}
	}
	cert, err := os.ReadFile(f.CertFile)
	if err != nil {
		return nil, &ErrFileRead{Field: "CertFile", Path: f.CertFile, Err: err}
	}
	key, err := os.ReadFile(f.KeyFile)
	if err != nil {
		return nil, &ErrFileRead{Field: "KeyFile", Path: f.KeyFile, Err: err}
	}
	p.logger.Info("cluster mTLS from operator-supplied files",
		"ca_cert_file", f.CACertFile, "cert_file", f.CertFile)
	return &Result{MTLS: &qrdbnode.RaftMTLSConfig{CACert: caCert, Cert: cert, Key: key}}, nil
}

// buildEnrollOptions maps Options onto go-qrdb's clusterenroll Options.
func (p *Provisioner) buildEnrollOptions() *clusterenroll.Options {
	return &clusterenroll.Options{
		RaftAddress: p.opts.RaftAddress,
		TrustDomain: p.opts.TrustDomain,
		DataDir:     p.opts.DataDir,
		SingleNode:  len(p.opts.Members) <= 1,
		Bootstrap:   p.opts.Bootstrap,
		Advertise:   p.opts.Advertise,
	}
}

// expectedNodeURI returns this node's canonical SPIFFE identity.
func (p *Provisioner) expectedNodeURI() string {
	return clusterenroll.NodeURI(p.opts.TrustDomain, p.opts.RaftAddress)
}

// verifyLeafAgainstAnchor verifies that leaf chains to the anchor pool
// (optionally through intermediates) and carries this node's SPIFFE SAN.
func (p *Provisioner) verifyLeafAgainstAnchor(leaf *x509.Certificate, intermediates []*x509.Certificate, anchorPEM []byte) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(anchorPEM) {
		return &ErrAnchorMismatch{Reason: "trust anchor contains no parseable certificates"}
	}
	pool := x509.NewCertPool()
	for _, ic := range intermediates {
		pool.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return &ErrAnchorMismatch{Reason: err.Error()}
	}

	expected := p.expectedNodeURI()
	got := make([]string, 0, len(leaf.URIs))
	for _, u := range leaf.URIs {
		if u.String() == expected {
			return nil
		}
		got = append(got, u.String())
	}
	return &ErrSPIFFEMismatch{Expected: expected, Got: got}
}
