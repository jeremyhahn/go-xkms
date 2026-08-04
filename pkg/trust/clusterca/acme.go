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

package clusterca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	acmeclient "github.com/jeremyhahn/go-xkms/pkg/acme/client"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// tpmProvider is the surface a backend must expose for enroll-01: access to
// the underlying TrustedPlatformModule. The tpm2 backend satisfies it.
type tpmProvider interface {
	TPM() pkgtpm2.TrustedPlatformModule
}

// provisionACME resolves the node identity in ACME-attested mode: cached
// material when still valid, otherwise first-node in-process issuance or
// joiner enrollment.
func (p *Provisioner) provisionACME(ctx context.Context) (*Result, error) {
	if leafChainPEM, anchorPEM, ok := p.loadCachedIdentity(); ok {
		res, err := p.resultFromCache(ctx, leafChainPEM, anchorPEM)
		if err == nil {
			p.logger.Info("cluster identity restored from cache", "data_dir", p.opts.DataDir)
			return res, nil
		}
		p.logger.Warn("cached cluster identity unusable; re-provisioning", "error", err)
	}

	if p.opts.Bootstrap.HasFlags() {
		return p.enrollJoiner(ctx)
	}
	return p.provisionFirstNode(ctx)
}

// resultFromCache rebuilds the node identity from cached PEM material,
// verifying the chain, SPIFFE SAN, remaining validity, and that the cached
// leaf still matches this node's backend-held key.
func (p *Provisioner) resultFromCache(ctx context.Context, leafChainPEM, anchorPEM []byte) (*Result, error) {
	leaf, intermediates, err := parseChainPEM(leafChainPEM)
	if err != nil {
		return nil, err
	}
	if needsRenewal(leaf, time.Now()) {
		return nil, &errs.Message{Msg: fmt.Sprintf("clusterca: cached node certificate expires %s (inside renewal window)", leaf.NotAfter)}
	}
	if err := p.verifyLeafAgainstAnchor(leaf, append(intermediates, anchorIntermediates(anchorPEM)...), anchorPEM); err != nil {
		return nil, err
	}

	signer, err := p.acmeNodeSigner(ctx, leaf)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(leaf.PublicKey, signer.Public()) {
		return nil, &ErrAnchorMismatch{Reason: "cached certificate public key does not match the backend-held node key"}
	}

	tlsCert, err := signerCertificate(certsToPEM(leaf), intermediates, signer)
	if err != nil {
		return nil, err
	}
	return p.finishACME(tlsCert, anchorPEM, false)
}

// acmeNodeSigner returns the signer for the node's ACME-mode transport key:
// the TPM-resident IDevID key for tpm2, the backend node key otherwise.
func (p *Provisioner) acmeNodeSigner(ctx context.Context, leaf *x509.Certificate) (crypto.Signer, error) {
	backendName := p.keyBackendName()
	backend, err := p.opts.Backends(backendName)
	if err != nil {
		return nil, err
	}
	if backendName == "tpm2" {
		provider, ok := backend.(tpmProvider)
		if !ok {
			return nil, &ErrNoTPM{KeyBackend: backendName}
		}
		attrs, err := provider.TPM().IDevIDAttributes()
		if err != nil {
			return nil, &errs.Wrapped{Msg: "clusterca: idevid attributes", Err: err}
		}
		return &tpmKeySigner{tpm: provider.TPM(), attrs: attrs, public: leaf.PublicKey}, nil
	}
	return p.nodeSigner(ctx, backend.KeyProvider())
}

// keyBackendName returns the configured key backend, defaulting to software.
func (p *Provisioner) keyBackendName() string {
	if p.opts.KeyBackend == "" {
		return "software"
	}
	return p.opts.KeyBackend
}

// finishACME assembles the Result and, on the first node of a multi-node
// cluster, starts the anchor-only Noise advertiser.
func (p *Provisioner) finishACME(tlsCert *tls.Certificate, anchorPEM []byte, firstNode bool) (*Result, error) {
	res := &Result{
		MTLS: &qrdbnode.RaftMTLSConfig{
			CACert:      anchorPEM,
			Certificate: tlsCert,
		},
	}
	if firstNode && len(p.opts.Members) > 1 {
		adv, err := clusterenroll.StartAnchorAdvertiser(anchorPEM, p.opts.Advertise, p.opts.DataDir, p.logger)
		if err != nil {
			return nil, err
		}
		res.Advertiser = adv
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// First node
// ---------------------------------------------------------------------------

// provisionFirstNode issues this node's transport certificate in-process
// from the TrustedCA — the running instance when the composition root has
// one, else a bootstrap instance pre-staged from CAConfig — and advertises
// the trust anchor for joiners.
func (p *Provisioner) provisionFirstNode(ctx context.Context) (*Result, error) {
	issuer := p.opts.CA
	if issuer == nil {
		bootstrapCA, err := p.stageBootstrapCA(ctx)
		if err != nil {
			return nil, err
		}
		issuer = bootstrapCA
	}

	anchorPEM, err := issuer.CABundle()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: trust anchor bundle", Err: err}
	}

	// Node transport key on the configured backend (any backend; hardware
	// keys never leave the device).
	backend, err := p.opts.Backends(p.keyBackendName())
	if err != nil {
		return nil, err
	}
	signer, err := p.nodeSigner(ctx, backend.KeyProvider())
	if err != nil {
		return nil, err
	}

	leaf, issuerCert, err := p.issueNodeLeaf(ctx, issuer, signer)
	if err != nil {
		return nil, err
	}

	var chain []*x509.Certificate
	if issuerCert != nil && issuerCert.CheckSignatureFrom(issuerCert) != nil {
		chain = append(chain, issuerCert)
	}
	if err := p.verifyLeafAgainstAnchor(leaf, append(chain, anchorIntermediates(anchorPEM)...), anchorPEM); err != nil {
		return nil, err
	}

	if err := p.cacheIdentity(certsToPEM(append([]*x509.Certificate{leaf}, chain...)...), anchorPEM); err != nil {
		return nil, err
	}

	// When we pre-staged the CA (no running CA was supplied), persist the FULL
	// CA certificate set so the runtime CA can adopt it before Load. The anchor
	// bundle alone is insufficient — Load verifies every configured intermediate,
	// not just the selected issuing one.
	if p.opts.CAConfig != nil {
		if err := p.persistStagedCACerts(ctx, issuer); err != nil {
			return nil, err
		}
	}

	tlsCert, err := signerCertificate(certsToPEM(leaf), chain, signer)
	if err != nil {
		return nil, err
	}

	p.logger.Info("first-node cluster identity issued from TrustedCA",
		"cluster_ca_cn", p.opts.ClusterCACN,
		"key_backend", p.keyBackendName(),
		"spiffe", p.expectedNodeURI())
	return p.finishACME(tlsCert, anchorPEM, true)
}

// issueNodeLeaf builds a CSR over the node key and signs it — from the named
// cluster identity when ClusterCACN is set (and the issuer supports
// per-identity issuance), else the issuer's default issuing identity. The
// certificate carries the SPIFFE node SAN and the key-provenance OID.
func (p *Provisioner) issueNodeLeaf(ctx context.Context, issuer CAIssuer, signer crypto.Signer) (*x509.Certificate, *x509.Certificate, error) {
	nodeURI := p.expectedNodeURI()
	uri, err := url.Parse(nodeURI)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: fmt.Sprintf("clusterca: invalid node URI %q", nodeURI), Err: err}
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: fmt.Sprintf("raft-node-%d", p.opts.NodeID)},
		URIs:    []*url.URL{uri},
	}, signer)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "clusterca: create node CSR", Err: err}
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	opts := &ca.SignOptions{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// Stamp the verified key-provenance OID (tp-keyStore): the CA records
	// where this node's key lives so relying parties can ratchet policy.
	if ext, extErr := ca.CreateTPKeyStoreExtension(p.keyBackendName()); extErr == nil {
		opts.ExtraExtensions = append(opts.ExtraExtensions, ext)
	}

	var issuerCert *x509.Certificate
	if p.opts.ClusterCACN != "" {
		identityIssuer, ok := issuer.(ca.IdentityIssuer)
		if !ok {
			return nil, nil, &ErrMissingOption{Field: "CA (must support per-identity issuance for ClusterCACN)", Mode: "acme first-node"}
		}
		clusterSigner, clusterCert, err := identityIssuer.IssuerForIdentity(ctx, p.opts.ClusterCACN)
		if err != nil {
			return nil, nil, err
		}
		opts.Signer = clusterSigner
		opts.IssuerCert = clusterCert
		issuerCert = clusterCert
	} else if cert, err := issuer.CACertificate(); err == nil {
		issuerCert = cert
	}

	leaf, err := issuer.SignCSR(ctx, csrPEM, opts)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "clusterca: sign node leaf", Err: err}
	}
	return leaf, issuerCert, nil
}

// stageBootstrapCA constructs the TrustedCA from CAConfig over in-memory cert
// and serial stores and initializes it. Init generates the identity keys
// directly into their FINAL keystores (the injected key backend — software /
// TPM / HSM, all persistent) via the CA's own routing, so no key material is
// ever copied. The (public) CA certificates it produces are carried forward
// to the runtime CA through the anchor bundle written to the node cache; the
// runtime CA's initializeCA imports them and Load()s, so Init never runs a
// second time.
//
// The bootstrap cert/serial stores are deliberately in-memory (not disk): the
// node certificate and trust-anchor bundle persist via cacheIdentity, and the
// growth guard below fails closed if a first-boot pre-stage is attempted when
// identity keys already exist — so the persistent state that matters survives
// a restart while the transient bootstrap CA instance does not.
func (p *Provisioner) stageBootstrapCA(ctx context.Context) (ca.TrustedCA, error) {
	if p.opts.CAConfig == nil {
		return nil, &ErrMissingOption{Field: "CAConfig", Mode: "acme first-node"}
	}
	rootIdentity := p.opts.CAConfig.RootIdentity()
	if rootIdentity == nil {
		return nil, &ErrMissingOption{Field: "CAConfig.Identity", Mode: "acme first-node"}
	}

	keystoreBackend, err := p.opts.Backends(string(rootIdentity.GetStoreType()))
	if err != nil {
		return nil, err
	}

	// Guard against forking a second root: identity keys already present with
	// no cached node certificate is the grown-from-standalone shape, which
	// must fail closed (see ErrExistingCAWithoutStagedCerts).
	rootAttrs, err := rootIdentity.ToKeyAttributes()
	if err != nil {
		return nil, err
	}
	if _, err := keystoreBackend.Signer(ctx, rootAttrs); err == nil {
		return nil, &ErrExistingCAWithoutStagedCerts{Identity: rootIdentity.Subject.CommonName}
	}

	stagingCertStore, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(storage.NewMemory()),
	})
	if err != nil {
		return nil, err
	}

	bootstrapCA, err := ca.NewHierarchicalCA(&ca.MultiIdentityParams{
		Config:          p.opts.CAConfig,
		KeyStore:        keystoreBackend,
		CertStore:       stagingCertStore,
		SerialGen:       ca.NewSerialGenerator(ca.NewMemoryStorage()),
		RevocationStore: storage.NewMemory(),
	})
	if err != nil {
		return nil, err
	}
	if err := bootstrapCA.Init(ctx); err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: pre-stage CA init", Err: err}
	}
	p.logger.Info("bootstrap CA pre-staged (keys in final keystores, certs cached for adoption)",
		"identities", len(p.opts.CAConfig.Identity))
	return bootstrapCA, nil
}

// persistStagedCACerts writes the full CA certificate set (root + every
// configured intermediate) from the pre-staged bootstrap CA to
// StagedCACertsPath, for the runtime CA to adopt before Load.
func (p *Provisioner) persistStagedCACerts(ctx context.Context, issuer CAIssuer) error {
	identityIssuer, ok := issuer.(ca.IdentityIssuer)
	if !ok {
		// Cannot enumerate identities; the anchor bundle remains the fallback.
		return nil
	}
	var certs []*x509.Certificate
	for i := range p.opts.CAConfig.Identity {
		cn := p.opts.CAConfig.Identity[i].Subject.CommonName
		_, cert, err := identityIssuer.IssuerForIdentity(ctx, cn)
		if err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("clusterca: collect staged CA cert %q", cn), Err: err}
		}
		certs = append(certs, cert)
	}
	if err := os.MkdirAll(p.opts.DataDir, 0o700); err != nil {
		return err
	}
	// CA certificates are public — the private keys stay in the keystore.
	return os.WriteFile(StagedCACertsPath(p.opts.DataDir), certsToPEM(certs...), 0o644)
}

// ---------------------------------------------------------------------------
// Joining node
// ---------------------------------------------------------------------------

// enrollJoiner fetches the cluster trust anchor via truststrap and obtains
// this node's transport certificate through ACME enroll-01 TPM attestation
// against an existing cluster node.
func (p *Provisioner) enrollJoiner(ctx context.Context) (*Result, error) {
	if p.opts.ACME.DirectoryURL == "" {
		return nil, &ErrMissingOption{Field: "ACME.DirectoryURL", Mode: "acme joiner"}
	}
	backendName := p.keyBackendName()
	if backendName != "tpm2" {
		// The software/pkcs11 CSR enrollment variant is tracked separately;
		// only the TPM-attested path is implemented.
		return nil, &ErrACMEBackendUnsupported{KeyBackend: backendName}
	}

	anchorPEM, err := clusterenroll.FetchAnchor(ctx, p.buildEnrollOptions(), p.logger)
	if err != nil {
		return nil, err
	}

	backend, err := p.opts.Backends(backendName)
	if err != nil {
		return nil, err
	}
	provider, ok := backend.(tpmProvider)
	if !ok {
		return nil, &ErrNoTPM{KeyBackend: backendName}
	}
	tpm := provider.TPM()

	host, _, err := net.SplitHostPort(p.opts.RaftAddress)
	if err != nil {
		host = p.opts.RaftAddress
	}

	client, err := p.newACMEClient(anchorPEM)
	if err != nil {
		return nil, err
	}
	enrollment, err := client.EnrollDevice(ctx, &acmeclient.EnrollmentConfig{
		Challenge: string(acmeclient.ChallengeTypeEnroll01),
		IPAddress: host,
		Port:      p.opts.ACME.ChallengePort,
		TPMModule: acmeclient.NewXKMSTPMAdapter(tpm),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: acme enrollment", Err: err}
	}
	leaf := enrollment.IDevIDCertificate
	if leaf == nil {
		return nil, &ErrAnchorMismatch{Reason: "acme enrollment returned no IDevID certificate"}
	}

	intermediates := anchorIntermediates(anchorPEM)
	if err := p.verifyLeafAgainstAnchor(leaf, intermediates, anchorPEM); err != nil {
		return nil, err
	}

	attrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: idevid attributes", Err: err}
	}
	signer := &tpmKeySigner{tpm: tpm, attrs: attrs, public: leaf.PublicKey}

	if err := p.cacheIdentity(certsToPEM(append([]*x509.Certificate{leaf}, intermediates...)...), anchorPEM); err != nil {
		return nil, err
	}

	tlsCert, err := signerCertificate(certsToPEM(leaf), intermediates, signer)
	if err != nil {
		return nil, err
	}

	p.logger.Info("cluster identity enrolled via ACME enroll-01 TPM attestation",
		"directory_url", p.opts.ACME.DirectoryURL,
		"spiffe", p.expectedNodeURI())
	return p.finishACME(tlsCert, anchorPEM, false)
}

// newACMEClient builds an ACME client that trusts exactly the fetched
// cluster anchor. Account state is ephemeral: the account key is generated
// per enrollment and registration is idempotent server-side.
func (p *Provisioner) newACMEClient(anchorPEM []byte) (*acmeclient.Client, error) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	stateKV, err := kvadapter.New(storage.NewMemory())
	if err != nil {
		return nil, err
	}
	factory, err := acmeobjstore.NewFactoryFromKVStore(stateKV)
	if err != nil {
		return nil, err
	}
	accountDAO, err := factory.AccountDAO()
	if err != nil {
		return nil, err
	}
	return acmeclient.NewClient(&acmeclient.Params{
		AccountSigner: accountKey,
		Config: &acmeclient.Config{
			DirectoryURL:   p.opts.ACME.DirectoryURL,
			SystemCertPool: false,
			TrustedRoots:   []string{string(anchorPEM)},
		},
		Logger:  p.logger,
		Storage: accountDAO,
	})
}

// publicKeysEqual compares two public keys using their Equal method.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if ae, ok := a.(equaler); ok {
		return ae.Equal(b)
	}
	return false
}
