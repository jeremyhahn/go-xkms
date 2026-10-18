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
	"net/url"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	acmeclient "github.com/jeremyhahn/go-xkms/pkg/acme/client"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tpmProvider is the surface a backend must expose for enroll-01: access to
// the underlying TrustedPlatformModule and to the store its key blobs live
// in. The tpm2 backend satisfies it.
type tpmProvider interface {
	TPM() pkgtpm2.TrustedPlatformModule
	KeyBackend() store.KeyBackend
}

// provisionTrustedCA resolves the node identity issued by the TrustedCA, in
// ACME-attested and local-CA mode: cached material when still valid,
// otherwise first-node in-process issuance or (ACME only) joiner enrollment.
func (p *Provisioner) provisionTrustedCA(ctx context.Context) (*Result, error) {
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

	signer, err := p.cachedNodeSigner(ctx)
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
	return p.finishACME(tlsCert, anchorPEM)
}

// cachedNodeSigner restores the signer for the transport key a cached leaf was
// issued for, the same key provisioning used: the TPM-resident IDevID key of a
// node that joined through ACME enroll-01 (enrollJoiner), otherwise the named
// node key on the configured backend (provisionFirstNode). It only loads the
// key; a missing key fails rather than generating a new one.
func (p *Provisioner) cachedNodeSigner(ctx context.Context) (crypto.Signer, error) {
	backend, err := p.nodeKeyBackend()
	if err != nil {
		return nil, err
	}
	if p.opts.Bootstrap.HasFlags() {
		return idevidSigner(backend, p.keyBackendName())
	}
	kp := backend.KeyProvider()
	signer, err := kp.Signer(ctx, p.nodeKeyAttributes(kp))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: node signer", Err: err}
	}
	return signer, nil
}

// keyBackendName returns the configured key backend, defaulting to software.
func (p *Provisioner) keyBackendName() string {
	if p.opts.KeyBackend == "" {
		return "software"
	}
	return p.opts.KeyBackend
}

// nodeKeyBackend resolves the backend that holds the node transport key.
func (p *Provisioner) nodeKeyBackend() (xkms.Backend, error) {
	name := p.keyBackendName()
	backend, err := p.opts.NodeKeyBackends(name)
	if err != nil {
		return nil, &ErrKeyBackendUnavailable{KeyBackend: name, Err: err}
	}
	return backend, nil
}

// resolveBackend resolves a named key backend through the Backends seam,
// failing with ErrKeyBackendUnavailable when the seam cannot supply it.
func (p *Provisioner) resolveBackend(name string) (xkms.Backend, error) {
	backend, err := p.opts.Backends(name)
	if err != nil {
		return nil, &ErrKeyBackendUnavailable{KeyBackend: name, Err: err}
	}
	return backend, nil
}

// firstNodeMode names the first-node issuance mode for error reports:
// ACME-attested, or local-CA when ACME is not configured.
func (p *Provisioner) firstNodeMode() string {
	if p.opts.ACME == nil {
		return localCAMode
	}
	return "acme first-node"
}

// finishACME assembles the Result and, on the founding node of a multi-node
// cluster, starts the anchor-only Noise advertiser, on first issuance and on a
// cached restart alike.
func (p *Provisioner) finishACME(tlsCert *tls.Certificate, anchorPEM []byte) (*Result, error) {
	res := &Result{
		MTLS: &qrdbnode.RaftMTLSConfig{
			CACert:      anchorPEM,
			Certificate: tlsCert,
		},
	}
	if p.advertisesAnchor() {
		adv, err := clusterenroll.StartAnchorAdvertiser(anchorPEM, p.opts.Advertise, p.opts.DataDir, p.logger)
		if err != nil {
			return nil, err
		}
		res.Advertiser = adv
	}
	return res, nil
}

// advertisesAnchor reports whether this node serves the trust anchor to
// joiners: the founding node (no join-side bootstrap flags) of a multi-member
// cluster. It follows the node's role, not whether the identity was just
// issued, so a founding node advertises again when it restarts on its cached
// identity.
func (p *Provisioner) advertisesAnchor() bool {
	return !p.opts.Bootstrap.HasFlags() && len(p.opts.Members) > 1
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
	backend, err := p.nodeKeyBackend()
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
	return p.finishACME(tlsCert, anchorPEM)
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

	// The node's transport certificate belongs to the system tenant.
	opts := &ca.SignOptions{
		TenantID:    qrdbsdk.SystemTenantID,
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
			return nil, nil, &ErrMissingOption{Field: "CA (must support per-identity issuance for ClusterCACN)", Mode: p.firstNodeMode()}
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
func (p *Provisioner) stageBootstrapCA(ctx context.Context) (CAIssuer, error) {
	if p.opts.CAConfig == nil {
		return nil, &ErrMissingOption{Field: "CAConfig", Mode: p.firstNodeMode()}
	}
	rootIdentity := p.opts.CAConfig.RootIdentity()
	if rootIdentity == nil {
		return nil, &ErrMissingOption{Field: "CAConfig.Identity", Mode: p.firstNodeMode()}
	}

	keystoreBackend, err := p.resolveBackend(string(rootIdentity.GetStoreType()))
	if err != nil {
		return nil, err
	}

	// Guard against forking a second root: identity keys already present with
	// no cached node certificate is the grown-from-standalone shape, which
	// must fail closed (see ErrExistingCAWithoutStagedCerts).
	rootAttrs, err := rootIdentity.ToKeyAttributes(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := keystoreBackend.Signer(ctx, rootAttrs); err == nil {
		return nil, &ErrExistingCAWithoutStagedCerts{Identity: rootIdentity.Subject.CommonName}
	}

	stagingCertStore, err := certstore.New(&certstore.Config{
		DAOs: dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore()),
	})
	if err != nil {
		return nil, err
	}

	// p.opts.Backends resolves a key backend by name, and the StoreType names
	// line up with those backend names (software, tpm2, ...), so it doubles
	// as the per-StoreType resolver every CA signing key is routed through.
	backendForStore := func(cn string, st types.StoreType) (xkms.Backend, error) {
		return p.resolveBackend(string(st))
	}

	bootstrapCA, err := ca.NewHierarchicalCA(&ca.MultiIdentityParams{
		Config:          p.opts.CAConfig,
		KeyStore:        keystoreBackend,
		CertStore:       stagingCertStore,
		SerialGen:       ca.NewSerialGenerator(ca.NewMemoryStorage()),
		RevocationStore: storage.NewMemory(),
		BackendForStore: backendForStore,
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
	return os.WriteFile(StagedCACertsPath(p.opts.DataDir), certsToPEM(certs...), 0o644) // #nosec G306 - CA certificates are public
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
		// Not a missing code path: the cluster CA's ACME server offers only
		// TPM-attested challenges (enroll-01/endorse-01/device-attest-01) for
		// the IP/permanent-identifier authorization a joining node presents,
		// and none of them is satisfiable without a real TPM. See
		// ErrACMEBackendUnsupported's doc comment for the security property
		// this loses and the join modes that do not require it.
		return nil, &ErrACMEBackendUnsupported{KeyBackend: backendName}
	}

	anchorPEM, err := clusterenroll.FetchAnchor(ctx, p.buildEnrollOptions(), p.logger)
	if err != nil {
		return nil, err
	}

	backend, err := p.nodeKeyBackend()
	if err != nil {
		return nil, err
	}
	provider, ok := backend.(tpmProvider)
	if !ok {
		return nil, &ErrNoTPM{KeyBackend: backendName}
	}
	tpm := provider.TPM()

	client, err := p.newACMEClient(anchorPEM)
	if err != nil {
		return nil, err
	}
	// The permanent-identifier is the full Raft address: it is the node ID
	// the cluster CA stamps into spiffe://<td>/node/<id> once it finds the
	// address in its membership, and the server dials only its host, on the
	// challenge port.
	enrollment, err := client.EnrollDevice(ctx, &acmeclient.EnrollmentConfig{
		Challenge:  string(acmeclient.ChallengeTypeEnroll01),
		IPAddress:  p.opts.RaftAddress,
		Port:       p.opts.ACME.ChallengePort,
		ListenHost: p.opts.ACME.ChallengeHost,
		TPMModule:  acmeclient.NewXKMSTPMAdapter(tpm, provider.KeyBackend()),
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

	signer, err := idevidSigner(backend, backendName)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(leaf.PublicKey, signer.Public()) {
		return nil, &ErrAnchorMismatch{Reason: "acme enrollment certificate public key does not match the TPM IDevID key"}
	}

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
	return p.finishACME(tlsCert, anchorPEM)
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
