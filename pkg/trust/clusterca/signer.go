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
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpmstore "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// nodeSigner returns the crypto.Signer for this node's transport key on the
// given provider, reusing an existing key across restarts and generating an
// ECDSA P-256 signing key on first boot. For hardware backends the private
// key is generated inside and never leaves the device.
func (p *Provisioner) nodeSigner(ctx context.Context, kp types.KeyProvider) (crypto.Signer, error) {
	attrs := p.nodeKeyAttributes(kp)
	// Reuse the key if it already exists (restart); otherwise generate it.
	if signer, err := kp.Signer(ctx, attrs); err == nil {
		return signer, nil
	}
	if _, err := kp.GenerateKey(ctx, attrs); err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: generate node key", Err: err}
	}
	signer, err := kp.Signer(ctx, attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: node signer", Err: err}
	}
	return signer, nil
}

// nodeKeyAttributes names this node's transport key on the key provider.
func (p *Provisioner) nodeKeyAttributes(kp types.KeyProvider) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            fmt.Sprintf("raft-node-%d", p.opts.NodeID),
		StoreType:     types.ParseStoreType(string(kp.Type())),
		KeyType:       types.KeyTypeSigning,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
}

// idevidSigner returns the signer for the TPM-resident IDevID key, the
// transport key of a node that joined through ACME enroll-01. Its public key
// is read from the TPM, so a comparison against a certificate checks the key
// TLS signs with.
func idevidSigner(backend xkms.Backend, keyBackend string) (crypto.Signer, error) {
	provider, ok := backend.(tpmProvider)
	if !ok {
		return nil, &ErrNoTPM{KeyBackend: keyBackend}
	}
	tpm := provider.TPM()
	attrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: idevid attributes", Err: err}
	}
	public, err := tpm.IDevID()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: idevid public key", Err: err}
	}
	return &tpmKeySigner{tpm: tpm, attrs: attrs, public: public}, nil
}

// signerCertificate assembles a tls.Certificate from the node leaf PEM (plus
// optional intermediate chain) and a backend-held signer. The signer — not
// exportable key bytes — drives all TLS handshake signatures, so a
// hardware-resident private key never leaves the device.
func signerCertificate(leafPEM []byte, chain []*x509.Certificate, signer crypto.Signer) (*tls.Certificate, error) {
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return nil, &ErrLeafDecode{}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: parse node leaf", Err: err}
	}
	certDER := [][]byte{block.Bytes}
	for _, c := range chain {
		certDER = append(certDER, c.Raw)
	}
	return &tls.Certificate{
		Certificate: certDER,
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}

// tpmKeySigner is a crypto.Signer over a TPM-resident key identified by its
// key attributes (e.g. the IDevID key certified during enroll-01). Signing is
// delegated to the TPM; the private key never leaves the device.
type tpmKeySigner struct {
	tpm    pkgtpm2.TrustedPlatformModule
	attrs  *types.KeyAttributes
	public crypto.PublicKey
}

// Public returns the public key corresponding to the TPM-resident key.
func (s *tpmKeySigner) Public() crypto.PublicKey { return s.public }

// Sign signs digest in the TPM using the key identified by the attributes.
func (s *tpmKeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.tpm.Sign(rand, digest, &tpmstore.SignerOpts{KeyAttributes: s.attrs})
}
