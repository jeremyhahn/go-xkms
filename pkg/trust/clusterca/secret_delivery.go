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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// SecretDeliveryPath is the HTTP path a node POSTs to, after it has enrolled and
// holds a cluster-CA-signed transport cert, to fetch any wrapped provisioning
// material a custody strategy has for it (e.g. the tpm-kek cluster seed). It
// mirrors the post-enrollment device-config fetch pattern: authenticated by the
// node's just-issued cert over mTLS, the material additionally wrapped to the
// node's TPM.
const SecretDeliveryPath = "/api/v1/cluster/secret"

// Secret delivery errors.
var (
	ErrNoNodeIdentity   = errors.New("clusterca: secret delivery requires an authenticated node client certificate")
	ErrMalformedRequest = errors.New("clusterca: malformed secret-delivery request")
)

// secretDeliveryRequest is the joiner→server body: its just-issued cluster CA
// node certificate (for authorization) plus the TPM attestation material a
// provider wraps material to.
type secretDeliveryRequest struct {
	// NodeCertificatePEM is the requesting node's cluster-CA-signed transport
	// certificate (issued by enroll-01). The service verifies it chains to the
	// cluster CA and takes the authoritative node identity from its SPIFFE SAN.
	NodeCertificatePEM []byte `json:"node_certificate_pem"`
	// EKCertificatePEM is the node's TPM EK certificate.
	EKCertificatePEM []byte `json:"ek_certificate_pem"`
	// IAKPublic is the marshaled public area of the node's attestation key.
	IAKPublic []byte `json:"iak_public"`
}

// secretDeliveryResponse is the server→joiner body: the wrapped material.
type secretDeliveryResponse struct {
	Secrets []*ProvisionedSecret `json:"secrets"`
}

// SecretDeliveryService orchestrates the registered NodeSecretProviders. It is
// the decoupled heart of the post-enrollment fetch: it knows only about generic
// providers, never about seeds or KEKs, so any custody strategy plugs in. It is
// reusable by every product (xkmsd, quicbaasd, trusted-platform) — each mounts
// Handler on its server surface and wires the strategy's provider.
type SecretDeliveryService struct {
	providers  []NodeSecretProvider
	clusterCAs *x509.CertPool
	logger     *slog.Logger
}

// NewSecretDeliveryService builds a delivery service over the given providers
// (nil entries are ignored). clusterCAs is the pool the requesting node's
// certificate is verified against; when nil, node-certificate verification is
// skipped (the credential-activation wrapping still guarantees only the target
// TPM can use the material) — supply it in production for authorization.
func NewSecretDeliveryService(logger *slog.Logger, clusterCAs *x509.CertPool, providers ...NodeSecretProvider) *SecretDeliveryService {
	if logger == nil {
		logger = slog.Default()
	}
	out := make([]NodeSecretProvider, 0, len(providers))
	for _, p := range providers {
		if p != nil {
			out = append(out, p)
		}
	}
	return &SecretDeliveryService{providers: out, clusterCAs: clusterCAs, logger: logger}
}

// HasProviders reports whether any provider is registered — the composition root
// mounts the HTTP handler only when true.
func (s *SecretDeliveryService) HasProviders() bool { return len(s.providers) > 0 }

// Deliver runs every registered provider for the requesting node and returns the
// non-empty wrapped material. It is pure orchestration (no transport), so it is
// unit-testable without HTTP.
func (s *SecretDeliveryService) Deliver(ctx context.Context, req *NodeSecretRequest) ([]*ProvisionedSecret, error) {
	var secrets []*ProvisionedSecret
	for _, p := range s.providers {
		secret, err := p.ProvisionFor(ctx, req)
		if err != nil {
			return nil, err
		}
		if secret != nil {
			secrets = append(secrets, secret)
		}
	}
	return secrets, nil
}

// Handler returns the HTTP handler serving SecretDeliveryPath. The requesting
// node is authorized by the cluster-CA-signed node certificate in its request
// body (verified against the configured cluster CA pool); its SPIFFE identity is
// taken from that certificate's URI SAN. The delivered material is additionally
// wrapped to the node's TPM (credential activation), so confidentiality holds
// even independent of transport security.
func (s *SecretDeliveryService) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body secretDeliveryRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, ErrMalformedRequest.Error(), http.StatusBadRequest)
			return
		}

		// Authorize: the requesting node must present a valid cluster-CA-signed
		// certificate; its SPIFFE SAN is the authoritative node identity.
		nodeCert, err := s.verifyNodeCert(body.NodeCertificatePEM)
		if err != nil {
			http.Error(w, ErrNoNodeIdentity.Error(), http.StatusUnauthorized)
			return
		}
		nodeURI := nodeURIFromCert(nodeCert)
		if nodeURI == "" {
			http.Error(w, ErrNoNodeIdentity.Error(), http.StatusUnauthorized)
			return
		}

		ekCert, err := parseEKCertPEM(body.EKCertificatePEM)
		if err != nil {
			http.Error(w, ErrMalformedRequest.Error(), http.StatusBadRequest)
			return
		}

		secrets, err := s.Deliver(r.Context(), &NodeSecretRequest{
			NodeURI:       nodeURI,
			EKCertificate: ekCert,
			IAKPublic:     body.IAKPublic,
		})
		if err != nil {
			s.logger.Error("cluster secret delivery failed", "node", nodeURI, "error", err.Error())
			http.Error(w, "secret provisioning failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&secretDeliveryResponse{Secrets: secrets})
	}
}

// FetchClusterSecrets is the joiner-side client: after enrollment it POSTs its
// just-issued node certificate (for authorization) and TPM attestation material
// to an existing node's delivery endpoint and returns the wrapped material to
// hand to its strategy's ConsumeEnrollmentSecret.
func FetchClusterSecrets(ctx context.Context, httpClient *http.Client, baseURL string, nodeCertPEM, ekCertPEM, iakPublic []byte) ([]*ProvisionedSecret, error) {
	body, err := json.Marshal(&secretDeliveryRequest{
		NodeCertificatePEM: nodeCertPEM,
		EKCertificatePEM:   ekCertPEM,
		IAKPublic:          iakPublic,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+SecretDeliveryPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Debug("clusterca: failed to close HTTP response body", "error", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, &errs.Message{Msg: fmt.Sprintf("clusterca: secret delivery returned status %d", resp.StatusCode)}
	}
	var out secretDeliveryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Secrets, nil
}

// verifyNodeCert parses the requesting node's certificate and, when a cluster CA
// pool is configured, verifies it chains to the cluster CA. Returns the leaf.
func (s *SecretDeliveryService) verifyNodeCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoNodeIdentity
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if s.clusterCAs != nil {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     s.clusterCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return nil, err
		}
	}
	return cert, nil
}

// nodeURIFromCert returns the first SPIFFE URI SAN of a node certificate.
func nodeURIFromCert(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if u != nil {
			return u.String()
		}
	}
	return ""
}

// parseEKCertPEM decodes a PEM-encoded EK certificate.
func parseEKCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrMalformedRequest
	}
	return x509.ParseCertificate(block.Bytes)
}
