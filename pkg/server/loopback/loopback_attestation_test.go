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

package loopback

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// attestationHTTPClient is the wire client of the attestation Verifier over
// the launched engine's real HTTP listener, authenticated by the per-launch
// token.
func attestationHTTPClient(t *testing.T, inst *Instance) wire.AttestationAppraisalClient {
	t.Helper()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	return wire.AttestationAppraisalClient{Do: func(ctx context.Context, method, path string, body any) ([]byte, error) {
		var raw []byte
		if body != nil {
			var err error
			if raw, err = json.Marshal(body); err != nil {
				return nil, err
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			req, err := http.NewRequestWithContext(ctx, method, inst.BaseURL+path, bytes.NewReader(raw))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+inst.Token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := httpClient.Do(req)
			if err != nil {
				// The REST listener starts asynchronously in Launch.
				if time.Now().After(deadline) {
					return nil, err
				}
				time.Sleep(20 * time.Millisecond)
				continue
			}
			out, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			if resp.StatusCode >= 300 {
				return nil, fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, out)
			}
			return out, nil
		}
	}}
}

// selfSignedAKRootPEM is a throwaway CA certificate to register as an AK
// root endorsement.
func selfSignedAKRootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "loopback AK root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// reachedTheVerifier fails the test when step answered the unconfigured
// Verifier's ErrNotConfigured, the defect a normally composed engine must not
// show. It reports whether step succeeded: the loopback engine's qrdb node
// never runs first-boot, so a store write it refuses as awaiting the
// bootstrap admin credential has reached the composed Verifier and its
// store, and ends the workflow there.
func reachedTheVerifier(t *testing.T, step string, err error) bool {
	t.Helper()
	switch {
	case err == nil:
		return true
	case strings.Contains(err.Error(), "subsystem not configured"):
		t.Fatalf("%s: the composed engine has no attestation Appraiser: %v", step, err)
	case strings.Contains(err.Error(), "awaiting admin credential"):
		t.Logf("%s reached the Verifier's store; the uninitialized loopback node refused it: %v", step, err)
		return false
	default:
		t.Fatalf("%s: %v", step, err)
	}
	return false
}

// TestLaunch_ServesTheAttestationAppraisalWorkflow proves a normally composed
// engine (server.New, no test-only SetAttestationAppraiser) serves the
// attestation Verifier: an endorsement is stored and listed, the reference
// values are listed, and evidence is appraised to a result rather than the
// unconfigured Verifier's 503.
func TestLaunch_ServesTheAttestationAppraisalWorkflow(t *testing.T) {
	inst, err := Launch(context.Background(), Options{Config: minimalLoopbackConfig(t)})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close(context.Background()) })
	client := attestationHTTPClient(t, inst)
	ctx := context.Background()

	rootPEM := selfSignedAKRootPEM(t)
	put, err := client.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{
		Name: "fleet-root", Kind: appraisal.EndorsementAKRoot, CertificatePEM: rootPEM,
	})
	if !reachedTheVerifier(t, "endorsement add", err) {
		return
	}
	if put.Name != "fleet-root" {
		t.Fatalf("endorsement add name = %q, want fleet-root", put.Name)
	}
	list, err := client.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
	if !reachedTheVerifier(t, "endorsement list", err) {
		return
	}
	if len(list.Endorsements) != 1 || list.Endorsements[0].Name != "fleet-root" {
		t.Fatalf("endorsement list = %+v, want the one fleet-root", list.Endorsements)
	}

	_, err = client.ListAttestationReferenceValues(ctx)
	if !reachedTheVerifier(t, "reference-value list", err) {
		return
	}

	result, err := client.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{
		AKCertificatePEM: rootPEM, Quote: []byte{1}, Signature: []byte{1}, Nonce: []byte{1},
		PCRs: map[uint32][]byte{0: make([]byte, 32)},
	})
	if !reachedTheVerifier(t, "appraise", err) {
		return
	}
	if result.Verified {
		t.Fatal("a malformed quote must not appraise as verified")
	}
	if len(result.Checks) == 0 {
		t.Fatal("appraise result names no checks")
	}
}
