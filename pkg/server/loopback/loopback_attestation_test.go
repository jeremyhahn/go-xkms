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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

// attestationWorkflowConfig is the loopback launch config with a first-boot
// root CA. Authentication is always on, so the embedded node serves its data
// plane, the Verifier's store included, only once first boot has issued and
// bound the bootstrap admin's certificate from the CA.
func attestationWorkflowConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := minimalLoopbackConfig(t)
	cfg.CA = &ca.MultiIdentityCAConfig{
		SelectedCA:          0,
		DefaultValidityDays: 365,
		Identity: []ca.Identity{{
			IsRoot:  true,
			Valid:   1,
			Subject: ca.Subject{CommonName: "loopback test root CA", Organization: "go-xkms", Country: "US"},
			Keys: []*types.KeyConfig{{
				KeyAlgorithm: types.AlgorithmECDSA,
				ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
			}},
		}},
	}
	return cfg
}

// TestLaunch_ServesTheAttestationAppraisalWorkflow proves a normally composed
// engine (server.New, no test-only SetAttestationAppraiser) serves the
// attestation Verifier over its real datastore: the trust anchors and signed
// reference values are stored and listed, genuine TPM evidence appraises as
// Verified, and tampered evidence is refused.
func TestLaunch_ServesTheAttestationAppraisalWorkflow(t *testing.T) {
	inst, err := Launch(context.Background(), Options{Config: attestationWorkflowConfig(t)})
	require.NoError(t, err, "Launch")
	t.Cleanup(func() { _ = inst.Close(context.Background()) })
	client := attestationHTTPClient(t, inst)
	ctx := context.Background()

	pcrs := appraisaltest.PCRValues(0, 4, 7)
	akCA, err := appraisaltest.NewAuthority("loopback AK CA")
	require.NoError(t, err)
	rvCA, err := appraisaltest.NewAuthority("loopback Reference Value CA")
	require.NoError(t, err)
	ak, err := appraisaltest.IssueAttestationKey(akCA, true)
	require.NoError(t, err)
	signerCert, signerKey, err := appraisaltest.SignerUnder(rvCA)
	require.NoError(t, err)
	corim, err := appraisaltest.SignCoRIM(pcrs, signerKey, []*x509.Certificate{signerCert})
	require.NoError(t, err)

	put, err := client.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{
		Name: "ak-ca", Kind: appraisal.EndorsementAKRoot, CertificatePEM: akCA.CertificatePEM(),
	})
	require.NoError(t, err, "endorsement add (ak-ca)")
	require.Equal(t, "ak-ca", put.Name)
	_, err = client.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{
		Name: "rv-ca", Kind: appraisal.EndorsementReferenceSigner, CertificatePEM: rvCA.CertificatePEM(),
	})
	require.NoError(t, err, "endorsement add (rv-ca)")

	list, err := client.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
	require.NoError(t, err, "endorsement list")
	names := make([]string, 0, len(list.Endorsements))
	for _, e := range list.Endorsements {
		names = append(names, e.Name)
	}
	require.ElementsMatch(t, []string{"ak-ca", "rv-ca"}, names)

	rv, err := client.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{
		Name: "golden", SignedCoRIM: corim,
	})
	require.NoError(t, err, "reference-value add")
	require.Equal(t, "golden", rv.Name)
	require.Equal(t, []uint32{0, 4, 7}, rv.PCRIndices)

	rvList, err := client.ListAttestationReferenceValues(ctx)
	require.NoError(t, err, "reference-value list")
	require.Len(t, rvList.ReferenceValues, 1)
	require.Equal(t, "golden", rvList.ReferenceValues[0].Name)

	nonce := []byte("loopback-attestation-nonce-00000")
	quote, err := appraisaltest.SignQuote(ak, pcrs, nonce)
	require.NoError(t, err)
	genuine := &transport.AppraiseAttestationQuoteRequest{
		AKCertificatePEM: ak.CertificatePEM(),
		Quote:            quote.Attest,
		Signature:        quote.Signature,
		Nonce:            nonce,
		PCRs:             pcrs,
		ReferenceValues:  "golden",
	}
	result, err := client.AppraiseAttestationQuote(ctx, genuine)
	require.NoError(t, err, "appraise genuine evidence")
	require.True(t, result.Verified, "genuine evidence must appraise as verified: %+v", result)
	require.NotEmpty(t, result.Checks)

	tamperedPCRs := make(map[uint32][]byte, len(pcrs))
	for i, v := range pcrs {
		tamperedPCRs[i] = bytes.Clone(v)
	}
	tamperedPCRs[7][0] ^= 0xff
	tampered := *genuine
	tampered.PCRs = tamperedPCRs
	refused, err := client.AppraiseAttestationQuote(ctx, &tampered)
	require.NoError(t, err, "appraise tampered evidence")
	require.False(t, refused.Verified, "tampered PCR values must not appraise as verified")
}
