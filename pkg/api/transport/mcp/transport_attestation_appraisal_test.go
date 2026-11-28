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

package mcp

import (
	"context"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// appraisalCalls returns one call per attestation appraisal method, keyed by
// the MCP tool it must reach.
func appraisalCalls(ctx context.Context, svc transport.AttestationAppraisalService) map[string]func() error {
	return map[string]func() error{
		"attestation.endorsement.put": func() error {
			_, err := svc.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{Name: "root"})
			return err
		},
		"attestation.endorsement.list": func() error {
			_, err := svc.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
			return err
		},
		"attestation.endorsement.delete": func() error {
			return svc.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "root"})
		},
		"attestation.reference_values.put": func() error {
			_, err := svc.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "golden"})
			return err
		},
		"attestation.reference_values.get": func() error {
			_, err := svc.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "golden"})
			return err
		},
		"attestation.reference_values.list": func() error {
			_, err := svc.ListAttestationReferenceValues(ctx)
			return err
		},
		"attestation.reference_values.delete": func() error {
			return svc.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "golden"})
		},
		"attestation.appraise": func() error {
			_, err := svc.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: "golden"})
			return err
		},
		"attestation.appraise.android_key": func() error {
			_, err := svc.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: [][]byte{{0x30}}})
			return err
		},
		"attestation.appraise.ek_certificate": func() error {
			_, err := svc.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{CertificateDER: []byte{0x30}})
			return err
		},
	}
}

// TestAttestationAppraisal_CallsTheTool proves every appraisal method reaches
// its attestation.* tool.
func TestAttestationAppraisal_CallsTheTool(t *testing.T) {
	var mu sync.Mutex
	var last string
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			return jsonrpcResponse{Result: []byte(`{"status":"ok"}`)}
		}
		mu.Lock()
		last = req.Method
		mu.Unlock()
		return jsonrpcResponse{Result: []byte(`{}`)}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	for tool, call := range appraisalCalls(context.Background(), tr) {
		t.Run(tool, func(t *testing.T) {
			assert.NoError(t, call())
			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, tool, last)
		})
	}
}

// TestAttestationAppraisal_ServerRefusal surfaces the server's refusal.
func TestAttestationAppraisal_ServerRefusal(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			return jsonrpcResponse{Result: []byte(`{"status":"ok"}`)}
		}
		return jsonrpcResponse{ErrorText: "validation failed: invalid name", Envelope: qrdbsdk.MCPCodeInvalidArgument}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	for tool, call := range appraisalCalls(context.Background(), tr) {
		t.Run(tool, func(t *testing.T) { assert.ErrorContains(t, call(), "invalid name") })
	}
}

// TestAttestationAppraisal_NotConnected refuses every method before dialing.
func TestAttestationAppraisal_NotConnected(t *testing.T) {
	for tool, call := range appraisalCalls(context.Background(), &Transport{}) {
		t.Run(tool, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
