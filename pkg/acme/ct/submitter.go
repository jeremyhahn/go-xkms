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

package ct

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// HTTPLogSubmitter implements LogSubmitter using HTTP.
type HTTPLogSubmitter struct {
	client *http.Client
}

// NewHTTPLogSubmitter creates a new HTTP-based CT log submitter.
func NewHTTPLogSubmitter(client *http.Client) *HTTPLogSubmitter {
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return &HTTPLogSubmitter{client: client}
}

// addPrecertChainRequest is the request format for add-pre-chain endpoint.
type addPrecertChainRequest struct {
	Chain []string `json:"chain"`
}

// addPrecertChainResponse is the response format from add-pre-chain endpoint.
type addPrecertChainResponse struct {
	SCTVersion Version `json:"sct_version"`
	ID         string  `json:"id"`
	Timestamp  uint64  `json:"timestamp"`
	Extensions string  `json:"extensions"`
	Signature  string  `json:"signature"`
}

// SubmitPrecert submits a precertificate to a CT log.
func (s *HTTPLogSubmitter) SubmitPrecert(ctx context.Context, precertDER []byte, chain [][]byte, log LogGroup) (*SignedCertificateTimestamp, error) {
	// Refuse a log whose SCTs could not be verified before submitting to it.
	if err := checkLogPublicKey(log.PublicKey); err != nil {
		return nil, NewLogConfigError(log, err)
	}

	// Build the chain (precert + issuing chain)
	fullChain := make([]string, 0, len(chain)+1)
	fullChain = append(fullChain, base64.StdEncoding.EncodeToString(precertDER))
	for _, cert := range chain {
		fullChain = append(fullChain, base64.StdEncoding.EncodeToString(cert))
	}

	// Create request
	reqBody := addPrecertChainRequest{Chain: fullChain}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, caerrors.SerializationFailureError("ct: log submission failed: marshaling request: %v", err)
	}

	// Build URL
	url := log.URL
	if url[len(url)-1] != '/' {
		url += "/"
	}
	url += "ct/v1/add-pre-chain"

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, caerrors.ConnectionFailureError("ct: log submission failed: creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &errs.Joined{Lead: ErrCTSubmissionTimeout, Cause: ctx.Err()}
		}
		return nil, caerrors.ConnectionFailureError("ct: log submission failed: sending request: %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("ct: failed to close response body", slog.String("error", closeErr.Error()))
		}
	}()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("ct: log submission failed: reading response: %v", err)
	}

	// Check status
	if resp.StatusCode != http.StatusOK {
		return nil, caerrors.ConnectionFailureError("ct: log submission failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var sctResp addPrecertChainResponse
	if err := json.Unmarshal(body, &sctResp); err != nil {
		return nil, caerrors.SerializationFailureError("ct: log submission failed: parsing response: %v", err)
	}

	sct, err := s.responseToSCT(&sctResp, log)
	if err != nil {
		return nil, err
	}

	// RFC 6962 §3.2: verify the SCT's signature over the precert_entry
	// before relying on it.
	if err := VerifySCT(sct, log, precertDER, chain); err != nil {
		return nil, err
	}
	return sct, nil
}

// responseToSCT converts the API response to an SCT.
func (s *HTTPLogSubmitter) responseToSCT(resp *addPrecertChainResponse, log LogGroup) (*SignedCertificateTimestamp, error) {
	sct := &SignedCertificateTimestamp{
		Version:   resp.SCTVersion,
		Timestamp: resp.Timestamp,
	}

	// Decode log ID
	idBytes, err := base64.StdEncoding.DecodeString(resp.ID)
	if err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: decoding log ID: %v", err)
	}
	if len(idBytes) != 32 {
		return nil, caerrors.MalformedError("SCT decoding failed: invalid log ID length: %d", len(idBytes))
	}
	copy(sct.LogID[:], idBytes)

	// Decode extensions
	if resp.Extensions != "" {
		sct.Extensions, err = base64.StdEncoding.DecodeString(resp.Extensions)
		if err != nil {
			return nil, caerrors.SerializationFailureError("SCT decoding failed: decoding extensions: %v", err)
		}
	}

	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: decoding signature: %v", err)
	}

	// Parse signature structure
	if len(sigBytes) < 4 {
		return nil, caerrors.MalformedError("SCT decoding failed: signature too short")
	}

	sct.Signature.HashAlgorithm = HashAlgorithm(sigBytes[0])
	sct.Signature.SigAlgorithm = SignatureAlgorithm(sigBytes[1])

	sigLen := int(sigBytes[2])<<8 | int(sigBytes[3])
	if len(sigBytes) < 4+sigLen {
		return nil, caerrors.MalformedError("SCT decoding failed: signature data incomplete")
	}
	sct.Signature.Signature = sigBytes[4 : 4+sigLen]

	return sct, nil
}
