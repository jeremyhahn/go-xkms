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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
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
func (s *HTTPLogSubmitter) SubmitPrecert(ctx interface{}, precertDER []byte, chain [][]byte, log LogGroup) (*SignedCertificateTimestamp, error) {
	goCtx, ok := ctx.(context.Context)
	if !ok {
		return nil, caerrors.MalformedError("ct: log submission failed: invalid context type")
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
	req, err := http.NewRequestWithContext(goCtx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, caerrors.ConnectionFailureError("ct: log submission failed: creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
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

	// Convert to SCT
	return s.responseToSCT(&sctResp, log)
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

// MockLogSubmitter implements LogSubmitter for testing.
type MockLogSubmitter struct {
	// SCTs maps log URL to the SCT that should be returned.
	SCTs map[string]*SignedCertificateTimestamp

	// Errors maps log URL to the error that should be returned.
	Errors map[string]error

	// Delay is the simulated submission delay.
	Delay time.Duration

	// Submissions tracks all submission attempts.
	Submissions []MockSubmission

	mu sync.Mutex
}

// MockSubmission records a submission attempt.
type MockSubmission struct {
	PrecertDER []byte
	Chain      [][]byte
	Log        LogGroup
	Timestamp  time.Time
}

// NewMockLogSubmitter creates a new mock log submitter.
func NewMockLogSubmitter() *MockLogSubmitter {
	return &MockLogSubmitter{
		SCTs:   make(map[string]*SignedCertificateTimestamp),
		Errors: make(map[string]error),
	}
}

// SubmitPrecert implements LogSubmitter for testing.
func (m *MockLogSubmitter) SubmitPrecert(ctx interface{}, precertDER []byte, chain [][]byte, log LogGroup) (*SignedCertificateTimestamp, error) {
	goCtx, ok := ctx.(context.Context)
	if !ok {
		return nil, caerrors.MalformedError("ct: log submission failed: invalid context type")
	}

	// Record submission
	m.mu.Lock()
	m.Submissions = append(m.Submissions, MockSubmission{
		PrecertDER: precertDER,
		Chain:      chain,
		Log:        log,
		Timestamp:  time.Now(),
	})
	m.mu.Unlock()

	// Simulate delay
	if m.Delay > 0 {
		select {
		case <-goCtx.Done():
			return nil, goCtx.Err()
		case <-time.After(m.Delay):
		}
	}

	// Check for error
	if err, ok := m.Errors[log.URL]; ok {
		return nil, err
	}

	// Return configured SCT or generate one
	if sct, ok := m.SCTs[log.URL]; ok {
		return sct, nil
	}

	// Generate a mock SCT
	return m.generateMockSCT(precertDER, log), nil
}

// generateMockSCT creates a mock SCT for testing.
func (m *MockLogSubmitter) generateMockSCT(precertDER []byte, log LogGroup) *SignedCertificateTimestamp {
	// Use log's LogID or compute from URL
	var logID [32]byte
	if log.LogID != [32]byte{} {
		logID = log.LogID
	} else {
		logID = sha256.Sum256([]byte(log.URL))
	}

	return &SignedCertificateTimestamp{
		Version:   V1,
		LogID:     logID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Signature: DigitallySigned{
			HashAlgorithm: HashAlgorithmSHA256,
			SigAlgorithm:  SignatureAlgorithmECDSA,
			Signature:     []byte("mock-signature"),
		},
	}
}

// SetSCT configures an SCT to return for a specific log.
func (m *MockLogSubmitter) SetSCT(logURL string, sct *SignedCertificateTimestamp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SCTs[logURL] = sct
}

// SetError configures an error to return for a specific log.
func (m *MockLogSubmitter) SetError(logURL string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Errors[logURL] = err
}

// GetSubmissions returns all recorded submissions.
func (m *MockLogSubmitter) GetSubmissions() []MockSubmission {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]MockSubmission, len(m.Submissions))
	copy(result, m.Submissions)
	return result
}

// Reset clears all configured responses and recorded submissions.
func (m *MockLogSubmitter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SCTs = make(map[string]*SignedCertificateTimestamp)
	m.Errors = make(map[string]error)
	m.Submissions = nil
}
