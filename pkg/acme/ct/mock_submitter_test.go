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
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

// MockLogSubmitter implements LogSubmitter for the policy tests.
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

// NewMockLogSubmitter creates a new mock submitter.
func NewMockLogSubmitter() *MockLogSubmitter {
	return &MockLogSubmitter{
		SCTs:   make(map[string]*SignedCertificateTimestamp),
		Errors: make(map[string]error),
	}
}

// SubmitPrecert records the submission and returns the configured SCT or error.
func (m *MockLogSubmitter) SubmitPrecert(ctx context.Context, precertDER []byte, chain [][]byte, log LogGroup) (*SignedCertificateTimestamp, error) {
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
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.Delay):
		}
	}

	// Check for error
	m.mu.Lock()
	err, hasErr := m.Errors[log.URL]
	sct, hasSCT := m.SCTs[log.URL]
	m.mu.Unlock()
	if hasErr {
		return nil, err
	}

	// Return configured SCT or generate one
	if hasSCT {
		return sct, nil
	}
	return m.generateMockSCT(log), nil
}

// generateMockSCT generates an unsigned SCT for the log.
func (m *MockLogSubmitter) generateMockSCT(log LogGroup) *SignedCertificateTimestamp {
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

// SetSCT configures the SCT to return for a log.
func (m *MockLogSubmitter) SetSCT(logURL string, sct *SignedCertificateTimestamp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SCTs[logURL] = sct
}

// SetError configures the error to return for a log.
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

// Reset clears all recorded submissions and configuration.
func (m *MockLogSubmitter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SCTs = make(map[string]*SignedCertificateTimestamp)
	m.Errors = make(map[string]error)
	m.Submissions = nil
}
