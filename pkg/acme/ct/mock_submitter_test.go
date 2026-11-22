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
		Errors: make(map[string]error),
	}
}

// SubmitPrecert records the submission and returns the configured error or a generated SCT.
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
	m.mu.Unlock()
	if hasErr {
		return nil, err
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
