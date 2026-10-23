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
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// CTPolicy implements CT policy enforcement with multi-operator SCT requirements.
type CTPolicy struct {
	config    PolicyConfig
	submitter LogSubmitter
	mu        sync.RWMutex
}

// NewCTPolicy creates a new CT policy with the given configuration.
// The submitter is used to submit precertificates to CT logs.
func NewCTPolicy(config PolicyConfig, submitter LogSubmitter) (*CTPolicy, error) {
	if err := validatePolicyConfig(&config); err != nil {
		return nil, err
	}

	return &CTPolicy{
		config:    config,
		submitter: submitter,
	}, nil
}

// validatePolicyConfig validates the policy configuration.
func validatePolicyConfig(config *PolicyConfig) error {
	if config.MinSCTs < 1 {
		return NewPolicyViolationError("MinSCTs", config.MinSCTs, 1)
	}

	if config.MinOperators < 1 {
		return NewPolicyViolationError("MinOperators", config.MinOperators, 1)
	}

	// Validate a copy so deriving log IDs never writes to the caller's slice.
	logs := make([]LogGroup, 0, len(config.LogGroups))
	for _, log := range config.LogGroups {
		if err := log.validate(); err != nil {
			return err
		}
		if err := checkDuplicateLog(logs, log); err != nil {
			return err
		}
		logs = append(logs, log)
	}
	config.LogGroups = logs

	if !config.Enabled() {
		return ErrNoLogsConfigured
	}

	// Set defaults if not specified
	if config.SubmissionTimeout == 0 {
		config.SubmissionTimeout = 10 * time.Second
	}

	if config.MaxParallelSubmissions == 0 {
		config.MaxParallelSubmissions = 10
	}

	return nil
}

// checkDuplicateLog refuses log when a log in logs has its URL or log ID.
func checkDuplicateLog(logs []LogGroup, log LogGroup) error {
	for _, existing := range logs {
		if existing.URL == log.URL || existing.LogID == log.LogID {
			return NewLogConfigError(log, ErrDuplicateLog)
		}
	}
	return nil
}

// Submit submits precertDER, with the issuing chain (issuer first), to every
// enabled log whose temporal window holds expiry (RFC 6962 §4.2
// add-pre-chain) and waits for every log to answer or time out, so each
// failure is reported. It succeeds when the verified SCTs meet MinSCTs,
// MinOperators and RequireRFC6962Log; Submission.Failures then names each log
// that refused the precertificate, timed out or returned an SCT that failed
// verification. Otherwise it fails with a PolicyViolationError, or
// ErrNoRFC6962Log, joined with each log's CTSubmissionError.
func (p *CTPolicy) Submit(ctx context.Context, precertDER []byte, chain [][]byte, expiry time.Time) (*Submission, error) {
	if len(precertDER) == 0 {
		return nil, ErrNilInput
	}

	p.mu.RLock()
	config := p.config
	p.mu.RUnlock()

	// Filter logs by temporal validity
	eligibleLogs := p.filterEligibleLogs(expiry)
	if len(eligibleLogs) == 0 {
		return nil, ErrNoEligibleLogs
	}

	// Check if we can potentially meet requirements
	operators := countOperators(eligibleLogs)
	if operators < config.MinOperators {
		return nil, NewPolicyViolationError("available operators", operators, config.MinOperators)
	}

	results := p.submitToLogs(ctx, precertDER, chain, eligibleLogs)
	return collectSCTs(results, config)
}

// filterEligibleLogs returns logs that are temporally valid for the certificate.
func (p *CTPolicy) filterEligibleLogs(expiry time.Time) []LogGroup {
	var eligible []LogGroup
	for _, log := range p.config.LogGroups {
		if log.Enabled && log.IsTemporallyValid(expiry) {
			eligible = append(eligible, log)
		}
	}
	return eligible
}

// countOperators returns the number of distinct operators in the log list.
func countOperators(logs []LogGroup) int {
	operators := make(map[string]struct{})
	for _, log := range logs {
		operators[log.Operator] = struct{}{}
	}
	return len(operators)
}

// submitToLogs submits the precertificate to all eligible logs concurrently.
func (p *CTPolicy) submitToLogs(ctx context.Context, precertDER []byte, chain [][]byte, logs []LogGroup) <-chan SCTResult {
	results := make(chan SCTResult, len(logs))

	// Create a cancellable context for early termination
	submitCtx, cancel := context.WithCancel(ctx) // #nosec G118 -- cancel is called in the goroutine on success

	// Track submissions
	var wg sync.WaitGroup
	var submitted int32

	// Semaphore for limiting concurrent submissions
	sem := make(chan struct{}, p.config.MaxParallelSubmissions)

	// Submit to each log
	for i, log := range logs {
		wg.Add(1)
		go func(idx int, lg LogGroup) {
			defer wg.Done()

			// Stagger submissions to prevent thundering herd
			if p.config.StaggerDelay > 0 && idx > 0 {
				select {
				case <-submitCtx.Done():
					return
				case <-time.After(p.config.StaggerDelay * time.Duration(idx)):
				}
			}

			// Acquire semaphore
			select {
			case <-submitCtx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			// Check if context is still active
			if submitCtx.Err() != nil {
				return
			}

			// Create timeout context for this submission
			subCtx, subCancel := context.WithTimeout(submitCtx, p.config.SubmissionTimeout)
			defer subCancel()

			// Submit to log
			sct, err := p.submitter.SubmitPrecert(subCtx, precertDER, chain, lg)

			result := SCTResult{
				Log:   lg,
				Error: err,
			}
			if sct != nil {
				result.SCT = sct
			}

			// Send result
			select {
			case results <- result:
				if err == nil {
					atomic.AddInt32(&submitted, 1)
				}
			case <-submitCtx.Done():
				return
			}
		}(i, log)
	}

	// Close results channel when all submissions complete
	go func() {
		wg.Wait()
		cancel()
		close(results)
	}()

	return results
}

// collectSCTs collects SCTs from results and validates against policy.
func collectSCTs(results <-chan SCTResult, config PolicyConfig) (*Submission, error) {
	submission := &Submission{}
	operators := make(map[string]struct{})
	hasRFC6962 := false

	for result := range results {
		if result.Error != nil || result.SCT == nil {
			cause := result.Error
			if cause == nil {
				cause = ErrInvalidSCT
			}
			submission.Failures = append(submission.Failures,
				NewCTSubmissionError(result.Log.Name, result.Log.URL, cause))
			continue
		}
		submission.SCTs = append(submission.SCTs, *result.SCT)
		operators[result.Log.Operator] = struct{}{}
		if result.Log.IsRFC6962Compliant() {
			hasRFC6962 = true
		}
	}

	var violation error
	switch {
	case len(submission.SCTs) < config.MinSCTs:
		violation = NewPolicyViolationError("SCTs", len(submission.SCTs), config.MinSCTs)
	case len(operators) < config.MinOperators:
		violation = NewPolicyViolationError("operators", len(operators), config.MinOperators)
	case config.RequireRFC6962Log && !hasRFC6962:
		violation = ErrNoRFC6962Log
	}
	if violation != nil {
		errs := []error{violation}
		for _, failure := range submission.Failures {
			errs = append(errs, failure)
		}
		return nil, errors.Join(errs...)
	}
	return submission, nil
}

// Config returns a copy of the current policy configuration.
func (p *CTPolicy) Config() PolicyConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()

	config := p.config
	config.LogGroups = make([]LogGroup, len(p.config.LogGroups))
	copy(config.LogGroups, p.config.LogGroups)
	return config
}

// UpdateConfig updates the policy configuration.
func (p *CTPolicy) UpdateConfig(config PolicyConfig) error {
	if err := validatePolicyConfig(&config); err != nil {
		return err
	}

	p.mu.Lock()
	p.config = config
	p.mu.Unlock()

	return nil
}

// AddLog adds a new log to the policy.
func (p *CTPolicy) AddLog(log LogGroup) error {
	if err := log.validate(); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if err := checkDuplicateLog(p.config.LogGroups, log); err != nil {
		return err
	}

	p.config.LogGroups = append(p.config.LogGroups, log)
	return nil
}

// RemoveLog removes a log from the policy by URL.
func (p *CTPolicy) RemoveLog(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, log := range p.config.LogGroups {
		if log.URL == url {
			p.config.LogGroups = append(p.config.LogGroups[:i], p.config.LogGroups[i+1:]...)
			return
		}
	}
}

// EligibleLogs returns the logs eligible for a certificate with the given expiry.
func (p *CTPolicy) EligibleLogs(expiry time.Time) []LogGroup {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.filterEligibleLogs(expiry)
}

// Operators returns the distinct operators in the configured logs.
func (p *CTPolicy) Operators() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	opSet := make(map[string]struct{})
	for _, log := range p.config.LogGroups {
		opSet[log.Operator] = struct{}{}
	}

	operators := make([]string, 0, len(opSet))
	for op := range opSet {
		operators = append(operators, op)
	}
	return operators
}
