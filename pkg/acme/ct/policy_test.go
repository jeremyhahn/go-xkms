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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCTPolicy(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:      2,
			MinOperators: 2,
			LogGroups:    createTestLogGroups(),
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)
		require.NotNil(t, policy)
	})

	t.Run("no logs", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:      2,
			MinOperators: 2,
			LogGroups:    nil,
		}

		submitter := NewMockLogSubmitter()
		_, err := NewCTPolicy(config, submitter)
		assert.ErrorIs(t, err, ErrNoLogsConfigured)
	})

	t.Run("invalid MinSCTs", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:      0,
			MinOperators: 2,
			LogGroups:    createTestLogGroups(),
		}

		submitter := NewMockLogSubmitter()
		_, err := NewCTPolicy(config, submitter)
		assert.Error(t, err)
	})

	t.Run("invalid MinOperators", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:      2,
			MinOperators: 0,
			LogGroups:    createTestLogGroups(),
		}

		submitter := NewMockLogSubmitter()
		_, err := NewCTPolicy(config, submitter)
		assert.Error(t, err)
	})

	t.Run("defaults applied", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:      1,
			MinOperators: 1,
			LogGroups:    createTestLogGroups(),
			// SubmissionTimeout and MaxParallelSubmissions are 0
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		cfg := policy.Config()
		assert.NotZero(t, cfg.SubmissionTimeout)
		assert.NotZero(t, cfg.MaxParallelSubmissions)
	})
}

func TestCTPolicy_GetSCTs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		logs := createTestLogGroups()
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		ctx := context.Background()
		precertDER := []byte("test-precert")
		expiry := time.Now().AddDate(1, 0, 0)

		scts, err := policy.GetSCTs(ctx, precertDER, nil, expiry)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(scts), 2)
	})

	t.Run("nil precert", func(t *testing.T) {
		policy, err := NewCTPolicy(PolicyConfig{
			MinSCTs:      2,
			MinOperators: 2,
			LogGroups:    createTestLogGroups(),
		}, NewMockLogSubmitter())
		require.NoError(t, err)

		_, err = policy.GetSCTs(context.Background(), nil, nil, time.Now())
		assert.ErrorIs(t, err, ErrNilInput)
	})

	t.Run("no eligible logs", func(t *testing.T) {
		// Create logs that are temporally invalid
		logs := []LogGroup{
			{
				Name:      "Log1",
				Operator:  "Op1",
				URL:       "https://log1.example.com",
				StartTime: time.Now().AddDate(-2, 0, 0),
				EndTime:   time.Now().AddDate(-1, 0, 0), // Ended a year ago
			},
		}

		config := PolicyConfig{
			MinSCTs:      1,
			MinOperators: 1,
			LogGroups:    logs,
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		// Certificate expires next year, but log ended a year ago
		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		assert.ErrorIs(t, err, ErrNoEligibleLogs)
	})

	t.Run("insufficient operators", func(t *testing.T) {
		// Only one operator, but require two
		logs := []LogGroup{
			{
				Name:      "Log1",
				Operator:  "Op1",
				URL:       "https://log1.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
			{
				Name:      "Log2",
				Operator:  "Op1", // Same operator
				URL:       "https://log2.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
		}

		config := PolicyConfig{
			MinSCTs:      2,
			MinOperators: 2, // Require 2 operators
			LogGroups:    logs,
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		assert.Error(t, err)
	})

	t.Run("submission errors handled", func(t *testing.T) {
		logs := createTestLogGroups()
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		// Set error for first log
		submitter.SetError(logs[0].URL, errors.New("submission failed"))

		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		expiry := time.Now().AddDate(1, 0, 0)
		scts, err := policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		// Should still succeed with remaining logs
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(scts), 2)
	})

	t.Run("context cancellation", func(t *testing.T) {
		logs := createTestLogGroups()
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		submitter.Delay = 2 * time.Second // Slow submissions

		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(ctx, []byte("test"), nil, expiry)
		assert.Error(t, err) // Should fail due to timeout
	})

	t.Run("require RFC6962 log success", func(t *testing.T) {
		logs := []LogGroup{
			{
				Name:      "RFC6962 Log",
				Operator:  "Op1",
				URL:       "https://rfc6962.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
				IsTiled:   false, // RFC6962 compliant
			},
			{
				Name:      "Tiled Log",
				Operator:  "Op2",
				URL:       "https://tiled.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
				IsTiled:   true, // Not RFC6962 compliant
			},
		}

		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			RequireRFC6962Log: true,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		expiry := time.Now().AddDate(1, 0, 0)
		scts, err := policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		require.NoError(t, err)
		assert.Len(t, scts, 2)
	})

	t.Run("require RFC6962 log failure", func(t *testing.T) {
		logs := []LogGroup{
			{
				Name:      "Tiled Log 1",
				Operator:  "Op1",
				URL:       "https://tiled1.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
				IsTiled:   true, // Not RFC6962 compliant
			},
			{
				Name:      "Tiled Log 2",
				Operator:  "Op2",
				URL:       "https://tiled2.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
				IsTiled:   true, // Not RFC6962 compliant
			},
		}

		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			RequireRFC6962Log: true,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		assert.ErrorIs(t, err, ErrNoRFC6962Log)
	})

	t.Run("insufficient SCTs after all submissions", func(t *testing.T) {
		logs := []LogGroup{
			{
				Name:      "Log1",
				Operator:  "Op1",
				URL:       "https://log1.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
			{
				Name:      "Log2",
				Operator:  "Op2",
				URL:       "https://log2.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
		}

		config := PolicyConfig{
			MinSCTs:           3, // Require 3 SCTs but only 2 logs available
			MinOperators:      2,
			LogGroups:         logs,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		assert.Error(t, err)
	})

	t.Run("insufficient operators after submissions", func(t *testing.T) {
		logs := []LogGroup{
			{
				Name:      "Log1",
				Operator:  "Op1",
				URL:       "https://log1.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
			{
				Name:      "Log2",
				Operator:  "Op1", // Same operator
				URL:       "https://log2.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
			{
				Name:      "Log3",
				Operator:  "Op2",
				URL:       "https://log3.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
		}

		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		// Make both non-Op1 logs fail
		submitter.SetError("https://log3.example.com", errors.New("failed"))

		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		// Should fail because we can only get SCTs from one operator
		assert.Error(t, err)
	})

	t.Run("stagger delay", func(t *testing.T) {
		logs := createTestLogGroups()
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			StaggerDelay:      10 * time.Millisecond,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		start := time.Now()
		expiry := time.Now().AddDate(1, 0, 0)
		scts, err := policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(scts), 2)
		// With stagger delay, should take at least some time
		assert.GreaterOrEqual(t, elapsed, 10*time.Millisecond)
	})

	t.Run("with certificate chain", func(t *testing.T) {
		logs := createTestLogGroups()
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		ctx := context.Background()
		precertDER := []byte("test-precert")
		chain := [][]byte{
			[]byte("issuer-cert"),
			[]byte("root-cert"),
		}
		expiry := time.Now().AddDate(1, 0, 0)

		scts, err := policy.GetSCTs(ctx, precertDER, chain, expiry)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(scts), 2)

		// Verify chain was passed to submitter
		submissions := submitter.GetSubmissions()
		for _, sub := range submissions {
			assert.Equal(t, chain, sub.Chain)
		}
	})

	t.Run("empty precert", func(t *testing.T) {
		policy, err := NewCTPolicy(PolicyConfig{
			MinSCTs:      2,
			MinOperators: 2,
			LogGroups:    createTestLogGroups(),
		}, NewMockLogSubmitter())
		require.NoError(t, err)

		_, err = policy.GetSCTs(context.Background(), []byte{}, nil, time.Now())
		assert.ErrorIs(t, err, ErrNilInput)
	})

	t.Run("context cancelled during stagger delay", func(t *testing.T) {
		logs := createTestLogGroups()
		config := PolicyConfig{
			MinSCTs:                2,
			MinOperators:           2,
			LogGroups:              logs,
			StaggerDelay:           500 * time.Millisecond, // Long stagger delay
			SubmissionTimeout:      5 * time.Second,
			MaxParallelSubmissions: 1, // Sequential to ensure stagger delay is hit
		}

		submitter := NewMockLogSubmitter()
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		// Cancel after short time to trigger cancel during stagger
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()

		expiry := time.Now().AddDate(1, 0, 0)
		_, _ = policy.GetSCTs(ctx, []byte("test"), nil, expiry)
		// May or may not get enough SCTs depending on timing
		// The important thing is it doesn't hang
	})

	t.Run("context cancelled during semaphore acquisition", func(t *testing.T) {
		logs := createTestLogGroups()
		config := PolicyConfig{
			MinSCTs:                4, // Need all 4 logs
			MinOperators:           4, // Need all 4 operators
			LogGroups:              logs,
			StaggerDelay:           0,
			SubmissionTimeout:      5 * time.Second,
			MaxParallelSubmissions: 1, // Only 1 at a time to trigger semaphore wait
		}

		submitter := NewMockLogSubmitter()
		submitter.Delay = 200 * time.Millisecond // Slow submissions

		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(ctx, []byte("test"), nil, expiry)
		// Should fail because context cancelled while waiting for semaphore
		assert.Error(t, err)
	})

	t.Run("context cancelled after semaphore acquired", func(t *testing.T) {
		logs := createTestLogGroups()
		config := PolicyConfig{
			MinSCTs:                2,
			MinOperators:           2,
			LogGroups:              logs,
			StaggerDelay:           0,
			SubmissionTimeout:      5 * time.Second,
			MaxParallelSubmissions: 4, // All can run in parallel
		}

		submitter := NewMockLogSubmitter()
		submitter.Delay = 500 * time.Millisecond // Slow submissions

		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		// Cancel context after semaphore acquired but during submission
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(ctx, []byte("test"), nil, expiry)
		assert.Error(t, err)
	})

	t.Run("all logs fail", func(t *testing.T) {
		logs := []LogGroup{
			{
				Name:      "Log1",
				Operator:  "Op1",
				URL:       "https://log1.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
			{
				Name:      "Log2",
				Operator:  "Op2",
				URL:       "https://log2.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
		}

		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		log1Err := errors.New("log1 failed")
		log2Err := errors.New("log2 failed")
		submitter.SetError("https://log1.example.com", log1Err)
		submitter.SetError("https://log2.example.com", log2Err)

		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		require.Error(t, err)

		// The policy violation ("not enough SCTs") is reported...
		var policyErr *PolicyViolationError
		assert.ErrorAs(t, err, &policyErr)
		// ...and so is why: both per-log submission failures are joined in
		// rather than silently dropped, so an operator can see which logs
		// rejected the precert and why.
		assert.ErrorIs(t, err, log1Err)
		assert.ErrorIs(t, err, log2Err)
	})

	t.Run("RFC6962 log fails but tiled logs succeed", func(t *testing.T) {
		// This tests the specific case where RequireRFC6962Log is true
		// but the RFC6962 log fails, while tiled logs succeed
		logs := []LogGroup{
			{
				Name:      "RFC6962 Log",
				Operator:  "Op1",
				URL:       "https://rfc6962.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
				IsTiled:   false, // RFC6962 compliant
			},
			{
				Name:      "Tiled Log 1",
				Operator:  "Op2",
				URL:       "https://tiled1.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
				IsTiled:   true, // Not RFC6962 compliant
			},
			{
				Name:      "Tiled Log 2",
				Operator:  "Op3",
				URL:       "https://tiled2.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
				IsTiled:   true, // Not RFC6962 compliant
			},
		}

		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			LogGroups:         logs,
			RequireRFC6962Log: true,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		// Make the RFC6962 log fail
		submitter.SetError("https://rfc6962.example.com", errors.New("failed"))

		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		expiry := time.Now().AddDate(1, 0, 0)
		_, err = policy.GetSCTs(context.Background(), []byte("test"), nil, expiry)
		// Should fail because no RFC6962 log returned an SCT
		assert.ErrorIs(t, err, ErrNoRFC6962Log)
	})

	t.Run("sending result blocked by context done", func(t *testing.T) {
		// This tests the case where sending result to channel is blocked
		// because context was cancelled
		logs := []LogGroup{
			{
				Name:      "Log1",
				Operator:  "Op1",
				URL:       "https://log1.example.com",
				StartTime: time.Now().AddDate(-1, 0, 0),
			},
		}

		config := PolicyConfig{
			MinSCTs:           1,
			MinOperators:      1,
			LogGroups:         logs,
			StaggerDelay:      0,
			SubmissionTimeout: 5 * time.Second,
		}

		submitter := NewMockLogSubmitter()
		// Instant success
		policy, err := NewCTPolicy(config, submitter)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		expiry := time.Now().AddDate(1, 0, 0)
		// Context is already cancelled
		_, err = policy.GetSCTs(ctx, []byte("test"), nil, expiry)
		// Should fail because context is cancelled
		assert.Error(t, err)
	})
}

func TestCTPolicy_EligibleLogs(t *testing.T) {
	now := time.Now()
	logs := []LogGroup{
		{
			Name:      "Active Log",
			Operator:  "Op1",
			URL:       "https://active.example.com",
			StartTime: now.AddDate(-1, 0, 0),
			// No end time - still active
		},
		{
			Name:      "Sharded Log 2024",
			Operator:  "Op2",
			URL:       "https://shard2024.example.com",
			StartTime: now.AddDate(-1, 0, 0),
			EndTime:   now.AddDate(0, 6, 0), // Ends in 6 months
		},
		{
			Name:      "Expired Log",
			Operator:  "Op3",
			URL:       "https://expired.example.com",
			StartTime: now.AddDate(-3, 0, 0),
			EndTime:   now.AddDate(-1, 0, 0), // Ended a year ago
		},
	}

	config := PolicyConfig{
		MinSCTs:      2,
		MinOperators: 2,
		LogGroups:    logs,
	}

	policy, err := NewCTPolicy(config, NewMockLogSubmitter())
	require.NoError(t, err)

	t.Run("cert expires in 3 months", func(t *testing.T) {
		expiry := now.AddDate(0, 3, 0)
		eligible := policy.EligibleLogs(expiry)
		assert.Len(t, eligible, 2) // Active and Sharded 2024
	})

	t.Run("cert expires in 1 year", func(t *testing.T) {
		expiry := now.AddDate(1, 0, 0)
		eligible := policy.EligibleLogs(expiry)
		assert.Len(t, eligible, 1) // Only Active log
	})
}

func TestCTPolicy_Operators(t *testing.T) {
	logs := []LogGroup{
		{Operator: "Google"},
		{Operator: "Cloudflare"},
		{Operator: "Google"}, // Duplicate
		{Operator: "DigiCert"},
	}

	config := PolicyConfig{
		MinSCTs:      1,
		MinOperators: 1,
		LogGroups:    logs,
	}

	policy, err := NewCTPolicy(config, NewMockLogSubmitter())
	require.NoError(t, err)

	operators := policy.Operators()
	assert.Len(t, operators, 3) // Google, Cloudflare, DigiCert
}

func TestCTPolicy_AddRemoveLog(t *testing.T) {
	config := PolicyConfig{
		MinSCTs:      1,
		MinOperators: 1,
		LogGroups:    createTestLogGroups(),
	}

	policy, err := NewCTPolicy(config, NewMockLogSubmitter())
	require.NoError(t, err)

	initialCount := len(policy.Config().LogGroups)

	// Add log
	newLog := LogGroup{
		Name:     "New Log",
		Operator: "NewOp",
		URL:      "https://new.example.com",
	}
	err = policy.AddLog(newLog)
	require.NoError(t, err)
	assert.Len(t, policy.Config().LogGroups, initialCount+1)

	// Add duplicate should fail
	err = policy.AddLog(newLog)
	assert.ErrorIs(t, err, ErrInvalidLogConfig)

	// Remove log
	policy.RemoveLog("https://new.example.com")
	assert.Len(t, policy.Config().LogGroups, initialCount)

	// Remove non-existent log (should be no-op)
	policy.RemoveLog("https://nonexistent.example.com")
	assert.Len(t, policy.Config().LogGroups, initialCount)
}

func TestCTPolicy_UpdateConfig(t *testing.T) {
	config := PolicyConfig{
		MinSCTs:      1,
		MinOperators: 1,
		LogGroups:    createTestLogGroups(),
	}

	policy, err := NewCTPolicy(config, NewMockLogSubmitter())
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		newConfig := PolicyConfig{
			MinSCTs:      2,
			MinOperators: 2,
			LogGroups:    createTestLogGroups(),
		}

		err := policy.UpdateConfig(newConfig)
		require.NoError(t, err)

		cfg := policy.Config()
		assert.Equal(t, 2, cfg.MinSCTs)
		assert.Equal(t, 2, cfg.MinOperators)
	})

	t.Run("invalid update MinSCTs", func(t *testing.T) {
		newConfig := PolicyConfig{
			MinSCTs:      0,
			MinOperators: 1,
			LogGroups:    createTestLogGroups(),
		}

		err := policy.UpdateConfig(newConfig)
		assert.Error(t, err)
	})

	t.Run("invalid update MinOperators", func(t *testing.T) {
		newConfig := PolicyConfig{
			MinSCTs:      1,
			MinOperators: 0,
			LogGroups:    createTestLogGroups(),
		}

		err := policy.UpdateConfig(newConfig)
		assert.Error(t, err)
	})

	t.Run("invalid update no logs", func(t *testing.T) {
		newConfig := PolicyConfig{
			MinSCTs:      1,
			MinOperators: 1,
			LogGroups:    nil,
		}

		err := policy.UpdateConfig(newConfig)
		assert.ErrorIs(t, err, ErrNoLogsConfigured)
	})
}

func TestLogGroup_IsTemporallyValid(t *testing.T) {
	now := time.Now()

	t.Run("no end time (always valid)", func(t *testing.T) {
		log := LogGroup{
			StartTime: now.AddDate(-1, 0, 0),
			// No EndTime
		}

		// Any future expiry should be valid
		assert.True(t, log.IsTemporallyValid(now.AddDate(1, 0, 0)))
		assert.True(t, log.IsTemporallyValid(now.AddDate(10, 0, 0)))
	})

	t.Run("with end time", func(t *testing.T) {
		log := LogGroup{
			StartTime: now.AddDate(-1, 0, 0),
			EndTime:   now.AddDate(0, 6, 0), // Ends in 6 months
		}

		// Expiry within window
		assert.True(t, log.IsTemporallyValid(now.AddDate(0, 3, 0)))

		// Expiry at end time
		assert.True(t, log.IsTemporallyValid(now.AddDate(0, 6, 0)))

		// Expiry after end time
		assert.False(t, log.IsTemporallyValid(now.AddDate(1, 0, 0)))
	})

	t.Run("expiry before start time", func(t *testing.T) {
		log := LogGroup{
			StartTime: now,
		}

		// Expiry before start time
		assert.False(t, log.IsTemporallyValid(now.AddDate(0, -1, 0)))
	})
}

func TestLogGroup_IsRFC6962Compliant(t *testing.T) {
	t.Run("RFC6962 compliant", func(t *testing.T) {
		log := LogGroup{IsTiled: false}
		assert.True(t, log.IsRFC6962Compliant())
	})

	t.Run("tiled (not RFC6962)", func(t *testing.T) {
		log := LogGroup{IsTiled: true}
		assert.False(t, log.IsRFC6962Compliant())
	})
}

func TestDefaultPolicyConfig(t *testing.T) {
	config := DefaultPolicyConfig()

	assert.Equal(t, 2, config.MinSCTs)
	assert.Equal(t, 2, config.MinOperators)
	assert.True(t, config.RequireRFC6962Log)
	assert.NotZero(t, config.StaggerDelay)
	assert.NotZero(t, config.SubmissionTimeout)
	assert.NotZero(t, config.MaxParallelSubmissions)
}

func TestIsPolicySatisfied(t *testing.T) {
	policy, err := NewCTPolicy(PolicyConfig{
		MinSCTs:      2,
		MinOperators: 2,
		LogGroups:    createTestLogGroups(),
	}, NewMockLogSubmitter())
	require.NoError(t, err)

	t.Run("all requirements met", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			RequireRFC6962Log: true,
		}
		assert.True(t, policy.isPolicySatisfied(2, 2, true, config))
		assert.True(t, policy.isPolicySatisfied(3, 3, true, config))
	})

	t.Run("insufficient SCTs", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			RequireRFC6962Log: false,
		}
		assert.False(t, policy.isPolicySatisfied(1, 2, false, config))
	})

	t.Run("insufficient operators", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			RequireRFC6962Log: false,
		}
		assert.False(t, policy.isPolicySatisfied(2, 1, false, config))
	})

	t.Run("missing RFC6962 when required", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			RequireRFC6962Log: true,
		}
		assert.False(t, policy.isPolicySatisfied(2, 2, false, config))
	})

	t.Run("RFC6962 not required", func(t *testing.T) {
		config := PolicyConfig{
			MinSCTs:           2,
			MinOperators:      2,
			RequireRFC6962Log: false,
		}
		assert.True(t, policy.isPolicySatisfied(2, 2, false, config))
	})
}

func TestCountOperators(t *testing.T) {
	t.Run("empty logs", func(t *testing.T) {
		count := countOperators(nil)
		assert.Equal(t, 0, count)

		count = countOperators([]LogGroup{})
		assert.Equal(t, 0, count)
	})

	t.Run("single operator", func(t *testing.T) {
		logs := []LogGroup{
			{Operator: "Google"},
			{Operator: "Google"},
		}
		count := countOperators(logs)
		assert.Equal(t, 1, count)
	})

	t.Run("multiple operators", func(t *testing.T) {
		logs := []LogGroup{
			{Operator: "Google"},
			{Operator: "Cloudflare"},
			{Operator: "DigiCert"},
		}
		count := countOperators(logs)
		assert.Equal(t, 3, count)
	})

	t.Run("mixed duplicates", func(t *testing.T) {
		logs := []LogGroup{
			{Operator: "Google"},
			{Operator: "Cloudflare"},
			{Operator: "Google"},
			{Operator: "DigiCert"},
			{Operator: "Cloudflare"},
		}
		count := countOperators(logs)
		assert.Equal(t, 3, count)
	})
}

// createTestLogGroups creates a set of test log groups with multiple operators.
func createTestLogGroups() []LogGroup {
	now := time.Now()
	return []LogGroup{
		{
			Name:      "Google Argon 2025",
			Operator:  "Google",
			URL:       "https://ct.googleapis.com/logs/us1/argon2025",
			StartTime: now.AddDate(-1, 0, 0),
			IsTiled:   false,
		},
		{
			Name:      "Cloudflare Nimbus 2025",
			Operator:  "Cloudflare",
			URL:       "https://ct.cloudflare.com/logs/nimbus2025",
			StartTime: now.AddDate(-1, 0, 0),
			IsTiled:   false,
		},
		{
			Name:      "DigiCert Yeti 2025",
			Operator:  "DigiCert",
			URL:       "https://yeti2025.ct.digicert.com/log",
			StartTime: now.AddDate(-1, 0, 0),
			IsTiled:   false,
		},
		{
			Name:      "Let's Encrypt Oak 2025",
			Operator:  "Let's Encrypt",
			URL:       "https://oak.ct.letsencrypt.org/2025",
			StartTime: now.AddDate(-1, 0, 0),
			IsTiled:   false,
		},
	}
}
