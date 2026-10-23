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

package config

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Error types returned when validating the ACME Certificate Transparency
// configuration section.
var (
	// ErrACMECTLogPublicKey is returned when a ct.logs entry's public_key is
	// neither a PEM nor a base64 DER SubjectPublicKeyInfo.
	ErrACMECTLogPublicKey = errors.New("acme: ct.logs public_key is not a PEM or base64 DER SubjectPublicKeyInfo")

	// ErrACMECTLogTime is returned when a ct.logs entry's start_time or
	// end_time is not an RFC 3339 time.
	ErrACMECTLogTime = errors.New("acme: ct.logs start_time or end_time is not an RFC 3339 time")
)

// ACMECTConfig configures Certificate Transparency at ACME finalize: the
// precertificate is submitted to every enabled log (RFC 6962 §4.2) and the
// final certificate embeds the verified SCT list (RFC 6962 §3.3). CT is off
// unless at least one log is enabled.
//
// A log that refuses the precertificate, times out or returns an SCT that
// fails verification is logged and audited; finalize fails only when the
// verified SCTs do not meet MinSCTs, MinOperators or RequireRFC6962Log.
type ACMECTConfig struct {
	// Logs are the CT logs the ACME CA may submit to.
	Logs []ACMECTLogConfig `yaml:"logs"`

	// MinSCTs is the number of verified SCTs each certificate needs. Zero
	// selects 1.
	MinSCTs int `yaml:"min_scts"`

	// MinOperators is the number of distinct log operators those SCTs come
	// from. Zero selects 1.
	MinOperators int `yaml:"min_operators"`

	// RequireRFC6962Log requires an SCT from at least one RFC 6962 log, as
	// opposed to a static-ct-api (tiled) log.
	RequireRFC6962Log bool `yaml:"require_rfc6962_log"`

	// SubmissionTimeout bounds each log submission. Zero selects 10s.
	SubmissionTimeout time.Duration `yaml:"submission_timeout"`

	// StaggerDelay spaces successive log submissions apart.
	StaggerDelay time.Duration `yaml:"stagger_delay"`

	// MaxParallelSubmissions bounds concurrent log submissions. Zero
	// selects 10.
	MaxParallelSubmissions int `yaml:"max_parallel_submissions"`
}

// ACMECTLogConfig is one Certificate Transparency log.
type ACMECTLogConfig struct {
	// Name names the log in logs and audit events.
	Name string `yaml:"name"`

	// Operator identifies the log's operator, for MinOperators.
	Operator string `yaml:"operator"`

	// URL is the log's base URL; RFC 6962 §4.2 add-pre-chain is appended.
	URL string `yaml:"url"`

	// PublicKey is the log's SubjectPublicKeyInfo, PEM or base64 DER as log
	// lists publish it. Every SCT the log returns is verified with it (RFC
	// 6962 §3.2).
	PublicKey string `yaml:"public_key"`

	// Enabled selects the log for submission.
	Enabled bool `yaml:"enabled"`

	// StartTime and EndTime bound the expiry of the certificates a
	// temporally sharded log accepts, as RFC 3339 times. Empty leaves the
	// bound open.
	StartTime string `yaml:"start_time"`
	EndTime   string `yaml:"end_time"`

	// Tiled marks a static-ct-api (tiled) log rather than an RFC 6962 log.
	Tiled bool `yaml:"tiled"`

	// MaxChainLength is the longest chain the log accepts; zero is
	// unbounded.
	MaxChainLength int `yaml:"max_chain_length"`
}

// Validate parses every log's public key and shard times.
func (c ACMECTConfig) Validate() error {
	_, err := c.PolicyConfig()
	return err
}

// PolicyConfig returns the ct.PolicyConfig the ACME finalize path submits
// precertificates under, with the zero-value defaults applied.
func (c ACMECTConfig) PolicyConfig() (ct.PolicyConfig, error) {
	policy := ct.PolicyConfig{
		MinSCTs:                max(c.MinSCTs, 1),
		MinOperators:           max(c.MinOperators, 1),
		RequireRFC6962Log:      c.RequireRFC6962Log,
		SubmissionTimeout:      c.SubmissionTimeout,
		StaggerDelay:           c.StaggerDelay,
		MaxParallelSubmissions: c.MaxParallelSubmissions,
	}
	for _, log := range c.Logs {
		group, err := log.logGroup()
		if err != nil {
			return ct.PolicyConfig{}, err
		}
		policy.LogGroups = append(policy.LogGroups, group)
	}
	return policy, nil
}

// logGroup returns the log as a ct.LogGroup.
func (l ACMECTLogConfig) logGroup() (ct.LogGroup, error) {
	var der []byte
	if block, _ := pem.Decode([]byte(l.PublicKey)); block != nil {
		der = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(l.PublicKey)
		if err != nil {
			return ct.LogGroup{}, &errs.Detail{Err: ErrACMECTLogPublicKey, Detail: l.Name}
		}
		der = decoded
	}
	publicKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return ct.LogGroup{}, &errs.Detail{Err: ErrACMECTLogPublicKey, Detail: l.Name}
	}
	start, err := parseOptionalTime(l.StartTime)
	if err != nil {
		return ct.LogGroup{}, &errs.Detail{Err: ErrACMECTLogTime, Detail: l.Name}
	}
	end, err := parseOptionalTime(l.EndTime)
	if err != nil {
		return ct.LogGroup{}, &errs.Detail{Err: ErrACMECTLogTime, Detail: l.Name}
	}
	return ct.LogGroup{
		Name:           l.Name,
		Operator:       l.Operator,
		URL:            l.URL,
		PublicKey:      publicKey,
		Enabled:        l.Enabled,
		StartTime:      start,
		EndTime:        end,
		IsTiled:        l.Tiled,
		MaxChainLength: l.MaxChainLength,
	}, nil
}

// parseOptionalTime parses an RFC 3339 time; empty is the zero time.
func parseOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, value)
}
