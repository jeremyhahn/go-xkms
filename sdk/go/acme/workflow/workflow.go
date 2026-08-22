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

// Package workflow provides high-level ACME workflow orchestration on top of
// the low-level SDK clients. It composes individual RFC 8555 protocol steps
// into complete operations suitable for GUI and automation use cases.
package workflow

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/account"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/authorization"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/certificate"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/challenge"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/order"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// Client is the minimal interface the workflow orchestrator requires from
// the Trusted CA SDK client. The trustedca.Client type satisfies this
// interface implicitly.
type Client interface {
	Account() account.Client
	Order() order.Client
	Authorization() authorization.Client
	Challenge() challenge.Client
	Certificate() certificate.Client
}

// Workflow provides high-level ACME certificate lifecycle operations.
type Workflow interface {
	// Register creates or retrieves an ACME account.
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)

	// RequestCertificate performs the full ACME certificate issuance flow:
	// create order, authorize domains, solve challenges, finalize, and download.
	RequestCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error)

	// RevokeCertificate revokes a previously issued certificate.
	RevokeCertificate(ctx context.Context, req *RevokeRequest) error
}

type workflow struct {
	client       Client
	pollTimeout  time.Duration
	pollInterval time.Duration
}

// NewWorkflow creates a new ACME workflow orchestrator backed by the given client.
func NewWorkflow(client Client, opts ...Option) Workflow {
	if client == nil {
		return nil
	}
	w := &workflow{
		client:       client,
		pollTimeout:  120 * time.Second,
		pollInterval: 2 * time.Second,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Option is a functional option for configuring a Workflow.
type Option func(*workflow)

// WithPollTimeout sets the maximum time to wait when polling for status changes.
func WithPollTimeout(d time.Duration) Option {
	return func(w *workflow) {
		if d > 0 {
			w.pollTimeout = d
		}
	}
}

// WithPollInterval sets the interval between status polling attempts.
func WithPollInterval(d time.Duration) Option {
	return func(w *workflow) {
		if d > 0 {
			w.pollInterval = d
		}
	}
}

// pollCondition is a function that returns true when the desired condition is met,
// or an error if the resource reached a terminal failure state.
type pollCondition func(ctx context.Context) (done bool, err error)

// poll repeatedly evaluates the condition until it returns true, the context
// is canceled, or the poll timeout expires.
func (w *workflow) poll(ctx context.Context, condition pollCondition) error {
	deadline := time.After(w.pollTimeout)
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		done, err := condition(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}

		select {
		case <-ctx.Done():
			return errors.NewCanceled("workflow.poll", "context canceled while polling")
		case <-deadline:
			return errors.NewTimeout("workflow.poll", "poll timeout exceeded")
		case <-ticker.C:
			// Next tick: loop round and poll again.
		}
	}
}
