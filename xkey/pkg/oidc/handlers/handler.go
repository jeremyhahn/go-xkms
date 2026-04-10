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

package handlers

import (
	"context"
	"io"
	"time"
)

// TokenData represents the token data passed to output handlers.
// This is a handler-specific view of the token response that includes
// both standard OIDC tokens and provider-specific data.
type TokenData struct {
	// AccessToken is the OAuth2 access token.
	AccessToken string `json:"access_token,omitempty"`

	// RefreshToken is the OAuth2 refresh token.
	RefreshToken string `json:"refresh_token,omitempty"`

	// IDToken is the OIDC ID token.
	IDToken string `json:"id_token,omitempty"`

	// TokenType is the type of token (usually "Bearer" or "DPoP").
	TokenType string `json:"token_type,omitempty"`

	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int `json:"expires_in,omitempty"`

	// Expiry is the calculated expiry time.
	Expiry time.Time `json:"expiry,omitempty"`

	// Scope is the granted scope.
	Scope string `json:"scope,omitempty"`

	// Provider-specific fields

	// AWSCredentials contains AWS-specific credential data.
	AWSCredentials *AWSCredentials `json:"aws_credentials,omitempty"`

	// Extra contains any additional provider-specific data.
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// AWSCredentials represents AWS temporary credentials.
type AWSCredentials struct {
	// AccessKeyID is the AWS access key ID.
	AccessKeyID string `json:"accessKeyId"`

	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string `json:"secretAccessKey"`

	// SessionToken is the AWS session token.
	SessionToken string `json:"sessionToken"`

	// Expiration is when the credentials expire.
	Expiration time.Time `json:"expiration"`

	// Region is the AWS region these credentials are for.
	Region string `json:"region,omitempty"`
}

// OutputHandler defines the interface for processing token responses.
// Different implementations handle tokens in different ways (exec, file, stdout, etc.).
type OutputHandler interface {
	// Handle processes the token data and produces output.
	// The context can be used for cancellation and timeouts.
	Handle(ctx context.Context, data *TokenData) error

	// Name returns the handler's identifier.
	Name() string
}

// WriterHandler is an OutputHandler that writes to an io.Writer.
// This is useful for handlers that produce text output.
type WriterHandler interface {
	OutputHandler

	// SetWriter sets the output destination.
	SetWriter(w io.Writer)
}

// ValidateTokenData validates that token data is not nil and has required fields.
func ValidateTokenData(data *TokenData) error {
	if data == nil {
		return ErrNilTokenResponse
	}
	return nil
}

// ChainHandler chains multiple handlers together.
// All handlers are executed in order, and the first error stops execution.
type ChainHandler struct {
	handlers []OutputHandler
}

// NewChainHandler creates a new chain of handlers.
func NewChainHandler(handlers ...OutputHandler) *ChainHandler {
	return &ChainHandler{handlers: handlers}
}

// Handle executes all handlers in order.
func (c *ChainHandler) Handle(ctx context.Context, data *TokenData) error {
	for _, h := range c.handlers {
		if err := h.Handle(ctx, data); err != nil {
			return err
		}
	}
	return nil
}

// Name returns the chain handler's identifier.
func (c *ChainHandler) Name() string {
	return "chain"
}

// Add appends a handler to the chain.
func (c *ChainHandler) Add(h OutputHandler) {
	c.handlers = append(c.handlers, h)
}

// NoopHandler is a handler that does nothing.
// Useful for testing or when no output is desired.
type NoopHandler struct{}

// NewNoopHandler creates a new no-op handler.
func NewNoopHandler() *NoopHandler {
	return &NoopHandler{}
}

// Handle does nothing and returns nil.
func (n *NoopHandler) Handle(ctx context.Context, data *TokenData) error {
	return nil
}

// Name returns the noop handler's identifier.
func (n *NoopHandler) Name() string {
	return "noop"
}
