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
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// JSONHandler outputs token data as JSON to a writer.
type JSONHandler struct {
	// Writer is the destination for JSON output.
	Writer io.Writer

	// Indent enables pretty-printing with indentation.
	Indent bool

	// IncludeAWS includes AWS credentials in output.
	IncludeAWS bool

	// OmitEmpty excludes empty fields from output.
	OmitEmpty bool

	// AWSOnly outputs only AWS credentials (for AWS CLI compatibility).
	AWSOnly bool
}

// NewJSONHandler creates a new JSON handler that writes to stdout.
func NewJSONHandler() *JSONHandler {
	return &JSONHandler{
		Writer:     os.Stdout,
		Indent:     true,
		IncludeAWS: true,
	}
}

// Handle outputs the token data as JSON.
func (h *JSONHandler) Handle(ctx context.Context, data *TokenData) error {
	if err := ValidateTokenData(data); err != nil {
		return err
	}

	var output interface{}

	if h.AWSOnly && data.AWSCredentials != nil {
		// AWS CLI compatible output
		output = h.awsCredentialOutput(data.AWSCredentials)
	} else {
		output = h.buildOutput(data)
	}

	var jsonBytes []byte
	var err error

	if h.Indent {
		jsonBytes, err = json.MarshalIndent(output, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(output)
	}

	if err != nil {
		return fmt.Errorf("%w: %v", ErrJSONMarshalFailed, err)
	}

	writer := h.Writer
	if writer == nil {
		writer = os.Stdout
	}

	if _, err := writer.Write(jsonBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrOutputWriteFailed, err)
	}

	// Add newline for readability
	if _, err := writer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("%w: %v", ErrOutputWriteFailed, err)
	}

	return nil
}

// Name returns the handler's identifier.
func (h *JSONHandler) Name() string {
	return "json"
}

// SetWriter sets the output destination.
func (h *JSONHandler) SetWriter(w io.Writer) {
	h.Writer = w
}

// buildOutput builds the JSON output structure.
func (h *JSONHandler) buildOutput(data *TokenData) map[string]interface{} {
	output := make(map[string]interface{})

	if data.AccessToken != "" || !h.OmitEmpty {
		output["access_token"] = data.AccessToken
	}
	if data.RefreshToken != "" {
		output["refresh_token"] = data.RefreshToken
	}
	if data.IDToken != "" {
		output["id_token"] = data.IDToken
	}
	if data.TokenType != "" || !h.OmitEmpty {
		output["token_type"] = data.TokenType
	}
	if data.ExpiresIn > 0 {
		output["expires_in"] = data.ExpiresIn
	}
	if !data.Expiry.IsZero() {
		output["expiry"] = data.Expiry.Format("2006-01-02T15:04:05Z07:00")
	}
	if data.Scope != "" {
		output["scope"] = data.Scope
	}

	if h.IncludeAWS && data.AWSCredentials != nil {
		output["aws_credentials"] = h.awsCredentialOutput(data.AWSCredentials)
	}

	if len(data.Extra) > 0 {
		for k, v := range data.Extra {
			output[k] = v
		}
	}

	return output
}

// awsCredentialOutput creates AWS CLI compatible output.
func (h *JSONHandler) awsCredentialOutput(creds *AWSCredentials) map[string]interface{} {
	output := map[string]interface{}{
		"Version":         1,
		"AccessKeyId":     creds.AccessKeyID,
		"SecretAccessKey": creds.SecretAccessKey,
		"SessionToken":    creds.SessionToken,
	}

	if !creds.Expiration.IsZero() {
		output["Expiration"] = creds.Expiration.Format("2006-01-02T15:04:05Z")
	}

	return output
}

// WithWriter sets the output destination.
func (h *JSONHandler) WithWriter(w io.Writer) *JSONHandler {
	h.Writer = w
	return h
}

// WithIndent enables pretty-printing.
func (h *JSONHandler) WithIndent(indent bool) *JSONHandler {
	h.Indent = indent
	return h
}

// WithAWSOnly outputs only AWS credentials.
func (h *JSONHandler) WithAWSOnly() *JSONHandler {
	h.AWSOnly = true
	return h
}

// WithOmitEmpty excludes empty fields.
func (h *JSONHandler) WithOmitEmpty() *JSONHandler {
	h.OmitEmpty = true
	return h
}
