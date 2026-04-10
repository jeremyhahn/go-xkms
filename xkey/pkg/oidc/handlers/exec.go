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
	"os/exec"
)

// ExecHandler executes a command and passes token data as environment variables.
type ExecHandler struct {
	// Command is the command to execute (parsed by shell).
	Command string

	// Shell is the shell to use (defaults to /bin/sh).
	Shell string

	// Env contains additional environment variables.
	Env map[string]string

	// Stdin is the input to pass to the command (optional).
	Stdin io.Reader

	// Stdout is where command output goes (defaults to os.Stdout).
	Stdout io.Writer

	// Stderr is where command errors go (defaults to os.Stderr).
	Stderr io.Writer

	// PassJSON passes token data as JSON via stdin.
	PassJSON bool
}

// NewExecHandler creates a new exec handler.
func NewExecHandler(command string) *ExecHandler {
	return &ExecHandler{
		Command: command,
		Shell:   "/bin/sh",
		Env:     make(map[string]string),
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	}
}

// Handle executes the command with token data available.
func (h *ExecHandler) Handle(ctx context.Context, data *TokenData) error {
	if err := ValidateTokenData(data); err != nil {
		return err
	}
	if h.Command == "" {
		return ErrExecCommandRequired
	}

	shell := h.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	cmd := exec.CommandContext(ctx, shell, "-c", h.Command)

	// Set up standard file descriptors
	cmd.Stdout = h.Stdout
	cmd.Stderr = h.Stderr

	// Build environment variables from token data
	env := os.Environ()
	env = append(env, h.tokenEnvVars(data)...)

	// Add custom environment variables
	for k, v := range h.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	// Pass JSON via stdin if requested
	if h.PassJSON {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrJSONMarshalFailed, err)
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrExecCommandFailed, err)
		}
		go func() {
			defer stdin.Close()
			stdin.Write(jsonData)
		}()
	} else if h.Stdin != nil {
		cmd.Stdin = h.Stdin
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %v", ErrExecCommandFailed, err)
	}

	return nil
}

// Name returns the handler's identifier.
func (h *ExecHandler) Name() string {
	return "exec"
}

// tokenEnvVars converts token data to environment variables.
func (h *ExecHandler) tokenEnvVars(data *TokenData) []string {
	var env []string

	// Standard OIDC tokens
	if data.AccessToken != "" {
		env = append(env, "OIDC_ACCESS_TOKEN="+data.AccessToken)
	}
	if data.RefreshToken != "" {
		env = append(env, "OIDC_REFRESH_TOKEN="+data.RefreshToken)
	}
	if data.IDToken != "" {
		env = append(env, "OIDC_ID_TOKEN="+data.IDToken)
	}
	if data.TokenType != "" {
		env = append(env, "OIDC_TOKEN_TYPE="+data.TokenType)
	}
	if data.ExpiresIn > 0 {
		env = append(env, fmt.Sprintf("OIDC_EXPIRES_IN=%d", data.ExpiresIn))
	}
	if !data.Expiry.IsZero() {
		env = append(env, "OIDC_EXPIRY="+data.Expiry.Format("2006-01-02T15:04:05Z07:00"))
	}
	if data.Scope != "" {
		env = append(env, "OIDC_SCOPE="+data.Scope)
	}

	// AWS credentials (if present)
	if data.AWSCredentials != nil {
		env = append(env, "AWS_ACCESS_KEY_ID="+data.AWSCredentials.AccessKeyID)
		env = append(env, "AWS_SECRET_ACCESS_KEY="+data.AWSCredentials.SecretAccessKey)
		env = append(env, "AWS_SESSION_TOKEN="+data.AWSCredentials.SessionToken)
		if data.AWSCredentials.Region != "" {
			env = append(env, "AWS_REGION="+data.AWSCredentials.Region)
			env = append(env, "AWS_DEFAULT_REGION="+data.AWSCredentials.Region)
		}
		if !data.AWSCredentials.Expiration.IsZero() {
			env = append(env, "AWS_CREDENTIAL_EXPIRATION="+data.AWSCredentials.Expiration.Format("2006-01-02T15:04:05Z"))
		}
	}

	return env
}

// WithShell sets the shell to use.
func (h *ExecHandler) WithShell(shell string) *ExecHandler {
	h.Shell = shell
	return h
}

// WithEnv adds an environment variable.
func (h *ExecHandler) WithEnv(key, value string) *ExecHandler {
	h.Env[key] = value
	return h
}

// WithPassJSON enables passing token data as JSON via stdin.
func (h *ExecHandler) WithPassJSON() *ExecHandler {
	h.PassJSON = true
	return h
}

// WithStdout sets the stdout destination.
func (h *ExecHandler) WithStdout(w io.Writer) *ExecHandler {
	h.Stdout = w
	return h
}

// WithStderr sets the stderr destination.
func (h *ExecHandler) WithStderr(w io.Writer) *ExecHandler {
	h.Stderr = w
	return h
}
