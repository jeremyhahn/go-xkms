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

package oidc

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// The codex CLI keeps a ChatGPT login in $CODEX_HOME/auth.json. Its shape is
// the AuthDotJson struct of openai/codex codex-rs/login/src/auth/storage.rs:
//
//	{
//	  "auth_mode": "chatgpt" | "chatgptAuthTokens" | ...,   (optional)
//	  "OPENAI_API_KEY": null,
//	  "tokens": {"id_token": "<JWT>", "access_token": "<JWT>",
//	             "refresh_token": "...", "account_id": "..."},
//	  "last_refresh": "<RFC 3339>"
//	}
//
// id_token is the raw JWT string (codex parses its claims on read and writes
// the raw string back). In the "chatgptAuthTokens" mode the tokens are owned
// by a host application: codex never refreshes them itself (its
// refresh_token_from_authority_impl returns early for that mode and
// should_refresh_proactively answers false), which is the mode a server that
// owns the refresh hands a workload.

const (
	// CodexAuthModeChatGPT is codex's own ChatGPT login: codex refreshes it.
	CodexAuthModeChatGPT = "chatgpt"

	// CodexAuthModeChatGPTAuthTokens is ChatGPT tokens supplied by a host
	// application: codex uses them and never refreshes them.
	CodexAuthModeChatGPTAuthTokens = "chatgptAuthTokens"

	// codexAuthClaim is the namespaced claim carrying the ChatGPT account.
	codexAuthClaim = "https://api.openai.com/auth"
)

var (
	// ErrCodexAuthInvalid is returned when an auth.json is not JSON, or
	// holds no ChatGPT tokens.
	ErrCodexAuthInvalid = errors.New("oidc: invalid codex auth.json")

	// ErrCodexAuthMode is returned when an auth.json is in a mode other than
	// a ChatGPT login (an API key, a personal access token, Bedrock ...).
	ErrCodexAuthMode = errors.New("oidc: codex auth.json is not a ChatGPT login")

	// ErrCodexIDTokenRequired is returned when a codex auth.json is to be
	// written without the ID token codex requires.
	ErrCodexIDTokenRequired = errors.New("oidc: codex auth.json needs an ID token")
)

// codexAuthFile is the on-disk shape of codex's auth.json.
type codexAuthFile struct {
	AuthMode     string           `json:"auth_mode,omitempty"`
	OpenAIAPIKey *string          `json:"OPENAI_API_KEY"`
	Tokens       *codexAuthTokens `json:"tokens,omitempty"`
	LastRefresh  *time.Time       `json:"last_refresh,omitempty"`
}

// codexAuthTokens is auth.json's "tokens" object.
type codexAuthTokens struct {
	IDToken      string  `json:"id_token"`
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	AccountID    *string `json:"account_id"`
}

// CodexAuth is a ChatGPT login read from a codex auth.json.
type CodexAuth struct {
	// Mode is the file's auth_mode ("" when the file names none, which
	// codex reads as its own ChatGPT login).
	Mode string

	// Tokens are the login's tokens. Expiry is the access token's "exp"
	// claim, since auth.json does not record the expiry.
	Tokens *TokenResponse

	// AccountID is the ChatGPT account the tokens belong to.
	AccountID string

	// LastRefresh is when codex last refreshed the login, or zero.
	LastRefresh time.Time
}

// ParseCodexAuth reads a ChatGPT login from the contents of a codex
// auth.json, so it can be imported without logging in again.
func ParseCodexAuth(data []byte) (*CodexAuth, error) {
	var file codexAuthFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrCodexAuthInvalid, Cause: err}
	}
	switch file.AuthMode {
	case "", CodexAuthModeChatGPT, CodexAuthModeChatGPTAuthTokens:
	default:
		return nil, &DetailError{Err: ErrCodexAuthMode, Detail: ": " + SanitizeProviderText(file.AuthMode)}
	}
	if file.Tokens == nil || file.Tokens.AccessToken == "" {
		return nil, &DetailError{Err: ErrCodexAuthInvalid, Detail: ": no ChatGPT tokens"}
	}

	tokens := &TokenResponse{
		AccessToken:  file.Tokens.AccessToken,
		RefreshToken: file.Tokens.RefreshToken,
		IDToken:      file.Tokens.IDToken,
		TokenType:    "Bearer",
	}
	tokens.Expiry = tokens.ExpiresAt()

	auth := &CodexAuth{Mode: file.AuthMode, Tokens: tokens}
	if file.Tokens.AccountID != nil {
		auth.AccountID = *file.Tokens.AccountID
	}
	if auth.AccountID == "" {
		auth.AccountID = CodexAccountID(file.Tokens.IDToken)
	}
	if file.LastRefresh != nil {
		auth.LastRefresh = *file.LastRefresh
	}
	return auth, nil
}

// CodexAccountID returns the ChatGPT account named by an OpenAI ID token's
// "https://api.openai.com/auth" claim, or "" when it names none. The claim is
// read without verifying the token (see UnverifiedClaims).
func CodexAccountID(idToken string) string {
	claims, ok := UnverifiedClaims(idToken)
	if !ok {
		return ""
	}
	auth, ok := claims[codexAuthClaim].(map[string]any)
	if !ok {
		return ""
	}
	account, _ := auth["chatgpt_account_id"].(string)
	return strings.TrimSpace(account)
}

// CodexAuthTokensFile renders a codex auth.json in the "chatgptAuthTokens"
// mode for the given access and ID tokens: codex uses the tokens and never
// refreshes them, so the server that owns the login stays the only party
// that redeems its refresh token. The refresh token is deliberately written
// empty -- it never leaves the server. accountID defaults to the account
// the ID token names.
func CodexAuthTokensFile(accessToken, idToken, accountID string, now time.Time) ([]byte, error) {
	if accessToken == "" {
		return nil, &DetailError{Err: ErrCodexAuthInvalid, Detail: ": no access token"}
	}
	if idToken == "" {
		return nil, ErrCodexIDTokenRequired
	}
	if accountID == "" {
		accountID = CodexAccountID(idToken)
	}
	var account *string
	if accountID != "" {
		account = &accountID
	}
	refreshed := now.UTC()
	file := codexAuthFile{
		AuthMode: CodexAuthModeChatGPTAuthTokens,
		Tokens: &codexAuthTokens{
			IDToken:     idToken,
			AccessToken: accessToken,
			AccountID:   account,
		},
		LastRefresh: &refreshed,
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrCodexAuthInvalid, Cause: err}
	}
	return data, nil
}
