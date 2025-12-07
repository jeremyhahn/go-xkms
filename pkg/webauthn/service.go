// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package webauthn

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Service provides WebAuthn registration and authentication operations.
type Service struct {
	webauthn   *webauthn.WebAuthn
	config     *Config
	users      UserStore
	sessions   SessionStore
	creds      CredentialStore
	jwtGen     JWTGenerator // optional
	configured bool
}

// ServiceParams contains dependencies for creating a WebAuthn service.
type ServiceParams struct {
	// Config is the WebAuthn configuration (required).
	Config *Config

	// UserStore is the user persistence layer (required).
	UserStore UserStore

	// SessionStore is the session persistence layer (required).
	SessionStore SessionStore

	// CredentialStore is the credential persistence layer (required).
	CredentialStore CredentialStore

	// JWTGenerator is an optional token generator for post-auth tokens.
	// If nil, the service returns the base64-encoded user ID after auth.
	JWTGenerator JWTGenerator
}

// NewService creates a new WebAuthn service with the provided dependencies.
func NewService(params ServiceParams) (*Service, error) {
	if params.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if params.UserStore == nil {
		return nil, fmt.Errorf("user store is required")
	}
	if params.SessionStore == nil {
		return nil, fmt.Errorf("session store is required")
	}
	if params.CredentialStore == nil {
		return nil, fmt.Errorf("credential store is required")
	}

	// Set defaults and validate
	params.Config.SetDefaults()
	if err := params.Config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create the go-webauthn instance
	wa, err := webauthn.New(params.Config.ToWebAuthnConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn instance: %w", err)
	}

	return &Service{
		webauthn:   wa,
		config:     params.Config,
		users:      params.UserStore,
		sessions:   params.SessionStore,
		creds:      params.CredentialStore,
		jwtGen:     params.JWTGenerator,
		configured: true,
	}, nil
}

// BeginRegistration starts the WebAuthn registration ceremony.
// Returns the registration options to be sent to the client and a session ID.
func (s *Service) BeginRegistration(ctx context.Context, email, displayName string) (*protocol.CredentialCreation, string, error) {
	if !s.configured {
		return nil, "", ErrNotConfigured
	}

	// Try to get existing user or create new one
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if !IsUserNotFound(err) {
			return nil, "", WrapError("get user by email", err)
		}
		// Create new user
		user, err = s.users.Create(ctx, email, displayName)
		if err != nil {
			return nil, "", WrapError("create user", err)
		}
	}

	// Get existing credentials to exclude
	existingCreds, err := s.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		return nil, "", WrapError("get credentials", err)
	}

	// Convert to exclude list
	excludeList := make([]protocol.CredentialDescriptor, len(existingCreds))
	for i, cred := range existingCreds {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
			Transport:    cred.Transport,
		}
	}

	// Begin registration with exclude list
	options, session, err := s.webauthn.BeginRegistration(user,
		webauthn.WithExclusions(excludeList),
	)
	if err != nil {
		return nil, "", WrapError("begin registration", err)
	}

	// Store session
	sessionID, err := s.sessions.Save(ctx, session)
	if err != nil {
		return nil, "", WrapError("save session", err)
	}

	return options, sessionID, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
// Returns a token (JWT if configured, otherwise base64 user ID) and the user.
func (s *Service) FinishRegistration(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData) (string, User, error) {
	if !s.configured {
		return "", nil, ErrNotConfigured
	}

	// Get session
	session, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		return "", nil, WrapError("get session", err)
	}

	// Get user
	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		return "", nil, WrapError("get user", err)
	}

	// Finish registration
	credential, err := s.webauthn.CreateCredential(user, *session, response)
	if err != nil {
		return "", nil, WrapError("create credential", err)
	}

	// Convert and store credential
	cred := FromWebAuthnCredential(user.WebAuthnID(), credential)
	if err := s.creds.Save(ctx, cred); err != nil {
		return "", nil, WrapError("save credential", err)
	}

	// Add credential to user
	user.AddCredential(cred)
	if err := s.users.Save(ctx, user); err != nil {
		return "", nil, WrapError("save user", err)
	}

	// Delete session
	if err := s.sessions.Delete(ctx, sessionID); err != nil {
		// Log but don't fail - session cleanup is best-effort
		_ = err
	}

	// Generate token
	token, err := s.generateToken(ctx, user)
	if err != nil {
		return "", nil, WrapError("generate token", err)
	}

	return token, user, nil
}

// BeginLogin starts the WebAuthn authentication ceremony.
// If userID is nil, returns options for discoverable credentials (passkeys).
func (s *Service) BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
	if !s.configured {
		return nil, "", ErrNotConfigured
	}

	var options *protocol.CredentialAssertion
	var session *webauthn.SessionData
	var err error

	if userID == nil {
		// Discoverable credentials flow
		options, session, err = s.webauthn.BeginDiscoverableLogin()
	} else {
		// User-identified flow
		user, userErr := s.users.GetByID(ctx, userID)
		if userErr != nil {
			return nil, "", WrapError("get user", userErr)
		}

		// Check if user has credentials
		creds, credErr := s.creds.GetByUserID(ctx, userID)
		if credErr != nil {
			return nil, "", WrapError("get credentials", credErr)
		}
		if len(creds) == 0 {
			return nil, "", ErrNoCredentials
		}

		options, session, err = s.webauthn.BeginLogin(user)
	}

	if err != nil {
		return nil, "", WrapError("begin login", err)
	}

	// Store session
	sessionID, err := s.sessions.Save(ctx, session)
	if err != nil {
		return nil, "", WrapError("save session", err)
	}

	return options, sessionID, nil
}

// FinishLogin completes the WebAuthn authentication ceremony.
// For discoverable credentials, userID can be nil.
// Returns a token (JWT if configured, otherwise base64 user ID) and the user.
func (s *Service) FinishLogin(ctx context.Context, sessionID string, userID []byte, response *protocol.ParsedCredentialAssertionData) (string, User, error) {
	if !s.configured {
		return "", nil, ErrNotConfigured
	}

	// Get session
	session, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		return "", nil, WrapError("get session", err)
	}

	var user User
	var credential *webauthn.Credential

	if userID == nil {
		// Discoverable credentials flow - find user by credential
		credential, err = s.webauthn.ValidateDiscoverableLogin(
			s.discoverableUserHandler(ctx),
			*session,
			response,
		)
		if err != nil {
			return "", nil, WrapError("validate discoverable login", err)
		}

		// Get user from credential
		cred, credErr := s.creds.GetByCredentialID(ctx, credential.ID)
		if credErr != nil {
			return "", nil, WrapError("get credential", credErr)
		}
		user, err = s.users.GetByID(ctx, cred.UserID)
		if err != nil {
			return "", nil, WrapError("get user", err)
		}
	} else {
		// User-identified flow
		user, err = s.users.GetByID(ctx, userID)
		if err != nil {
			return "", nil, WrapError("get user", err)
		}

		credential, err = s.webauthn.ValidateLogin(user, *session, response)
		if err != nil {
			return "", nil, WrapError("validate login", err)
		}
	}

	// Update credential sign counter
	cred, err := s.creds.GetByCredentialID(ctx, credential.ID)
	if err != nil {
		return "", nil, WrapError("get credential for update", err)
	}
	cred.Authenticator.SignCount = credential.Authenticator.SignCount
	cred.Authenticator.CloneWarning = credential.Authenticator.CloneWarning
	cred.LastUsedAt = time.Now().UTC()

	if err := s.creds.Update(ctx, cred); err != nil {
		return "", nil, WrapError("update credential", err)
	}

	// Update user's credential
	user.UpdateCredential(cred)
	if err := s.users.Save(ctx, user); err != nil {
		return "", nil, WrapError("save user", err)
	}

	// Delete session
	if err := s.sessions.Delete(ctx, sessionID); err != nil {
		// Log but don't fail
		_ = err
	}

	// Generate token
	token, err := s.generateToken(ctx, user)
	if err != nil {
		return "", nil, WrapError("generate token", err)
	}

	return token, user, nil
}

// IsRegistered checks if a user has any registered credentials.
func (s *Service) IsRegistered(ctx context.Context, userID []byte) (bool, error) {
	if !s.configured {
		return false, ErrNotConfigured
	}

	if userID == nil {
		return false, nil
	}

	creds, err := s.creds.GetByUserID(ctx, userID)
	if err != nil {
		return false, WrapError("get credentials", err)
	}

	return len(creds) > 0, nil
}

// GetUser retrieves a user by their WebAuthn ID.
func (s *Service) GetUser(ctx context.Context, userID []byte) (User, error) {
	if !s.configured {
		return nil, ErrNotConfigured
	}

	return s.users.GetByID(ctx, userID)
}

// GetUserByEmail retrieves a user by their email address.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (User, error) {
	if !s.configured {
		return nil, ErrNotConfigured
	}

	return s.users.GetByEmail(ctx, email)
}

// GetCredentials retrieves all credentials for a user.
func (s *Service) GetCredentials(ctx context.Context, userID []byte) ([]*Credential, error) {
	if !s.configured {
		return nil, ErrNotConfigured
	}

	return s.creds.GetByUserID(ctx, userID)
}

// DeleteCredential removes a credential.
func (s *Service) DeleteCredential(ctx context.Context, credID []byte) error {
	if !s.configured {
		return ErrNotConfigured
	}

	return s.creds.Delete(ctx, credID)
}

// DeleteUser removes a user and all their credentials.
func (s *Service) DeleteUser(ctx context.Context, userID []byte) error {
	if !s.configured {
		return ErrNotConfigured
	}

	// Delete all credentials first
	if err := s.creds.DeleteByUserID(ctx, userID); err != nil {
		return WrapError("delete user credentials", err)
	}

	// Delete user
	return s.users.Delete(ctx, userID)
}

// Config returns the service configuration.
func (s *Service) Config() *Config {
	return s.config
}

// generateToken creates a token for the authenticated user.
func (s *Service) generateToken(ctx context.Context, user User) (string, error) {
	if s.jwtGen != nil {
		return s.jwtGen.GenerateToken(ctx, user)
	}
	// Default: return base64-encoded user ID
	return base64.RawURLEncoding.EncodeToString(user.WebAuthnID()), nil
}

// discoverableUserHandler returns a handler for discoverable credential login.
func (s *Service) discoverableUserHandler(ctx context.Context) func(rawID, userHandle []byte) (webauthn.User, error) {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		// Try to find user by user handle
		user, err := s.users.GetByID(ctx, userHandle)
		if err != nil {
			return nil, err
		}
		return user, nil
	}
}
