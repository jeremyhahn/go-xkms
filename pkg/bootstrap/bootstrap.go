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

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/user"
)

// Bootstrap state constants.
const (
	// StateUninitialized indicates no setup token has been generated.
	StateUninitialized = "uninitialized"

	// StateReady indicates a setup token has been generated and the system
	// is ready for the first admin to initialize.
	StateReady = "ready"

	// StateCeremony indicates threshold mode is active and waiting for
	// additional admin registrations.
	StateCeremony = "ceremony"

	// StateComplete indicates the system has been fully initialized.
	StateComplete = "complete"

	// defaultTokenTTL is the default validity period for a setup token.
	defaultTokenTTL = 1 * time.Hour

	// tokenByteLength is the number of random bytes in a setup token.
	tokenByteLength = 32
)

// Config configures the bootstrap service.
type Config struct {
	// TokenTTL is how long the setup token is valid (default: 1 hour).
	TokenTTL time.Duration `json:"token_ttl,omitempty"`

	// ThresholdMode enables M-of-N admin initialization.
	ThresholdMode bool `json:"threshold_mode,omitempty"`

	// AdminThreshold is M for threshold mode (minimum admins required).
	AdminThreshold int `json:"admin_threshold,omitempty"`

	// AdminTotal is N for threshold mode (total admins to register).
	AdminTotal int `json:"admin_total,omitempty"`
}

// SetupToken represents the one-time setup token for bootstrap.
type SetupToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
}

// InitRequest is the atomic initialization request.
type InitRequest struct {
	// SetupToken is the one-time setup token.
	SetupToken string `json:"setup_token"`

	// Username for the admin account.
	Username string `json:"username"`

	// DisplayName for the admin (optional, defaults to username).
	DisplayName string `json:"display_name,omitempty"`

	// FIDO2Attestation is the WebAuthn attestation response (base64 JSON).
	FIDO2Attestation json.RawMessage `json:"fido2_attestation"`
}

// InitResponse is returned after successful initialization.
type InitResponse struct {
	// UserID of the created admin.
	UserID string `json:"user_id"`

	// Username of the created admin.
	Username string `json:"username"`

	// JWT for immediate API access.
	JWT string `json:"jwt,omitempty"`

	// ServerInfo contains server identification.
	ServerInfo *ServerInfo `json:"server_info,omitempty"`
}

// ServerInfo contains server identification details.
type ServerInfo struct {
	// SPKIPin is the SHA-256 SPKI fingerprint of the server's TLS cert.
	SPKIPin string `json:"spki_pin"`

	// Hostname is the server's hostname.
	Hostname string `json:"hostname"`

	// Version is the server version.
	Version string `json:"version"`
}

// ThresholdInitRequest is for threshold mode admin registration.
type ThresholdInitRequest struct {
	// SetupToken is the one-time setup token (used by the first admin only).
	SetupToken string `json:"setup_token,omitempty"`

	// Invitation is the invitation token (used by subsequent admins).
	Invitation string `json:"invitation,omitempty"`

	// Username for the admin account.
	Username string `json:"username"`

	// DisplayName for the admin (optional, defaults to username).
	DisplayName string `json:"display_name,omitempty"`

	// FIDO2Attestation is the WebAuthn attestation response (base64 JSON).
	FIDO2Attestation json.RawMessage `json:"fido2_attestation"`
}

// ThresholdInvitation is a time-limited invitation for additional admins.
type ThresholdInvitation struct {
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
	Used       bool      `json:"used"`
	AdminIndex int       `json:"admin_index"` // 2..N (first admin uses setup token)
}

// Service manages the bootstrap lifecycle for first-time server
// initialization. It provides a secure mechanism for generating setup tokens,
// validating them, and atomically creating the first admin user.
type Service struct {
	mu          sync.RWMutex
	config      Config
	state       string
	setupToken  *SetupToken
	invitations map[string]*ThresholdInvitation
	userStore   user.Store
	logger      *slog.Logger
}

// NewService creates a new bootstrap service.
func NewService(config Config, userStore user.Store, logger *slog.Logger) (*Service, error) {
	if userStore == nil {
		return nil, ErrNilUserStore
	}
	if logger == nil {
		return nil, ErrNilLogger
	}

	// Apply defaults
	if config.TokenTTL == 0 {
		config.TokenTTL = defaultTokenTTL
	}

	// Validate threshold config
	if config.ThresholdMode {
		if config.AdminThreshold <= 0 || config.AdminTotal <= 0 || config.AdminThreshold > config.AdminTotal {
			return nil, ErrThresholdConfig
		}
	}

	svc := &Service{
		config:      config,
		state:       StateUninitialized,
		invitations: make(map[string]*ThresholdInvitation),
		userStore:   userStore,
		logger:      logger,
	}

	// Check if users already exist, which means bootstrap is already complete
	hasUsers, err := userStore.HasAnyUsers(context.Background())
	if err != nil {
		return nil, err
	}
	if hasUsers {
		svc.state = StateComplete
	}

	return svc, nil
}

// State returns the current bootstrap state.
func (s *Service) State() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// IsInitialized returns true if bootstrap is complete.
func (s *Service) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state == StateComplete
}

// GenerateSetupToken creates a new one-time setup token. It can only be called
// when the system is in the Uninitialized state. The token is a base64url-encoded
// 32-byte cryptographically random value.
func (s *Service) GenerateSetupToken() (*SetupToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateComplete {
		return nil, ErrAlreadyInitialized
	}
	if s.state == StateCeremony {
		return nil, ErrNotReady
	}

	tokenBytes := make([]byte, tokenByteLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	token := &SetupToken{
		Token:     base64.RawURLEncoding.EncodeToString(tokenBytes),
		ExpiresAt: now.Add(s.config.TokenTTL),
		Used:      false,
		CreatedAt: now,
	}

	s.setupToken = token
	s.state = StateReady

	s.logger.Info("Bootstrap setup token generated",
		slog.Time("expires_at", token.ExpiresAt))

	return token, nil
}

// ValidateSetupToken checks if the provided token is valid, not expired, and not used.
func (s *Service) ValidateSetupToken(token string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.validateSetupTokenLocked(token)
}

// validateSetupTokenLocked performs token validation while the caller holds at least a read lock.
func (s *Service) validateSetupTokenLocked(token string) error {
	if token == "" {
		return ErrEmptyToken
	}

	if s.setupToken == nil {
		return ErrNoToken
	}

	if s.setupToken.Used {
		return ErrTokenUsed
	}

	if time.Now().UTC().After(s.setupToken.ExpiresAt) {
		return ErrTokenExpired
	}

	// Constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.setupToken.Token)) != 1 {
		return ErrInvalidToken
	}

	return nil
}

// ConsumeSetupToken atomically marks the setup token as used. Returns an error
// if the token is invalid, expired, or already consumed.
func (s *Service) ConsumeSetupToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateSetupTokenLocked(token); err != nil {
		return err
	}

	s.setupToken.Used = true

	s.logger.Info("Bootstrap setup token consumed")

	return nil
}

// Initialize performs the atomic system initialization: validates the setup token,
// creates the first admin user, and transitions to the Complete state. If user
// creation fails, the setup token is NOT consumed, ensuring all-or-nothing semantics.
//
// Note: FIDO2 registration is handled by the REST handler using webauthn.Service;
// this method handles token validation and user creation only.
func (s *Service) Initialize(ctx context.Context, req *InitRequest) (*InitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate state
	if s.state == StateComplete {
		return nil, ErrAlreadyInitialized
	}
	if s.state != StateReady {
		return nil, ErrNotReady
	}

	// Validate request
	if req == nil {
		return nil, ErrInvalidRequest
	}
	if req.Username == "" {
		return nil, ErrEmptyUsername
	}
	if len(req.FIDO2Attestation) == 0 {
		return nil, ErrEmptyAttestation
	}

	// Validate token (before creating user to fail fast)
	if err := s.validateSetupTokenLocked(req.SetupToken); err != nil {
		return nil, err
	}

	// Determine display name
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	// Create the admin user -- if this fails, the token is NOT consumed.
	adminUser, err := s.userStore.Create(ctx, req.Username, displayName, user.RoleAdmin, "")
	if err != nil {
		if err == user.ErrUserAlreadyExists {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}

	// User creation succeeded -- now consume the token atomically.
	s.setupToken.Used = true

	// Transition to Complete (or Ceremony for threshold mode)
	if s.config.ThresholdMode {
		s.state = StateCeremony
	} else {
		s.state = StateComplete
	}

	s.logger.Info("Bootstrap initialization complete",
		slog.String("username", adminUser.Username),
		slog.String("state", s.state))

	return &InitResponse{
		UserID:   base64.RawURLEncoding.EncodeToString(adminUser.ID),
		Username: adminUser.Username,
	}, nil
}

// GenerateInvitations creates invitation tokens for additional admins in threshold mode.
// It can only be called when the system is in the Ceremony state.
func (s *Service) GenerateInvitations(count int) ([]*ThresholdInvitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateCeremony {
		if s.state == StateComplete {
			return nil, ErrCeremonyComplete
		}
		return nil, ErrCeremonyNotStarted
	}

	if count <= 0 {
		return nil, ErrInvalidRequest
	}

	// Capture starting offset before the loop so AdminIndex is consistent
	// as invitations are added to the map within the loop.
	startIndex := len(s.invitations) + 2 // +2 because first admin is index 1

	invitations := make([]*ThresholdInvitation, 0, count)
	for i := 0; i < count; i++ {
		tokenBytes := make([]byte, tokenByteLength)
		if _, err := rand.Read(tokenBytes); err != nil {
			return nil, err
		}

		now := time.Now().UTC()
		inv := &ThresholdInvitation{
			Token:      base64.RawURLEncoding.EncodeToString(tokenBytes),
			ExpiresAt:  now.Add(s.config.TokenTTL),
			Used:       false,
			AdminIndex: startIndex + i,
		}

		s.invitations[inv.Token] = inv
		invitations = append(invitations, inv)
	}

	s.logger.Info("Bootstrap invitations generated",
		slog.Int("count", count))

	return invitations, nil
}

// ValidateInvitation checks if an invitation token is valid, not expired, and not used.
func (s *Service) ValidateInvitation(token string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.validateInvitationLocked(token)
}

// validateInvitationLocked performs invitation validation while the caller holds at least a read lock.
func (s *Service) validateInvitationLocked(token string) error {
	if token == "" {
		return ErrEmptyToken
	}

	if s.state != StateCeremony {
		if s.state == StateComplete {
			return ErrCeremonyComplete
		}
		return ErrCeremonyNotStarted
	}

	inv, ok := s.invitations[token]
	if !ok {
		return ErrInvalidInvitation
	}

	if inv.Used {
		return ErrInvitationUsed
	}

	if time.Now().UTC().After(inv.ExpiresAt) {
		return ErrInvitationExpired
	}

	return nil
}

// ConsumeInvitation atomically marks an invitation as used.
func (s *Service) ConsumeInvitation(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateInvitationLocked(token); err != nil {
		return err
	}

	s.invitations[token].Used = true

	// Check if we have enough admins to complete the ceremony
	adminCount, err := s.userStore.CountAdmins(context.Background())
	if err != nil {
		return err
	}

	if adminCount >= s.config.AdminTotal {
		s.state = StateComplete
		s.logger.Info("Bootstrap threshold ceremony complete",
			slog.Int("admin_count", adminCount),
			slog.Int("threshold", s.config.AdminThreshold))
	}

	return nil
}
