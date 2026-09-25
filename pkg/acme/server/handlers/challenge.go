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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// loopbackIdentifier is the permanent-identifier value that, for enrollment
// challenges, is eligible for substitution with the request's client IP when
// acme.enrollment.allow_loopback_identifier is enabled.
const loopbackIdentifier = "127.0.0.1"

func (s *RestService) ChallengeHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("ChallengeHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	if r.Method != http.MethodPost {
		writeError(w, common.MalformedError("Method not allowed", nil))
		return
	}

	pieces := strings.Split(r.URL.Path, "/")
	sChallengeID := pieces[len(pieces)-1]
	if sChallengeID == "" {
		http.Error(w, "Authorization ID not provided", http.StatusBadRequest)
		return
	}

	challengeID, err := strconv.ParseUint(sChallengeID, 10, 64)
	if err != nil {
		writeError(w, common.MalformedError("Invalid challenge ID", nil))
		return
	}

	account, _, err := s.parseKID(ctx, r)
	if err != nil {
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	authzDAO, err := s.storageFactory.AuthorizationDAO(account.ID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create authorization DAO"))
		return
	}

	orderDAO, err := s.storageFactory.OrderDAO(account.ID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create order DAO"))
		return
	}

	var authz *entities.ACMEAuthorization
	var challenge *entities.ACMEChallenge

	// List all authorizations for this account
	var authzList []*entities.ACMEAuthorization
	err = authzDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAuthorization]) error {
		authzList = append(authzList, page.Entities...)
		return nil
	})
	if err != nil {
		s.logger.Error("Failed to list authorizations", slog.String("error", err.Error()), slog.Uint64("accountID", account.ID))
		writeError(w, common.ServerInternal("Failed to retrieve authorizations"))
		return
	}

	s.logger.Debug("ChallengeHandler: searching for challenge",
		slog.Uint64("challengeID", challengeID),
		slog.Uint64("accountID", account.ID),
		slog.Int("authzCount", len(authzList)))

	// Find the authorization containing the challenge
	found := false
	for _, _authz := range authzList {
		s.logger.Debug("ChallengeHandler: checking authorization",
			slog.Uint64("authzID", _authz.ID),
			slog.Uint64("authzAccountID", _authz.AccountID),
			slog.Int("challengeCount", len(_authz.Challenges)))
		for _, _challenge := range _authz.Challenges {
			s.logger.Debug("ChallengeHandler: checking challenge",
				slog.Uint64("storedChallengeID", _challenge.ID),
				slog.Uint64("requestedChallengeID", challengeID),
				slog.Uint64("challengeAccountID", _challenge.AccountID))
			if _challenge.ID == challengeID && _authz.AccountID == _challenge.AccountID {
				authz = _authz
				challenge = &_challenge
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		s.logger.Warn("ChallengeHandler: challenge not found",
			slog.Uint64("challengeID", challengeID),
			slog.Uint64("accountID", account.ID),
			slog.Int("authzCount", len(authzList)))
		writeError(w, common.MalformedError("Challenge not found", nil))
		return
	}

	// Validate EAB authorization for endorse-01 challenges
	if IsEndorseChallengeType(challenge.Type) && s.endorseEABRequired {
		eabDAO, err := s.storageFactory.ExternalAccountBindingDAO()
		if err != nil {
			s.logger.Error("Failed to create EAB DAO for endorse-01 validation", slog.String("error", err.Error()))
			writeError(w, common.ServerInternal("Failed to validate authorization"))
			return
		}

		validator := NewEndorseEABValidator(eabDAO, s.endorseEABRequired, s.endorseDeviceIDMetaKey)
		eabAuth, err := validator.ValidateEndorseAuthorization(ctx, account, authz.Identifier.Value)
		if err != nil {
			s.logger.Warn("EAB authorization failed for endorse-01 challenge",
				slog.String("error", err.Error()),
				slog.Uint64("accountID", account.ID),
				slog.String("challengeType", challenge.Type))
			writeError(w, common.Unauthorized("Account not authorized for endorse-01 challenge: "+err.Error()))
			return
		}

		s.logger.Info("EAB authorization validated for endorse-01 challenge",
			slog.Uint64("accountID", account.ID),
			slog.String("externalAccountID", eabAuth.ExternalAccountID),
			slog.String("authorizedDeviceID", eabAuth.AuthorizedDeviceID))
	}

	// If the challenge is not in "pending" state, return it as is
	if challenge.Status != common.StatusPending {
		s.writeChallengeResponse(w, challenge)
		return
	}

	// Transition challenge to "processing"
	challenge.Status = common.StatusProcessing
	if err := authzDAO.Save(ctx, authz); err != nil {
		writeError(w, common.ServerInternal("Failed to update challenge status"))
		return
	}

	// Perform challenge validation
	var validationSuccessful bool

	pubKey, err := xkmssdk.DecodePublicKeyPEM([]byte(account.Key))
	if err != nil {
		challenge.Status = common.StatusInvalid
		challenge.Error = common.ServerInternal("Failed to decode account public key")
	}

	keyAuth, err := KeyAuthorization(challenge.Token, pubKey)
	if err != nil {
		challenge.Status = common.StatusInvalid
		challenge.Error = common.IncorrectResponse("Failed to compute key authorization")
	}

	// Parse the challenge type to extract the port number used by the challenge
	// selected by the client. The baseType is used for map lookup since challenges
	// with ports (e.g., "enroll-01-8888") should use the same verifier as base type.
	baseType, challengePort, err := parseChallengeAsDynamicPortAssignment(challenge.Type)
	if err != nil {
		writeError(w, common.MalformedError("Failed to parse challenge type", nil))
		return
	}

	// Use default ports when no explicit port is specified
	if challengePort == 0 {
		if isEnrollXChallenge(challenge.Type) {
			// Enrollment challenges default to port 8080
			challengePort = 8080
		} else if strings.HasPrefix(baseType, "http") {
			// HTTP-01 defaults to port 80
			challengePort = 80
		}
	}

	// Look up the challenge verifier from the challenge map using the base type.
	// This allows challenges like "enroll-01-8888" to use the "enroll-01" verifier.
	challengeVerifierFunc, ok := s.challengeMap[baseType]
	if !ok {
		// Fall back to exact match for challenges without port suffix
		challengeVerifierFunc, ok = s.challengeMap[challenge.Type]
	}
	if !ok {
		challenge.Status = common.StatusInvalid
		errmsg := fmt.Sprintf("Unsupported challenge type: %s", challenge.Type)
		challenge.Error = common.MalformedError(errmsg, nil)
	} else {
		// For enrollment challenges with permanent-identifier, we need the client's IP or hostname
		challengeDomain := authz.Identifier.Value
		loopbackRefused := false

		if authz.Identifier.Type == common.AuthzTypePermanentIdentifier &&
			isEnrollXChallenge(challenge.Type) {
			// Only use client IP when identifier is loopback (127.0.0.1)
			// This supports local development/testing where the device registers with the
			// loopback address but the actual challenge validation needs to reach the
			// device at its real IP. Gated by acme.enrollment.allow_loopback_identifier
			// (default false): a production deployment must refuse the substitution.
			if authz.Identifier.Value == loopbackIdentifier {
				if !s.allowLoopbackIdentifier {
					loopbackRefused = true
					s.logger.Warn("enrollment challenge refused: loopback identifier requires acme.enrollment.allow_loopback_identifier",
						"identifierValue", authz.Identifier.Value,
						"remoteAddr", r.RemoteAddr,
						"challengeType", challenge.Type)
				} else {
					// Extract the client IP from the request
					clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
					if err != nil {
						// If SplitHostPort fails, RemoteAddr might just be the IP
						clientIP = r.RemoteAddr
					}
					// Check for X-Forwarded-For header if behind a proxy
					if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
						// Use the first IP in the chain
						ips := strings.Split(xff, ",")
						if len(ips) > 0 {
							clientIP = strings.TrimSpace(ips[0])
						}
					}
					challengeDomain = clientIP

					s.logger.Info("Processing enrollment challenge with loopback override",
						"clientIP", clientIP,
						"remoteAddr", r.RemoteAddr,
						"identifierValue", authz.Identifier.Value,
						"challengeDomain", challengeDomain,
						"challengeType", challenge.Type)
				}
			} else {
				s.logger.Info("Processing enrollment challenge",
					"identifierValue", authz.Identifier.Value,
					"challengeDomain", challengeDomain,
					"challengeType", challenge.Type)
			}
		}

		if loopbackRefused {
			challenge.Status = common.StatusInvalid
			challenge.Error = common.Unauthorized(ErrLoopbackIdentifierNotAllowed.Error())
		} else {
			// Get DNS resolver - use default if not configured
			var resolver *net.Resolver
			if resolver == nil {
				resolver = net.DefaultResolver
			}

			if err := challengeVerifierFunc(
				resolver,
				s.ca,
				challengeDomain,
				fmt.Sprintf("%d", challengePort),
				challenge.Token,
				keyAuth); err != nil {

				s.logger.Warn(
					"challenge verification failed",
					slog.String("error", err.Error()),
					slog.String("challenge", challenge.Type))
				challenge.Status = common.StatusInvalid
				challenge.Error = common.IncorrectResponse(err.Error())
			} else {
				validationSuccessful = true
			}
		}
	}

	// enroll-01 and endorse-01 verification is a trust decision (proving TPM
	// residency of an identity key, or authorizing an EK-endorsement
	// request), so the audit write is part of the decision: it happens
	// before the challenge is allowed to transition to valid, and a failed
	// write refuses the challenge rather than let an unaudited attestation
	// decision stand. This mirrors the EventChallengeFailed gate below but
	// applies only to the two TPM attestation challenge families; a plain
	// http-01/dns-01 success stays covered by the existing (informational)
	// EventChallengeValidated / EventAuthorizationValidated events elsewhere
	// in the flow.
	if validationSuccessful {
		// baseType, not the broader isEnrollXChallenge/IsEndorseChallengeType
		// family checks: those both match "endorse-01" (isEnrollXChallenge
		// matches every enrollment-family type, including endorse-01 and the
		// unwired device-attest-01), so an exact match is required to tell
		// enroll-01 and endorse-01 apart here.
		var eventType audit.EventType
		switch baseType {
		case "enroll-01":
			eventType = audit.EventTPMAttestation
		case "endorse-01":
			eventType = audit.EventEndorsementVerified
		}
		if eventType != "" {
			if auditErr := s.recordAudit(eventType, s.auditLog.LogWithContext(auditContext(r),
				eventType,
				auditAccountRef(account.ID),
				"challenge:"+strconv.FormatUint(challenge.ID, 10),
				"validate",
				audit.ResultSuccess,
				map[string]interface{}{
					"challenge_type": challenge.Type,
				},
			)); auditErr != nil {
				validationSuccessful = false
				challenge.Status = common.StatusInvalid
				challenge.Error = common.ServerInternal("Failed to record audit event")
			}
		}
	}

	if validationSuccessful {
		// Validation succeeded
		challenge.Status = common.StatusValid
		challenge.Validated = time.Now().Format(time.RFC3339)
		authz.Status = common.StatusValid
		authz.Expires = time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	} else {
		// Validation failed - only set generic error if no specific error was already set
		if challenge.Error == nil {
			challenge.Status = common.StatusInvalid
			challenge.Error = common.IncorrectResponse("Challenge validation failed")
		}
		authz.Status = common.StatusInvalid
		authz.Expires = ""

		// A failed challenge can signal an attack attempt (domain takeover,
		// enumeration), not just a misconfigured client, so it is audited
		// like the other security-relevant failures in this package.
		errDetail := ""
		if challenge.Error != nil {
			errDetail = challenge.Error.Error()
		}
		if auditErr := s.recordAudit(audit.EventChallengeFailed, s.auditLog.LogWithContext(auditContext(r),
			audit.EventChallengeFailed,
			auditAccountRef(account.ID),
			"challenge:"+strconv.FormatUint(challenge.ID, 10),
			"validate",
			audit.ResultFailure,
			map[string]interface{}{
				"challenge_type": challenge.Type,
				"reason":         errDetail,
			},
		)); auditErr != nil {
			writeError(w, common.ServerInternal("Failed to record audit event"))
			return
		}
	}

	// Apply the updated challenge object to the Authorization
	for i, _challenge := range authz.Challenges {
		if _challenge.ID == challenge.ID {
			authz.Challenges[i] = *challenge
		}
	}

	// Save the updated Authorization
	if err := authzDAO.Save(ctx, authz); err != nil {
		writeError(w, common.ServerInternal("Failed to update authorization"))
		return
	}

	// Look up the order associated with the authorization
	order, err := orderDAO.Get(ctx, authz.OrderID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			writeError(w, common.MalformedError("Order not found", nil))
		} else {
			s.logger.Error("Storage error retrieving order", "error", err)
			writeError(w, common.ServerInternal("Failed to retrieve order"))
		}
		return
	}

	// Update the order status
	valid := true
	for _, authzURL := range order.Authorizations {

		pieces := strings.Split(authzURL, "/")
		sAuthzID := pieces[len(pieces)-1]

		authzID, err := strconv.ParseUint(sAuthzID, 10, 64)
		if err != nil {
			writeError(w, common.MalformedError("Invalid authorization ID", nil))
			return
		}

		_authz, err := authzDAO.Get(ctx, authzID)
		if err != nil {
			if qrdbsdk.IsDAONotFound(err) {
				writeError(w, common.MalformedError("Authorization not found", nil))
			} else {
				s.logger.Error("Storage error retrieving authorization", "error", err)
				writeError(w, common.ServerInternal("Failed to retrieve authorization"))
			}
			return
		}

		if _authz.Status != common.StatusValid {
			order.Status = common.StatusInvalid
			if err := orderDAO.Save(ctx, order); err != nil {
				writeError(w, common.ServerInternal("Failed to update order status"))
				return
			}
			valid = false
			break
		}
	}
	if valid {
		order.Status = common.StatusReady
		if err := orderDAO.Save(ctx, order); err != nil {
			writeError(w, common.ServerInternal("Failed to update order status"))
			return
		}
	}

	// RFC 8555 Section 6.6 failed-validation category. This cannot be
	// blanket route middleware like the other per-category limiters: it must
	// count only actual validation failures. The persisted challenge/order
	// state above always reflects this attempt; only the *response* to this
	// specific request changes when the account (within its tenant, if any)
	// has exceeded its recent-failure budget.
	if !validationSuccessful && s.failedValidationLimiter != nil {
		tenantID := server.TenantIDFromContext(ctx)
		clientKey := strconv.FormatUint(account.ID, 10)
		if !s.failedValidationLimiter.Allow(tenantID, clientKey) {
			s.writeFailedValidationRateLimitError(w, tenantID)
			return
		}
	}

	s.writeChallengeResponse(w, challenge)
}

// writeFailedValidationRateLimitError writes an RFC 8555 Section 6.6
// rateLimited response for a failed-validation quota exceeded for tenantID.
// It mirrors server.TenantRateLimiter's own response construction (that
// type's response writer is unexported and lives in a different package),
// reusing TenantRateLimiter.RetryAfterSeconds so the reported window always
// matches the limiter's actual configuration.
func (s *RestService) writeFailedValidationRateLimitError(w http.ResponseWriter, tenantID string) {
	retryAfterSeconds := s.failedValidationLimiter.RetryAfterSeconds(tenantID)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	detail := fmt.Sprintf("Rate limit exceeded. Please retry after %d seconds.", retryAfterSeconds)
	writeError(w, common.RateLimited(detail))
}

// writeChallengeResponse writes an ACME challenge response with proper RFC 8555 headers.
func (s *RestService) writeChallengeResponse(w http.ResponseWriter, challenge *entities.ACMEChallenge) {
	nonce, err := s.generateNonce()
	if err != nil {
		writeError(w, common.ServerInternal("Unable to generate nonce"))
		return
	}

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
	challengeResponse(w, challenge)
}

// parseChallengeAsDynamicPortAssignment parses a challenge type that may include a port number.
// Format: "challenge-type-port" where port is optional and must be > 99 (to avoid matching -01 suffix).
// Returns the base challenge type and the port number (0 if not specified).
// Examples:
//   - "http-01" -> ("http-01", 0, nil) - standard challenge, no port
//   - "enroll-01" -> ("enroll-01", 0, nil) - standard challenge, no port
//   - "enroll-01-8080" -> ("enroll-01", 8080, nil) - with explicit port
//   - "device-attest-01-443" -> ("device-attest-01", 443, nil) - with explicit port
func parseChallengeAsDynamicPortAssignment(challengeType string) (string, uint16, error) {
	parts := strings.Split(challengeType, "-")
	if len(parts) < 2 {
		// No port specified, return 0 for default
		return challengeType, 0, nil
	}

	// Try to parse the last part as a port number
	lastPart := parts[len(parts)-1]
	port, err := strconv.ParseUint(lastPart, 10, 16)
	if err != nil {
		// Last part is not a number, so no port specified
		return challengeType, 0, nil
	}

	// Port numbers <= 99 are reserved for challenge version suffixes (like -01)
	// Real port numbers would be > 99 (e.g., 80, 443, 8080)
	if port <= 99 {
		return challengeType, 0, nil
	}

	// Reconstruct the base challenge type without the port
	baseType := strings.Join(parts[:len(parts)-1], "-")
	return baseType, uint16(port), nil
}

// isEnrollXChallenge checks if the challenge type is an enrollment challenge.
// Enrollment challenges include enroll-01, enroll-01-8080, endorse-01, device-attest-01, etc.
// Uses HasPrefix to match both standard and port-suffixed challenge types.
func isEnrollXChallenge(challengeType string) bool {
	baseType, _, _ := parseChallengeAsDynamicPortAssignment(challengeType)
	return strings.HasPrefix(baseType, "enroll") ||
		strings.HasPrefix(baseType, "endorse") ||
		strings.HasPrefix(baseType, "device-attest")
}
