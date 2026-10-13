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
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// loopbackIdentifier is the permanent-identifier value that, for enrollment
// challenges, is eligible for substitution with the request's client IP when
// acme.enrollment.allow_loopback_identifier is enabled.
const loopbackIdentifier = "127.0.0.1"

// challengeProblem converts a challenge verifier's error into the problem
// document returned to the ACME client. It never includes err.Error() for an
// unrecognized error: a failure to reach or read from the target is the RFC
// 8555 "connection" problem carrying the validation client's fixed category
// (validation.Kind), an authorization of a type an attestation challenge
// cannot authorize is "unsupportedIdentifier" carrying that detail (safe: it
// names only the challenge and identifier TYPE, never any evidence), and
// every other failure is "incorrectResponse" with a fixed detail.
func challengeProblem(err error) *entities.Error {
	var identErr *ErrAttestationIdentifierType
	if errors.As(err, &identErr) {
		return common.UnsupportedIdentifier(identErr.Error())
	}
	var mismatch *ErrIdentityMismatch
	if errors.As(err, &mismatch) {
		return common.Unauthorized("Attested device identity does not match the order's identifier")
	}
	var noIdentity *ErrAttestationNoIdentity
	if errors.As(err, &noIdentity) {
		return common.ServerInternal("Challenge verifier returned no result")
	}
	var verr *validation.Error
	if !errors.As(err, &verr) {
		return common.IncorrectResponse("Challenge validation failed")
	}
	detail := "Challenge validation failed: " + verr.Kind.String()
	if verr.Kind == validation.KindInvalidTarget {
		return common.IncorrectResponse(detail)
	}
	return common.ConnectionError(detail)
}

// verifyAttestation runs an attestation challenge through verifier and
// enforces the identity binding (go-xkms#828): the identity the device
// attested must be the identifier the order authorizes, or the challenge is
// refused. On success the verified evidence, when the verifier produced any,
// is recorded on challenge so order finalization can bind the certificate
// request's key to it (go-xkms#789).
//
// The returned error is for the audit record and the log only; the client's
// problem document comes from challengeProblem, which never repeats an
// identity.
func (s *RestService) verifyAttestation(
	verifier common.AttestingVerifier,
	challenge *entities.ACMEChallenge,
	identifier entities.ACMEIdentifier,
	dialTarget, port, keyAuth string,
	payload []byte,
	authorizedIdentity string,
) error {
	attested, err := verifier.VerifyAttested(net.DefaultResolver, s.ca, common.AttestationChallenge{
		IdentifierType:     identifier.Type,
		IdentifierValue:    identifier.Value,
		DialTarget:         dialTarget,
		Port:               port,
		Payload:            payload,
		AuthorizedIdentity: authorizedIdentity,
		Token:              challenge.Token,
		KeyAuthorization:   keyAuth,
	})
	if err == nil && attested == nil {
		err = &ErrAttestationNoIdentity{Challenge: challenge.Type}
	}
	// Constant-time because both sides are attacker-influenced: the
	// identifier was chosen by the account that created the order, and the
	// evidence is not secret, so it could be replayed by someone who never
	// held the device.
	if err == nil && subtle.ConstantTimeCompare([]byte(attested.Identifier), []byte(identifier.Value)) != 1 {
		err = &ErrIdentityMismatch{Attested: attested.Identifier, Authorized: identifier.Value}
	}
	if err != nil {
		s.logger.Warn(
			"challenge verification failed",
			slog.String("error", err.Error()),
			slog.String("challenge", challenge.Type))
		return err
	}

	challenge.DeviceAttestation = attested.Attestation
	return nil
}

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

	account, payload, err := s.parseKID(ctx, r)
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

	// Validate EAB authorization for endorse-01 challenges. EAB is required
	// unless the operator waived it (Params.EndorseEABOptional), and what it
	// authorizes -- the EK the binding is bound to -- is the identity the
	// verifier attests (go-xkms#1392).
	var endorseAuthorizedIdentity string
	if IsEndorseChallengeType(challenge.Type) {
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

		if eabAuth.Unauthenticated {
			s.logger.Warn("endorse-01 challenge authorized with no external account binding: EAB is waived, so this account may obtain an EK certificate for any public key",
				slog.Uint64("accountID", account.ID),
				slog.String("challengeType", challenge.Type))
		} else {
			s.logger.Info("EAB authorization validated for endorse-01 challenge",
				slog.Uint64("accountID", account.ID),
				slog.String("externalAccountID", eabAuth.ExternalAccountID),
				slog.String("authorizedDeviceID", eabAuth.AuthorizedDeviceID))
		}
		endorseAuthorizedIdentity = eabAuth.AuthorizedIdentity
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
	// verifyErr keeps the verifier's full error for the audit record; the
	// client-facing challenge.Error carries only its category.
	var verifyErr error

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

	// Every challenge this server offers is a registered, unsuffixed type
	// (createChallenges never produces a port-suffixed challenge.Type -- see
	// go-xkms#1183), so the port is always the type's fixed default and the
	// verifier is always looked up by the literal type.
	var challengePort uint16
	if dialsDevice(challenge.Type) {
		// Challenges that contact the device default to port 8080
		challengePort = 8080
	} else if strings.HasPrefix(challenge.Type, "http") {
		// HTTP-01 defaults to port 80
		challengePort = 80
	}

	// Look up the verifier by the challenge's literal type. An attestation
	// challenge (enroll-01, endorse-01, device-attest-01) requires an
	// AttestingVerifier, the only kind that reports the identity the device
	// attested; every other type uses the ChallengeVerifierFunc map. An
	// attestation type with only a plain ChallengeVerifierFunc registered is
	// refused, never run without an identity check (go-xkms#828).
	attestation := isEnrollXChallenge(challenge.Type)
	var (
		challengeVerifierFunc common.ChallengeVerifierFunc
		attestingVerifier     common.AttestingVerifier
		ok                    bool
	)
	if attestation {
		attestingVerifier, ok = s.attestingVerifiers[challenge.Type]
		ok = ok && attestingVerifier != nil
	} else {
		challengeVerifierFunc, ok = s.challengeMap[challenge.Type]
	}
	_, unattested := s.challengeMap[challenge.Type]
	switch {
	case !ok && attestation && unattested:
		verifyErr = &ErrAttestingVerifierRequired{Challenge: challenge.Type}
		s.logger.Error("challenge refused", slog.String("error", verifyErr.Error()))
		challenge.Status = common.StatusInvalid
		challenge.Error = common.Unauthorized("Challenge verifier cannot establish the attested identity")
	case !ok:
		challenge.Status = common.StatusInvalid
		errmsg := fmt.Sprintf("Unsupported challenge type: %s", challenge.Type)
		challenge.Error = common.MalformedError(errmsg, nil)
	default:
		// For enrollment challenges with permanent-identifier, we need the client's IP or hostname
		challengeDomain := authz.Identifier.Value
		loopbackRefused := false

		if authz.Identifier.Type == common.AuthzTypePermanentIdentifier &&
			dialsDevice(challenge.Type) {
			// A cluster joiner names itself by its Raft address (host:port);
			// the device is reached at that host on the challenge port.
			challengeDomain = permanentIdentifierDialHost(authz.Identifier.Value)

			// Only use client IP when identifier is loopback (127.0.0.1)
			// This supports local development/testing where the device registers with the
			// loopback address but the actual challenge validation needs to reach the
			// device at its real IP. Gated by acme.enrollment.allow_loopback_identifier
			// (default false): a production deployment must refuse the substitution.
			if challengeDomain == loopbackIdentifier {
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

		switch {
		case loopbackRefused:
			challenge.Status = common.StatusInvalid
			challenge.Error = common.Unauthorized(ErrLoopbackIdentifierNotAllowed.Error())

		case attestation && authz.Identifier.Type == common.AuthzTypeIP:
			// go-xkms#828: an attested device identity is not an IP address,
			// so an attestation challenge never authorizes one.
			verifyErr = &ErrAttestationIdentifierType{Challenge: challenge.Type, Type: authz.Identifier.Type}
			s.logger.Warn(
				"challenge verification failed",
				slog.String("error", verifyErr.Error()),
				slog.String("challenge", challenge.Type))
			challenge.Status = common.StatusInvalid
			challenge.Error = challengeProblem(verifyErr)

		case attestation:
			// A challenge the server never dials is handed no address and no
			// port: the client's payload is all it verifies.
			dialTarget, port := "", ""
			if dialsDevice(challenge.Type) {
				dialTarget, port = challengeDomain, strconv.Itoa(int(challengePort))
			}
			verifyErr = s.verifyAttestation(attestingVerifier, challenge, authz.Identifier, dialTarget, port, keyAuth, payload, endorseAuthorizedIdentity)
			if verifyErr != nil {
				challenge.Status = common.StatusInvalid
				challenge.Error = challengeProblem(verifyErr)
			} else {
				validationSuccessful = true
			}

		default:
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

				// The verifier's error names the dialed address, the
				// resolver's answer or the target's status, all of which
				// would turn the challenge into a probe of the server's
				// network. It is logged and audited in full; the client
				// gets only a fixed category (challengeProblem).
				s.logger.Warn(
					"challenge verification failed",
					slog.String("error", err.Error()),
					slog.String("challenge", challenge.Type))
				verifyErr = err
				challenge.Status = common.StatusInvalid
				challenge.Error = challengeProblem(err)
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
		// challenge.Type, not the broader isEnrollXChallenge/
		// IsEndorseChallengeType family checks: those both match "endorse-01"
		// (isEnrollXChallenge matches every enrollment-family type, including
		// endorse-01 and device-attest-01), so an exact match is required to
		// tell enroll-01, endorse-01 and device-attest-01 apart here.
		var eventType audit.EventType
		switch challenge.Type {
		case "enroll-01":
			eventType = audit.EventTPMAttestation
		case "endorse-01":
			eventType = audit.EventEndorsementVerified
		case common.ChallengeTypeDeviceAttest01:
			eventType = audit.EventDeviceAttestation
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
		if verifyErr != nil {
			errDetail = verifyErr.Error()
		} else if challenge.Error != nil {
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

	// The challenge just left "pending" (to "valid" or "invalid"), and its
	// outcome is now persisted, so it is recorded once here rather than at
	// every possible earlier return above.
	metrics.DecPendingChallenges()
	metrics.NewMetricsCollector(account.TenantID).RecordChallenge(challenge.Type, challenge.Status)

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
			// The order reached its terminal "invalid" state because an
			// authorization failed, not because finalize was attempted.
			metrics.DecActiveOrders()
			if account.TenantID != "" {
				metrics.DecTenantActiveOrders(account.TenantID)
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

// isEnrollXChallenge checks if the challenge type is an enrollment challenge:
// enroll-01, endorse-01 or device-attest-01.
func isEnrollXChallenge(challengeType string) bool {
	return strings.HasPrefix(challengeType, "enroll") ||
		strings.HasPrefix(challengeType, "endorse") ||
		isDeviceAttestChallenge(challengeType)
}

// isDeviceAttestChallenge reports whether the challenge type is
// device-attest-01.
func isDeviceAttestChallenge(challengeType string) bool {
	return strings.HasPrefix(challengeType, "device-attest")
}

// dialsDevice reports whether the server answers the challenge by contacting
// the device: enroll-01 and endorse-01. device-attest-01 does not
// (draft-ietf-acme-device-attest): the client POSTs its attestation, so the
// device needs no address, no listener and no loopback substitution.
func dialsDevice(challengeType string) bool {
	return isEnrollXChallenge(challengeType) && !isDeviceAttestChallenge(challengeType)
}

// permanentIdentifierDialHost returns the host a dialing challenge reaches for
// a permanent-identifier value. A host:port value (a cluster node's Raft
// address, [v6]:port included) yields its host: the port names the node's
// Raft listener, and the device answers on the challenge port. Any other value
// is a host already and is returned unchanged.
func permanentIdentifierDialHost(identifier string) string {
	host, _, err := net.SplitHostPort(identifier)
	if err != nil {
		return identifier
	}
	return host
}
