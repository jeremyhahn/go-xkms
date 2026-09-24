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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// NewAccountRequest represents the structure of a new account registration request.
type NewAccountRequest struct {
	Contact                []string    `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool        `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting     bool        `json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"`
}

// NewAccountHandler handles account registration per RFC 8555 Section 7.3.
// It creates a new account or returns an existing one based on the public key.
// When external account binding is required (per RFC 8555 Section 7.3.4),
// the request MUST include an externalAccountBinding field with a valid JWS.
func (s *RestService) NewAccountHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	s.logger.Debug("NewAccountHandler", "method", r.Method, "url", r.URL.String())

	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create account DAO"))
		return
	}

	jwk, payload, err := s.parseJWS(r)
	if err != nil {
		s.logger.Error("NewAccountHandler: parseJWS failed", "error", err.Error())
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	var req NewAccountRequest
	err = json.Unmarshal(payload, &req)
	if err != nil {
		writeError(w, common.MalformedError("Invalid JSON payload", nil))
		return
	}

	if err := ValidateContactURLs(req.Contact); err != nil {
		writeError(w, err)
		return
	}

	// Serialize the public key to PEM format
	serializedKey, err := xkmssdk.EncodePublicKeyPEM(jwk.Key)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to serialize account key"))
		return
	}

	// Generate deterministic account ID from public key
	accountID, err := AccountIDFromPublicKey(jwk.Key)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to generate account ID"))
		return
	}

	// Check if account already exists
	account, err := accountDAO.Get(ctx, accountID)
	if err != nil && !qrdbsdk.IsDAONotFound(err) {
		s.logger.Error("Storage error checking for existing account", "error", err)
		writeError(w, common.ServerInternal("Storage error"))
		return
	}

	if err == nil {
		// Account exists — per RFC 8555 §7.3, if the server already has an
		// account registered with the provided key, respond 200 OK with
		// the existing account URL regardless of OnlyReturnExisting.
		// Returning 409 accountExists for idempotent re-registration breaks
		// clients (e.g. x/crypto/acme) that can't recover the KID from the
		// error and subsequently fail POST-as-GET / AuthorizeOrder.
		s.respondWithAccount(w, account, http.StatusOK)
		return
	}

	// Account doesn't exist
	if req.OnlyReturnExisting {
		writeError(w, common.AccountDoesNotExist("Account does not exist"))
		return
	}

	// Handle external account binding per RFC 8555 Section 7.3.4
	var verifiedBinding *entities.ExternalAccountBinding
	if s.externalAccountRequired {
		if req.ExternalAccountBinding == nil {
			writeError(w, common.ExternalAccountRequired("External account binding is required"))
			return
		}

		// Verify the external account binding JWS
		eabDAO, err := s.storageFactory.ExternalAccountBindingDAO()
		if err != nil {
			s.logger.Error("Failed to create external account binding DAO", "error", err)
			writeError(w, common.ServerInternal("Failed to verify external account binding"))
			return
		}

		newAccountURL := fmt.Sprintf("%s/acme/new-account", s.baseRESTURI)
		verifier := NewExternalAccountBindingVerifier(eabDAO, newAccountURL)

		verifiedBinding, err = verifier.Verify(ctx, req.ExternalAccountBinding, jwk)
		if err != nil {
			s.logger.Error("External account binding verification failed", "error", err)

			// A rejected external account binding is a refused enrollment, not
			// a protocol nicety: record it before the request is answered.
			if auditErr := s.recordAudit(audit.EventAuthenticationFailed, audit.LogAuthenticationFailed(auditContext(r), s.auditLog,
				"external account binding verification failed: "+err.Error())); auditErr != nil {
				writeError(w, common.ServerInternal("Failed to record audit event"))
				return
			}

			// Return appropriate error based on the verification failure.
			// Check sentinel errors first (returned directly by the verifier),
			// then check typed errors from the caerrors package.
			switch {
			case errors.Is(err, storage.ErrExternalAccountBindingExpired):
				writeError(w, common.Unauthorized("External account binding has expired"))
			case errors.Is(err, storage.ErrExternalAccountBindingUsed):
				writeError(w, common.Unauthorized("External account binding has already been used"))
			case errors.Is(err, storage.ErrExternalAccountBindingRevoked):
				writeError(w, common.Unauthorized("External account binding has been revoked"))
			case caerrors.IsType(err, caerrors.Malformed):
				writeError(w, common.MalformedError(err.Error(), nil))
			case caerrors.IsType(err, caerrors.NotFound):
				writeError(w, common.Unauthorized("Invalid key identifier in external account binding"))
			case caerrors.IsType(err, caerrors.VerificationFailure):
				writeError(w, common.Unauthorized("External account binding signature verification failed"))
			case caerrors.IsType(err, caerrors.SerializationFailure):
				writeError(w, common.MalformedError("Invalid external account binding format", nil))
			case caerrors.IsType(err, caerrors.Unauthorized):
				writeError(w, common.Unauthorized(err.Error()))
			default:
				writeError(w, common.Unauthorized("Invalid external account binding"))
			}
			return
		}

		s.logger.Info("External account binding verified",
			"kid", verifiedBinding.ID,
			"external_account_id", verifiedBinding.ExternalAccountID)
	} else if req.ExternalAccountBinding != nil {
		// External account binding provided but not required
		// Per RFC 8555, we still try to verify it if provided
		eabDAO, err := s.storageFactory.ExternalAccountBindingDAO()
		if err == nil {
			newAccountURL := fmt.Sprintf("%s/acme/new-account", s.baseRESTURI)
			verifier := NewExternalAccountBindingVerifier(eabDAO, newAccountURL)
			verifiedBinding, _ = verifier.Verify(ctx, req.ExternalAccountBinding, jwk)
			// If verification fails, we still proceed (binding is optional)
		}
	}

	// Create new account
	newAccount := &entities.ACMEAccount{
		ID:                     accountID,
		Status:                 common.StatusValid,
		Contact:                req.Contact,
		TermsOfServiceAgreed:   req.TermsOfServiceAgreed,
		ExternalAccountBinding: req.ExternalAccountBinding,
		Orders:                 fmt.Sprintf("%s/acme/account/%d/orders", s.baseRESTURI, accountID),
		Key:                    string(serializedKey),
		CreatedAt:              time.Now(),
	}
	newAccount.URL = s.accountURL(newAccount)

	// Set TenantID from EAB if present (for multi-tenant deployments)
	if verifiedBinding != nil && verifiedBinding.TenantID != "" {
		newAccount.TenantID = verifiedBinding.TenantID
	}

	// Save account
	if err := accountDAO.Save(ctx, newAccount); err != nil {
		s.logger.Error("Failed to save account", "error", err, "account_id", accountID)
		writeError(w, common.ServerInternal("Failed to save account"))
		return
	}
	s.logger.Info("ACMEAccount persisted via DAO", "account_id", accountID, "key_pem_len", len(newAccount.Key))

	// Mark the external account binding as used if verification succeeded
	if verifiedBinding != nil {
		eabDAO, err := s.storageFactory.ExternalAccountBindingDAO()
		if err == nil {
			verifiedBinding.MarkUsed(accountID)
			if err := eabDAO.Save(ctx, verifiedBinding); err != nil {
				s.logger.Error("Failed to update external account binding",
					"error", err, "kid", verifiedBinding.ID)
				// Don't fail the request - the account was created successfully
			}
		}
	}

	s.logger.Info("Account created", "id", accountID, "contacts", req.Contact,
		"external_account_bound", verifiedBinding != nil, "tenant_id", newAccount.TenantID)
	if auditErr := s.recordAudit(audit.EventAccountCreated, audit.LogAccountCreated(auditContext(r), s.auditLog,
		auditAccountID(accountID), req.Contact, verifiedBinding != nil)); auditErr != nil {
		writeError(w, common.ServerInternal("Failed to record audit event"))
		return
	}
	s.respondWithAccount(w, newAccount, http.StatusCreated)
}
