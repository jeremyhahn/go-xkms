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

package workflow

import (
	"context"
	"encoding/base64"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/authorization"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/certificate"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/challenge"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/order"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// RequestCertificate performs the full ACME certificate issuance flow per RFC 8555.
func (w *workflow) RequestCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	const op = "workflow.RequestCertificate"

	if err := w.validateCertificateRequest(req); err != nil {
		return nil, err
	}

	// Step 1: Create the order with domain identifiers.
	identifiers := make([]order.Identifier, len(req.Domains))
	for i, domain := range req.Domains {
		identifiers[i] = order.Identifier{
			Type:  "dns",
			Value: domain,
		}
	}

	orderResp, err := w.client.Order().Create(ctx, &order.CreateRequest{
		Identifiers: identifiers,
	})
	if err != nil {
		return nil, WrapFinalizationError(err, op, "failed to create order", "")
	}

	if orderResp.Order == nil {
		return nil, NewFinalizationError(op, "server returned nil order", "")
	}

	orderURL := orderResp.Location

	// Step 2: Process each authorization.
	for _, authzURL := range orderResp.Order.Authorizations {
		if err := w.processAuthorization(ctx, authzURL, req.ChallengeType, req.ChallengeHandler); err != nil {
			return nil, err
		}
	}

	// Step 3: Finalize the order with the CSR.
	csrBase64 := base64.RawURLEncoding.EncodeToString(req.CSR)

	finalizeResp, err := w.client.Order().Finalize(ctx, &order.FinalizeRequest{
		FinalizeURL: orderResp.Order.Finalize,
		CSR:         csrBase64,
	})
	if err != nil {
		return nil, WrapFinalizationError(err, op, "failed to finalize order", orderURL)
	}

	if finalizeResp.Order == nil {
		return nil, NewFinalizationError(op, "server returned nil order after finalize", orderURL)
	}

	// Step 4: Poll order until valid or invalid.
	var finalOrder *order.Order
	err = w.poll(ctx, func(ctx context.Context) (bool, error) {
		getResp, pollErr := w.client.Order().Get(ctx, &order.GetRequest{
			OrderURL: orderURL,
		})
		if pollErr != nil {
			return false, WrapFinalizationError(pollErr, op, "failed to poll order status", orderURL)
		}
		if getResp.Order == nil {
			return false, NewFinalizationError(op, "server returned nil order during polling", orderURL)
		}
		finalOrder = getResp.Order

		switch getResp.Order.Status {
		case order.StatusValid:
			return true, nil
		case order.StatusInvalid:
			return false, NewFinalizationError(op, "order reached invalid status", orderURL)
		default:
			return false, nil
		}
	})
	if err != nil {
		return nil, err
	}

	// Step 5: Download the certificate.
	if finalOrder.Certificate == "" {
		return nil, NewFinalizationError(op, "order is valid but has no certificate URL", orderURL)
	}

	certResp, err := w.client.Certificate().Get(ctx, &certificate.GetRequest{
		CertificateURL: finalOrder.Certificate,
	})
	if err != nil {
		return nil, WrapFinalizationError(err, op, "failed to download certificate", orderURL)
	}

	return &CertificateResponse{
		CertificateChain: certResp.Chain,
		CertificateURL:   finalOrder.Certificate,
		OrderURL:         orderURL,
	}, nil
}

// processAuthorization handles a single authorization: fetches it, finds the
// matching challenge, calls the handler, responds, and polls until valid.
func (w *workflow) processAuthorization(
	ctx context.Context,
	authzURL string,
	challengeType string,
	handler ChallengeHandler,
) error {
	const op = "workflow.processAuthorization"

	authzResp, err := w.client.Authorization().Get(ctx, &authorization.GetRequest{
		AuthorizationURL: authzURL,
	})
	if err != nil {
		return WrapAuthorizationError(err, op, "failed to get authorization", "", authzURL)
	}

	if authzResp.Authorization == nil {
		return NewAuthorizationError(op, "server returned nil authorization", "", authzURL)
	}

	authz := authzResp.Authorization
	domain := authz.Identifier.Value

	// If already valid, skip.
	if authz.Status == authorization.StatusValid {
		return nil
	}

	// Find the matching challenge.
	var matchedChallenge *authorization.Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == challengeType {
			matchedChallenge = &authz.Challenges[i]
			break
		}
	}

	if matchedChallenge == nil {
		return NewNoChallengeError(op, domain, challengeType)
	}

	// Call the challenge handler to set up the response.
	cleanup, err := handler.Setup(
		matchedChallenge.Type,
		matchedChallenge.Token,
		"", // keyAuth is computed server-side in our CA
		domain,
	)
	if err != nil {
		return WrapChallengeError(err, op, "challenge handler setup failed",
			domain, challengeType, matchedChallenge.URL)
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Respond to the challenge to trigger server-side validation.
	_, err = w.client.Challenge().Respond(ctx, &challenge.RespondRequest{
		ChallengeURL: matchedChallenge.URL,
	})
	if err != nil {
		return WrapChallengeError(err, op, "failed to respond to challenge",
			domain, challengeType, matchedChallenge.URL)
	}

	// Poll authorization until valid or invalid.
	err = w.poll(ctx, func(ctx context.Context) (bool, error) {
		pollResp, pollErr := w.client.Authorization().Get(ctx, &authorization.GetRequest{
			AuthorizationURL: authzURL,
		})
		if pollErr != nil {
			return false, WrapAuthorizationError(pollErr, op,
				"failed to poll authorization status", domain, authzURL)
		}
		if pollResp.Authorization == nil {
			return false, NewAuthorizationError(op,
				"server returned nil authorization during polling", domain, authzURL)
		}

		switch pollResp.Authorization.Status {
		case authorization.StatusValid:
			return true, nil
		case authorization.StatusInvalid:
			return false, NewAuthorizationError(op,
				"authorization reached invalid status", domain, authzURL)
		default:
			return false, nil
		}
	})

	return err
}

// validateCertificateRequest validates the certificate request parameters.
func (w *workflow) validateCertificateRequest(req *CertificateRequest) error {
	const op = "workflow.validateCertificateRequest"

	if req == nil {
		return errors.NewInvalidInput(op, "certificate request cannot be nil")
	}
	if len(req.Domains) == 0 {
		return errors.NewInvalidInput(op, "at least one domain is required")
	}
	if len(req.CSR) == 0 {
		return errors.NewInvalidInput(op, "CSR is required")
	}
	if req.ChallengeType == "" {
		return errors.NewInvalidInput(op, "challenge type is required")
	}
	if req.ChallengeHandler == nil {
		return errors.NewInvalidInput(op, "challenge handler is required")
	}
	return nil
}
