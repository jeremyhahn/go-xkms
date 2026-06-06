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

package fido2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// WebAuthnAuthenticationOptions carries the parameters the client needs to drive
// a CTAP2 authenticator through a WebAuthn authentication (login) ceremony. These
// are derived from the server's BeginAuthentication output
// (a protocol.CredentialAssertion): the challenge, relying party, and the list of
// allowed credential IDs.
type WebAuthnAuthenticationOptions struct {
	Challenge               []byte
	Origin                  string
	RPID                    string
	AllowCredentialIDs      [][]byte
	RequireUserVerification bool
	Timeout                 time.Duration
}

// WebAuthnAssertion is the result of a WebAuthn authentication ceremony. The
// PublicKeyCredentialJSON is a standard WebAuthn PublicKeyCredential document
// that the server consumes via protocol.ParseCredentialRequestResponseBody.
type WebAuthnAssertion struct {
	CredentialID            []byte
	PublicKeyCredentialJSON []byte
}

// assertionResponseJSON is the inner "response" object of a PublicKeyCredential
// for an authentication (AuthenticatorAssertionResponse).
type assertionResponseJSON struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// publicKeyAssertionJSON is the top-level PublicKeyCredential document the server
// parses with protocol.ParseCredentialRequestResponseBody.
type publicKeyAssertionJSON struct {
	ID       string                `json:"id"`
	RawID    string                `json:"rawId"`
	Type     string                `json:"type"`
	Response assertionResponseJSON `json:"response"`
}

// buildAssertionClientDataJSON constructs the WebAuthn CollectedClientData
// document for an authentication ceremony:
// {"type":"webauthn.get","challenge":base64url(challenge),"origin":origin}.
// The challenge is base64url-encoded (RawURLEncoding, no padding) exactly as the
// server expects when it re-derives and compares the challenge. It reuses the
// shared collectedClientData type and b64url helper from the registration path.
func buildAssertionClientDataJSON(challenge []byte, origin string) ([]byte, error) {
	cd := collectedClientData{
		Type:      "webauthn.get",
		Challenge: b64url(challenge),
		Origin:    origin,
	}
	out, err := json.Marshal(cd)
	if err != nil {
		return nil, fmt.Errorf("fido2: failed to marshal clientDataJSON: %w", err)
	}
	return out, nil
}

// buildPublicKeyAssertionJSON assembles the full WebAuthn PublicKeyCredential
// JSON document from a CTAP2 GetAssertion response and the clientDataJSON. The
// resulting document is what the xkms server consumes via
// protocol.ParseCredentialRequestResponseBody. userHandle is omitted from the
// JSON when empty.
func buildPublicKeyAssertionJSON(resp *GetAssertionResponse, clientDataJSON []byte) (credentialID, doc []byte, err error) {
	if resp == nil {
		return nil, nil, fmt.Errorf("fido2: nil GetAssertionResponse")
	}
	if len(resp.AuthData) == 0 {
		return nil, nil, fmt.Errorf("fido2: GetAssertionResponse missing authData")
	}
	if len(resp.Signature) == 0 {
		return nil, nil, fmt.Errorf("fido2: GetAssertionResponse missing signature")
	}

	credentialID = resp.Credential.ID
	if len(credentialID) == 0 {
		return nil, nil, fmt.Errorf("fido2: GetAssertionResponse missing credential id")
	}

	credIDB64 := b64url(credentialID)
	cred := publicKeyAssertionJSON{
		ID:    credIDB64,
		RawID: credIDB64,
		Type:  "public-key",
		Response: assertionResponseJSON{
			AuthenticatorData: b64url(resp.AuthData),
			ClientDataJSON:    b64url(clientDataJSON),
			Signature:         b64url(resp.Signature),
		},
	}
	if resp.User != nil && len(resp.User.ID) > 0 {
		cred.Response.UserHandle = b64url(resp.User.ID)
	}

	doc, err = json.Marshal(cred)
	if err != nil {
		return nil, nil, fmt.Errorf("fido2: failed to marshal PublicKeyCredential JSON: %w", err)
	}
	return credentialID, doc, nil
}

// buildWebAuthnAssertion runs the pure construction half of the authentication
// ceremony: it builds the clientDataJSON and assembles the PublicKeyCredential
// assertion document from a GetAssertion response. It is the shared, device-free
// core used by AuthenticateWebAuthn and exercised directly by the unit tests.
func buildWebAuthnAssertion(resp *GetAssertionResponse, challenge []byte, origin string) (*WebAuthnAssertion, error) {
	clientDataJSON, err := buildAssertionClientDataJSON(challenge, origin)
	if err != nil {
		return nil, err
	}

	credentialID, doc, err := buildPublicKeyAssertionJSON(resp, clientDataJSON)
	if err != nil {
		return nil, err
	}

	return &WebAuthnAssertion{
		CredentialID:            credentialID,
		PublicKeyCredentialJSON: doc,
	}, nil
}

// assertionAllowList converts raw credential IDs into the
// PublicKeyCredentialDescriptor allowList the authenticator expects.
func assertionAllowList(ids [][]byte) []PublicKeyCredentialDescriptor {
	if len(ids) == 0 {
		return nil
	}
	list := make([]PublicKeyCredentialDescriptor, 0, len(ids))
	for _, id := range ids {
		list = append(list, PublicKeyCredentialDescriptor{
			Type: "public-key",
			ID:   id,
		})
	}
	return list
}

// AuthenticateWebAuthn drives a CTAP2 authenticator through a WebAuthn
// authentication (login) ceremony and emits a standard WebAuthn
// PublicKeyCredential JSON document — the assertion the xkms server consumes via
// protocol.ParseCredentialRequestResponseBody.
//
// Given the server's BeginAuthentication output (challenge, relying party,
// allowed credential IDs), it builds the clientDataJSON, computes the
// clientDataHash, invokes authenticatorGetAssertion, and assembles the
// PublicKeyCredential document from the returned authData, signature, and
// optional userHandle.
func (h *FIDO2Handler) AuthenticateWebAuthn(opts WebAuthnAuthenticationOptions) (*WebAuthnAssertion, error) {
	if len(opts.Challenge) == 0 {
		return nil, fmt.Errorf("fido2: authentication challenge required")
	}
	if opts.Origin == "" {
		return nil, fmt.Errorf("fido2: authentication origin required")
	}

	// Build clientDataJSON and derive the clientDataHash the authenticator signs.
	clientDataJSON, err := buildAssertionClientDataJSON(opts.Challenge, opts.Origin)
	if err != nil {
		return nil, err
	}
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Acquire a device and authenticator using the same setup as RegisterWebAuthn.
	device, err := h.selectDevice()
	if err != nil {
		return nil, err
	}

	ctapDev, err := NewCTAPHIDDevice(device, h.config)
	if err != nil {
		if closeErr := device.Close(); closeErr != nil {
			log.Printf("failed to close device after CTAP init error: %v", closeErr)
		}
		return nil, fmt.Errorf("fido2: failed to initialize CTAP device: %w", err)
	}
	defer func() {
		if err := ctapDev.Close(); err != nil {
			log.Printf("failed to close CTAP device: %v", err)
		}
	}()

	auth, err := NewAuthenticator(ctapDev, h.config)
	if err != nil {
		return nil, fmt.Errorf("fido2: failed to create authenticator: %w", err)
	}

	if opts.Timeout > 0 {
		originalTimeout := h.config.Timeout
		h.config.Timeout = opts.Timeout
		defer func() { h.config.Timeout = originalTimeout }()
	}

	req := &GetAssertionRequest{
		RPID:           opts.RPID,
		ClientDataHash: clientDataHash[:],
		AllowList:      assertionAllowList(opts.AllowCredentialIDs),
		Options: AuthenticatorOptions{
			UP: true,
			UV: opts.RequireUserVerification,
		},
	}

	h.logger.Printf("Please touch your security key to authenticate...")
	resp, err := auth.GetAssertion(req)
	if err != nil {
		return nil, fmt.Errorf("fido2: GetAssertion failed: %w", err)
	}

	return buildWebAuthnAssertion(resp, opts.Challenge, opts.Origin)
}

// parseRequestOptions decodes the server-issued WebAuthn assertion options into
// the structured form AuthenticateWebAuthn consumes. The optionsJSON is the
// relying party's BeginLogin output: the JSON-marshaled WebAuthn
// PublicKeyCredentialRequestOptions. Both the browser-shaped wrapped form
// ({"publicKey": {...}}, a protocol.CredentialAssertion) and the bare
// PublicKeyCredentialRequestOptions object are accepted, because servers serve
// either shape depending on whether navigator.credentials.get() consumes the
// document directly.
//
// The origin is NOT carried in the WebAuthn options (the browser supplies it
// from its security context), so the caller provides it. When origin is empty,
// the WebAuthn-standard same-origin default "https://<rpId>" is used; this is
// correct whenever the relying party origin host equals the RP ID. Callers whose
// origin host differs from the RP ID (a registrable-suffix RP ID) must pass the
// explicit origin.
func parseRequestOptions(optionsJSON []byte, origin string) (WebAuthnAuthenticationOptions, error) {
	if len(optionsJSON) == 0 {
		return WebAuthnAuthenticationOptions{}, fmt.Errorf("fido2: %w", ErrAssertionOptionsRequired)
	}

	// Accept the wrapped CredentialAssertion ({"publicKey": {...}}) first; if the
	// publicKey member is absent the document is a bare request-options object,
	// which we then decode directly.
	var wrapped protocol.CredentialAssertion
	if err := json.Unmarshal(optionsJSON, &wrapped); err != nil {
		return WebAuthnAuthenticationOptions{}, fmt.Errorf("fido2: failed to parse assertion options: %w", err)
	}

	reqOpts := wrapped.Response
	if len(reqOpts.Challenge) == 0 {
		// No publicKey wrapper present — decode the bare request options.
		if err := json.Unmarshal(optionsJSON, &reqOpts); err != nil {
			return WebAuthnAuthenticationOptions{}, fmt.Errorf("fido2: failed to parse assertion options: %w", err)
		}
	}

	if len(reqOpts.Challenge) == 0 {
		return WebAuthnAuthenticationOptions{}, fmt.Errorf("fido2: %w", ErrAssertionChallengeMissing)
	}
	if reqOpts.RelyingPartyID == "" {
		return WebAuthnAuthenticationOptions{}, fmt.Errorf("fido2: %w", ErrAssertionRPIDMissing)
	}

	resolvedOrigin := origin
	if resolvedOrigin == "" {
		resolvedOrigin = "https://" + reqOpts.RelyingPartyID
	}

	allowCredentialIDs := make([][]byte, 0, len(reqOpts.AllowedCredentials))
	for _, cred := range reqOpts.AllowedCredentials {
		if len(cred.CredentialID) == 0 {
			continue
		}
		id := make([]byte, len(cred.CredentialID))
		copy(id, cred.CredentialID)
		allowCredentialIDs = append(allowCredentialIDs, id)
	}

	challenge := make([]byte, len(reqOpts.Challenge))
	copy(challenge, reqOpts.Challenge)

	return WebAuthnAuthenticationOptions{
		Challenge:               challenge,
		Origin:                  resolvedOrigin,
		RPID:                    reqOpts.RelyingPartyID,
		AllowCredentialIDs:      allowCredentialIDs,
		RequireUserVerification: reqOpts.UserVerification == protocol.VerificationRequired,
		Timeout:                 time.Duration(reqOpts.Timeout) * time.Millisecond,
	}, nil
}

// AssertWithOptions drives a connected CTAP2 authenticator through a WebAuthn
// assertion ceremony whose options were issued by a relying party server, and
// returns the WebAuthn assertion JSON for the server to verify.
//
// optionsJSON is the server's BeginLogin output: the JSON-marshaled WebAuthn
// PublicKeyCredentialRequestOptions (challenge, rpId, allowCredentials,
// userVerification, timeout), in either the wrapped browser shape
// ({"publicKey": {...}}) or the bare request-options shape. AssertWithOptions
// parses it, builds the clientDataJSON over the supplied challenge and the
// WebAuthn-standard same-origin default ("https://<rpId>"), invokes CTAP2
// authenticatorGetAssertion on the local authenticator, and assembles the
// navigator.credentials.get() response document (id, rawId, type,
// response{authenticatorData, clientDataJSON, signature, userHandle}).
//
// The returned bytes are exactly the body the server consumes via
// protocol.ParseCredentialRequestResponseBody in FinishLogin. Callers whose
// origin host differs from the RP ID must use AssertWithOptionsAndOrigin.
//
// The context bounds device acquisition; the CTAP user-presence timeout is taken
// from the options' timeout (falling back to the handler config when zero).
func (h *FIDO2Handler) AssertWithOptions(ctx context.Context, optionsJSON []byte) ([]byte, error) {
	return h.AssertWithOptionsAndOrigin(ctx, optionsJSON, "")
}

// AssertWithOptionsAndOrigin is AssertWithOptions with an explicit WebAuthn
// origin. The origin must match one of the relying party's configured RPOrigins
// or the server will reject the assertion. When origin is empty, the
// WebAuthn-standard same-origin default "https://<rpId>" is used.
func (h *FIDO2Handler) AssertWithOptionsAndOrigin(ctx context.Context, optionsJSON []byte, origin string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	opts, err := parseRequestOptions(optionsJSON, origin)
	if err != nil {
		return nil, err
	}

	assertion, err := h.AuthenticateWebAuthn(opts)
	if err != nil {
		return nil, err
	}

	return assertion.PublicKeyCredentialJSON, nil
}
