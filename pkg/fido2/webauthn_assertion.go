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
	"log"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

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

	// PIN is the authenticator's CTAP2 PIN. An authenticator configured with
	// alwaysUv, or a relying party that demands user verification, refuses
	// GetAssertion (CTAP2_ERR_PIN_REQUIRED) unless the request carries a
	// pinUvAuthParam, so this is what makes a login ceremony possible against
	// a PIN-protected key with no browser to prompt for it. It is the
	// assertion-side counterpart of WebAuthnRegistrationOptions.PIN and is
	// consumed through the same Authenticator.AuthorizeWithPIN path.
	//
	// The PIN is opened only inside AuthorizeWithPIN, at the point the CTAP2
	// pinUvAuth computation needs its bytes. Nil leaves the request
	// unauthorized, which is correct for a key with no PIN configured.
	PIN *secure.Secret
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
		return nil, &errs.Wrapped{Msg: "fido2: failed to marshal clientDataJSON", Err: err}
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
		return nil, nil, &errs.Message{Msg: "fido2: nil GetAssertionResponse"}
	}
	if len(resp.AuthData) == 0 {
		return nil, nil, &errs.Message{Msg: "fido2: GetAssertionResponse missing authData"}
	}
	if len(resp.Signature) == 0 {
		return nil, nil, &errs.Message{Msg: "fido2: GetAssertionResponse missing signature"}
	}

	credentialID = resp.Credential.ID
	if len(credentialID) == 0 {
		return nil, nil, &errs.Message{Msg: "fido2: GetAssertionResponse missing credential id"}
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
		return nil, nil, &errs.Wrapped{Msg: "fido2: failed to marshal PublicKeyCredential JSON", Err: err}
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
		return nil, &errs.Message{Msg: "fido2: authentication challenge required"}
	}
	if err := ValidateRPID(opts.RPID, opts.Origin); err != nil {
		return nil, err
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
		return nil, &errs.Wrapped{Msg: "fido2: failed to initialize CTAP device", Err: err}
	}
	defer func() {
		if err := ctapDev.Close(); err != nil {
			log.Printf("failed to close CTAP device: %v", err)
		}
	}()

	auth, err := NewAuthenticator(ctapDev, h.config)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "fido2: failed to create authenticator", Err: err}
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

	if opts.PIN != nil {
		param, pinProtocol, perr := auth.AuthorizeWithPIN(opts.PIN, clientDataHash[:])
		if perr != nil {
			return nil, perr
		}
		req.PinUVAuthParam = param
		req.PinUVAuthProtocol = pinProtocol

		// A pinUvAuthToken IS the user verification, and it supersedes the
		// "uv" option: CTAP 2.1 6.2.2 reserves "uv" for an authenticator's
		// BUILT-IN verification method, so a PIN-only key answers uv:true with
		// CTAP2_ERR_INVALID_OPTION even as it verifies the user by PIN. This
		// mirrors RegisterWebAuthn, which applies the same rule to
		// MakeCredential.
		req.Options.UV = false
	}

	h.logger.Printf("Please touch your security key to authenticate...")
	resp, err := auth.GetAssertion(req)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "fido2: GetAssertion failed", Err: err}
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
// from its security context), so the caller provides it, and the server's rpId
// must be the origin's effective domain or a registrable suffix of it
// (ValidateRPID). An empty origin is refused: it is never derived from the
// server-supplied rpId.
func parseRequestOptions(optionsJSON []byte, origin string) (WebAuthnAuthenticationOptions, error) {
	if len(optionsJSON) == 0 {
		return WebAuthnAuthenticationOptions{}, &errs.Wrapped{Msg: "fido2", Err: ErrAssertionOptionsRequired}
	}

	// Accept the wrapped CredentialAssertion ({"publicKey": {...}}) first; if the
	// publicKey member is absent the document is a bare request-options object,
	// which we then decode directly.
	var wrapped protocol.CredentialAssertion
	if err := json.Unmarshal(optionsJSON, &wrapped); err != nil {
		return WebAuthnAuthenticationOptions{}, &errs.Wrapped{Msg: "fido2: failed to parse assertion options", Err: err}
	}

	reqOpts := wrapped.Response
	if len(reqOpts.Challenge) == 0 {
		// No publicKey wrapper present — decode the bare request options.
		if err := json.Unmarshal(optionsJSON, &reqOpts); err != nil {
			return WebAuthnAuthenticationOptions{}, &errs.Wrapped{Msg: "fido2: failed to parse assertion options", Err: err}
		}
	}

	if len(reqOpts.Challenge) == 0 {
		return WebAuthnAuthenticationOptions{}, &errs.Wrapped{Msg: "fido2", Err: ErrAssertionChallengeMissing}
	}
	if reqOpts.RelyingPartyID == "" {
		return WebAuthnAuthenticationOptions{}, &errs.Wrapped{Msg: "fido2", Err: ErrAssertionRPIDMissing}
	}

	if err := ValidateRPID(reqOpts.RelyingPartyID, origin); err != nil {
		return WebAuthnAuthenticationOptions{}, err
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
		Origin:                  origin,
		RPID:                    reqOpts.RelyingPartyID,
		AllowCredentialIDs:      allowCredentialIDs,
		RequireUserVerification: reqOpts.UserVerification == protocol.VerificationRequired,
		Timeout:                 time.Duration(reqOpts.Timeout) * time.Millisecond,
	}, nil
}

// AssertWithOptionsAndOrigin drives a connected CTAP2 authenticator through a
// WebAuthn assertion ceremony whose options were issued by a relying party
// server, and returns the WebAuthn assertion JSON for the server to verify.
//
// optionsJSON is the server's BeginLogin output: the JSON-marshaled WebAuthn
// PublicKeyCredentialRequestOptions (challenge, rpId, allowCredentials,
// userVerification, timeout), in either the wrapped browser shape
// ({"publicKey": {...}}) or the bare request-options shape. It is parsed, the
// server's rpId is checked against origin (ValidateRPID), the clientDataJSON
// is built over the supplied challenge and origin, CTAP2
// authenticatorGetAssertion runs on the local authenticator, and the
// navigator.credentials.get() response document (id, rawId, type,
// response{authenticatorData, clientDataJSON, signature, userHandle}) is
// assembled.
//
// origin is the caller's WebAuthn origin and must match one of the relying
// party's configured RPOrigins or the server will reject the assertion. It is
// required: it is never derived from the server-supplied rpId.
//
// The returned bytes are exactly the body the server consumes via
// protocol.ParseCredentialRequestResponseBody in FinishLogin. The context
// bounds device acquisition; the CTAP user-presence timeout is taken from the
// options' timeout (falling back to the handler config when zero).
//
// A PIN-protected authenticator needs Assert, which carries one.
func (h *FIDO2Handler) AssertWithOptionsAndOrigin(ctx context.Context, optionsJSON []byte, origin string) ([]byte, error) {
	return h.Assert(ctx, WebAuthnAssertionRequest{OptionsJSON: optionsJSON, Origin: origin})
}

// WebAuthnAssertionRequest is the input to Assert: a relying party's
// server-issued assertion options plus the two things those options cannot
// carry — the WebAuthn origin, which a browser takes from its security
// context, and the authenticator's CTAP2 PIN, which a browser prompts for.
//
// It is the assertion-side counterpart of WebAuthnRegistrationOptions, and
// exists so the PIN is passed by NAME: origin and PIN are both strings, and a
// positional signature carrying the two adjacent would let a transposition
// send the PIN to the relying party as an origin.
type WebAuthnAssertionRequest struct {
	// OptionsJSON is the relying party's BeginLogin output, in either the
	// wrapped browser shape ({"publicKey": {...}}) or the bare
	// PublicKeyCredentialRequestOptions shape.
	OptionsJSON []byte

	// Origin is the WebAuthn origin the clientDataJSON is built over. It is
	// required, and the options' rpId must be its effective domain or a
	// registrable suffix of it (ValidateRPID).
	Origin string

	// PIN is the authenticator's CTAP2 PIN. Nil leaves the GetAssertion
	// request unauthorized, which is correct for a key with no PIN set; see
	// WebAuthnAuthenticationOptions.PIN.
	PIN *secure.Secret
}

// Assert drives a connected CTAP2 authenticator through a WebAuthn assertion
// ceremony whose options were issued by a relying party server, and returns the
// WebAuthn assertion JSON for the server to verify.
//
// It is the one assertion entry point: AssertWithOptions and
// AssertWithOptionsAndOrigin are the PIN-less shorthands over it, so every
// caller reaches the same parse, the same AuthorizeWithPIN authorization, and
// the same document assembly.
//
// The returned bytes are exactly the body the server consumes via
// protocol.ParseCredentialRequestResponseBody in FinishLogin.
func (h *FIDO2Handler) Assert(ctx context.Context, req WebAuthnAssertionRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	opts, err := parseRequestOptions(req.OptionsJSON, req.Origin)
	if err != nil {
		return nil, err
	}
	opts.PIN = req.PIN

	assertion, err := h.AuthenticateWebAuthn(opts)
	if err != nil {
		return nil, err
	}

	return assertion.PublicKeyCredentialJSON, nil
}
