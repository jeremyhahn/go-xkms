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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// WebAuthnRegistrationOptions carries the parameters the client needs to drive a
// CTAP2 authenticator through a WebAuthn registration ceremony. These are
// derived from the server's BeginRegistration output
// (a protocol.CredentialCreation): the challenge, relying party, and user.
type WebAuthnRegistrationOptions struct {
	Challenge               []byte
	Origin                  string
	RPID                    string
	RPName                  string
	UserID                  []byte
	UserName                string
	UserDisplayName         string
	RequireUserVerification bool
	Timeout                 time.Duration

	// PIN is the authenticator's CTAP2 PIN. An authenticator with a PIN set
	// refuses MakeCredential outright (CTAP2_ERR_PIN_REQUIRED) unless the
	// request carries a pinUvAuthParam, so this is what makes registration
	// possible against a PIN-protected key with no browser to prompt for it.
	//
	// The PIN is opened only inside AuthorizeWithPIN, at the point the CTAP2
	// pinUvAuth computation needs its bytes. Nil leaves the request
	// unauthorized, which is correct for a key with no PIN configured.
	PIN *secure.Secret
}

// WebAuthnAttestation is the result of a WebAuthn registration ceremony. The
// PublicKeyCredentialJSON is a standard WebAuthn PublicKeyCredential document
// that the server consumes via protocol.ParseCredentialCreationResponseBody.
type WebAuthnAttestation struct {
	CredentialID            []byte
	PublicKeyCredentialJSON []byte
}

// collectedClientData is the WebAuthn CollectedClientData structure that is
// serialized to clientDataJSON for a registration ceremony.
type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// authenticatorResponseJSON is the inner "response" object of a
// PublicKeyCredential for a registration (AuthenticatorAttestationResponse).
type authenticatorResponseJSON struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

// publicKeyCredentialJSON is the top-level PublicKeyCredential document the
// server parses with protocol.ParseCredentialCreationResponseBody.
type publicKeyCredentialJSON struct {
	ID       string                    `json:"id"`
	RawID    string                    `json:"rawId"`
	Type     string                    `json:"type"`
	Response authenticatorResponseJSON `json:"response"`
}

// b64url encodes data as unpadded base64url, the encoding WebAuthn JSON uses
// for binary fields (challenge, credential id, attestationObject, clientDataJSON).
func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// buildClientDataJSON constructs the WebAuthn CollectedClientData document for a
// registration ceremony: {"type":"webauthn.create","challenge":base64url(challenge),"origin":origin}.
// The challenge is base64url-encoded (RawURLEncoding, no padding) exactly as the
// server expects when it re-derives and compares the challenge.
func buildClientDataJSON(challenge []byte, origin string) ([]byte, error) {
	cd := collectedClientData{
		Type:      "webauthn.create",
		Challenge: b64url(challenge),
		Origin:    origin,
	}
	out, err := json.Marshal(cd)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "fido2: failed to marshal clientDataJSON", Err: err}
	}
	return out, nil
}

// encodeAttestationObject CBOR-encodes the WebAuthn attestationObject map from
// the three fields produced by a CTAP2 authenticatorMakeCredential response:
// {"fmt": Fmt, "attStmt": AttStmt, "authData": AuthData}. CTAP2 canonical
// (CTAP2-mode) CBOR encoding is used to match what FIDO2 authenticators emit and
// what the go-webauthn parser expects.
func encodeAttestationObject(resp *MakeCredentialResponse) ([]byte, error) {
	if resp == nil {
		return nil, &errs.Message{Msg: "fido2: nil MakeCredentialResponse"}
	}
	if len(resp.AuthData) == 0 {
		return nil, &errs.Message{Msg: "fido2: MakeCredentialResponse missing authData"}
	}

	attStmt := resp.AttStmt
	if attStmt == nil {
		attStmt = map[string]interface{}{}
	}

	attObj := map[string]interface{}{
		"fmt":      resp.Fmt,
		"attStmt":  attStmt,
		"authData": resp.AuthData,
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "fido2: failed to build CBOR encoder", Err: err}
	}

	encoded, err := encMode.Marshal(attObj)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "fido2: failed to encode attestationObject", Err: err}
	}
	return encoded, nil
}

// extractCredentialID parses the attested credential data out of WebAuthn
// authenticator data. The authData layout is:
//
//	rpIdHash[32] | flags[1] | signCount[4] | attestedCredentialData...
//
// where attestedCredentialData (present only when the AT flag, bit 6, is set) is:
//
//	aaguid[16] | credIdLen[2 big-endian] | credId[credIdLen] | credentialPublicKey(CBOR)
func extractCredentialID(authData []byte) ([]byte, error) {
	// rpIdHash(32) + flags(1) + signCount(4) = 37 byte fixed header.
	if len(authData) < 37 {
		return nil, &errs.Message{Msg: fmt.Sprintf("fido2: authData too short: %d bytes", len(authData))}
	}

	flags := authData[32]
	const flagAttestedCredentialData = 0x40 // AT flag, bit 6
	if flags&flagAttestedCredentialData == 0 {
		return nil, &errs.Message{Msg: "fido2: authData has no attested credential data (AT flag unset)"}
	}

	// attestedCredentialData starts at offset 37: aaguid(16) then credIdLen(2).
	const aaguidLen = 16
	credIDLenOffset := 37 + aaguidLen
	if len(authData) < credIDLenOffset+2 {
		return nil, &errs.Message{Msg: "fido2: authData truncated before credential id length"}
	}

	credIDLen := int(authData[credIDLenOffset])<<8 | int(authData[credIDLenOffset+1])
	credIDStart := credIDLenOffset + 2
	credIDEnd := credIDStart + credIDLen
	if len(authData) < credIDEnd {
		return nil, &errs.Message{Msg: fmt.Sprintf("fido2: authData truncated: credential id length %d exceeds buffer", credIDLen)}
	}

	credentialID := make([]byte, credIDLen)
	copy(credentialID, authData[credIDStart:credIDEnd])
	return credentialID, nil
}

// buildPublicKeyCredentialJSON assembles the full WebAuthn PublicKeyCredential
// JSON document from a CTAP2 MakeCredential response and the clientDataJSON. The
// resulting document is what the xkms server consumes via
// protocol.ParseCredentialCreationResponseBody.
func buildPublicKeyCredentialJSON(resp *MakeCredentialResponse, clientDataJSON []byte) (credentialID, doc []byte, err error) {
	credentialID, err = extractCredentialID(resp.AuthData)
	if err != nil {
		return nil, nil, err
	}

	attObj, err := encodeAttestationObject(resp)
	if err != nil {
		return nil, nil, err
	}

	credIDB64 := b64url(credentialID)
	cred := publicKeyCredentialJSON{
		ID:    credIDB64,
		RawID: credIDB64,
		Type:  "public-key",
		Response: authenticatorResponseJSON{
			AttestationObject: b64url(attObj),
			ClientDataJSON:    b64url(clientDataJSON),
		},
	}

	doc, err = json.Marshal(cred)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "fido2: failed to marshal PublicKeyCredential JSON", Err: err}
	}
	return credentialID, doc, nil
}

// makeCredentialPubKeyParams returns the pubKeyCredParams advertised to the
// authenticator. ES256 (-7) is preferred; RS256 (-257) is also offered to match
// the algorithms the rest of the FIDO2 package supports.
func makeCredentialPubKeyParams() []PublicKeyCredentialParameter {
	return []PublicKeyCredentialParameter{
		{Type: "public-key", Alg: COSEAlgES256},
		{Type: "public-key", Alg: COSEAlgRS256},
	}
}

// buildWebAuthnAttestation runs the pure construction half of the registration
// ceremony: it builds the clientDataJSON, encodes the attestationObject, extracts
// the credential id, and assembles the PublicKeyCredential document. It is the
// shared, device-free core used by RegisterWebAuthn and exercised directly by the
// unit tests.
func buildWebAuthnAttestation(resp *MakeCredentialResponse, challenge []byte, origin string) (*WebAuthnAttestation, error) {
	clientDataJSON, err := buildClientDataJSON(challenge, origin)
	if err != nil {
		return nil, err
	}

	credentialID, doc, err := buildPublicKeyCredentialJSON(resp, clientDataJSON)
	if err != nil {
		return nil, err
	}

	return &WebAuthnAttestation{
		CredentialID:            credentialID,
		PublicKeyCredentialJSON: doc,
	}, nil
}

// RegisterWebAuthn drives a CTAP2 authenticator through a WebAuthn registration
// ceremony and emits a standard WebAuthn PublicKeyCredential JSON document — the
// attestation the xkms server consumes via
// protocol.ParseCredentialCreationResponseBody.
//
// Given the server's BeginRegistration output (challenge, relying party, user),
// it builds the clientDataJSON, computes the clientDataHash, invokes
// authenticatorMakeCredential, encodes the returned fmt/authData/attStmt into a
// CBOR attestationObject, extracts the credential id from the attested credential
// data, and assembles the PublicKeyCredential document.
// BindDevice pins subsequent ceremonies to one authenticator path.
//
// Callers that have already resolved which of several attached authenticators
// to use call this so selectDevice does not independently choose another.
func (h *FIDO2Handler) BindDevice(path string) {
	h.config.DevicePath = path
}

// ParseWebAuthnRegistrationOptions decodes a relying party's registration
// options document into WebAuthnRegistrationOptions, the RegisterWebAuthn
// input. Both the browser-shaped wrapped document ({"publicKey": {...}}) and
// the bare PublicKeyCredentialCreationOptions object are accepted, mirroring
// parseRequestOptions on the assertion side.
//
// The origin is NOT carried in the options - a browser supplies it from its
// security context - so the caller provides it, and the server's rp.id must be
// the origin's effective domain or a registrable suffix of it (ValidateRPID).
// An empty origin is refused: it is never derived from the server-supplied
// rp.id.
func ParseWebAuthnRegistrationOptions(optionsJSON []byte, origin string) (WebAuthnRegistrationOptions, error) {
	if len(optionsJSON) == 0 {
		return WebAuthnRegistrationOptions{}, &errs.Wrapped{Msg: "fido2", Err: ErrRegistrationOptionsRequired}
	}

	// Accept the wrapped CredentialCreation ({"publicKey": {...}}) first; if
	// the publicKey member is absent the document is a bare creation-options
	// object, which we then decode directly.
	var wrapped protocol.CredentialCreation
	if err := json.Unmarshal(optionsJSON, &wrapped); err != nil {
		return WebAuthnRegistrationOptions{}, &errs.Wrapped{Msg: "fido2: failed to parse registration options", Err: err}
	}

	opts := wrapped.Response
	if len(opts.Challenge) == 0 {
		// No publicKey wrapper present — decode the bare creation options.
		if err := json.Unmarshal(optionsJSON, &opts); err != nil {
			return WebAuthnRegistrationOptions{}, &errs.Wrapped{Msg: "fido2: failed to parse registration options", Err: err}
		}
	}

	if len(opts.Challenge) == 0 {
		return WebAuthnRegistrationOptions{}, &errs.Wrapped{Msg: "fido2", Err: ErrRegistrationChallengeMissing}
	}
	if opts.RelyingParty.ID == "" {
		return WebAuthnRegistrationOptions{}, &errs.Wrapped{Msg: "fido2", Err: ErrRegistrationRPIDMissing}
	}

	userID, err := decodeWebAuthnUserHandle(opts.User.ID)
	if err != nil {
		return WebAuthnRegistrationOptions{}, &errs.Wrapped{Msg: "fido2: failed to decode user handle", Err: err}
	}

	if err := ValidateRPID(opts.RelyingParty.ID, origin); err != nil {
		return WebAuthnRegistrationOptions{}, err
	}

	challenge := make([]byte, len(opts.Challenge))
	copy(challenge, opts.Challenge)

	return WebAuthnRegistrationOptions{
		Challenge:               challenge,
		Origin:                  origin,
		RPID:                    opts.RelyingParty.ID,
		RPName:                  opts.RelyingParty.Name,
		UserID:                  userID,
		UserName:                opts.User.Name,
		UserDisplayName:         opts.User.DisplayName,
		RequireUserVerification: opts.AuthenticatorSelection.UserVerification == protocol.VerificationRequired,
		Timeout:                 time.Duration(opts.Timeout) * time.Millisecond,
	}, nil
}

// decodeWebAuthnUserHandle extracts the WebAuthn user handle bytes from the
// JSON-decoded User.ID field of a PublicKeyCredentialCreationOptions. The
// go-webauthn protocol package types User.ID as `any` because a generically
// decoded JSON document represents it as a base64url string rather than raw
// bytes.
func decodeWebAuthnUserHandle(id any) ([]byte, error) {
	switch v := id.(type) {
	case string:
		decoded, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	case []byte:
		return v, nil
	case nil:
		return nil, nil
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("fido2: unsupported user handle type %T", id)}
	}
}

func (h *FIDO2Handler) RegisterWebAuthn(opts WebAuthnRegistrationOptions) (*WebAuthnAttestation, error) {
	if len(opts.Challenge) == 0 {
		return nil, &errs.Message{Msg: "fido2: registration challenge required"}
	}
	if err := ValidateRPID(opts.RPID, opts.Origin); err != nil {
		return nil, err
	}

	// Build clientDataJSON and derive the clientDataHash the authenticator signs.
	clientDataJSON, err := buildClientDataJSON(opts.Challenge, opts.Origin)
	if err != nil {
		return nil, err
	}
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Acquire a device and authenticator using the same setup as EnrollKey.
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

	req := &MakeCredentialRequest{
		ClientDataHash: clientDataHash[:],
		RP: RelyingParty{
			ID:   opts.RPID,
			Name: opts.RPName,
		},
		User: User{
			ID:          opts.UserID,
			Name:        opts.UserName,
			DisplayName: opts.UserDisplayName,
		},
		PubKeyCredParams: makeCredentialPubKeyParams(),
		Options: AuthenticatorOptions{
			UV: opts.RequireUserVerification,
		},
	}

	if opts.PIN != nil {
		param, protocol, perr := auth.AuthorizeWithPIN(opts.PIN, clientDataHash[:])
		if perr != nil {
			return nil, perr
		}
		req.PinUVAuthParam = param
		req.PinUVAuthProtocol = protocol

		// A pinUvAuthToken IS the user verification, and it supersedes the
		// "uv" option: CTAP 2.1 6.1.2 reserves "uv" for an authenticator's
		// BUILT-IN verification method, so a PIN-only key answers uv:true with
		// CTAP2_ERR_INVALID_OPTION even as it verifies the user by PIN.
		req.Options.UV = false
	}

	h.logger.Printf("Please touch your security key to register...")
	resp, err := auth.MakeCredential(req)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "fido2: MakeCredential failed", Err: err}
	}

	return buildWebAuthnAttestation(resp, opts.Challenge, opts.Origin)
}
