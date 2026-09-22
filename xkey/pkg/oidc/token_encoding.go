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
	"fmt"
	"net/url"
)

// TokenEncoding selects how a token request body is encoded when POSTed to
// a provider's token endpoint. RFC 6749 specifies form encoding, but some
// providers expect application/json instead.
type TokenEncoding string

const (
	// TokenEncodingForm posts the token request as
	// application/x-www-form-urlencoded (RFC 6749; the default).
	TokenEncodingForm TokenEncoding = "form"

	// TokenEncodingJSON posts the token request as application/json.
	TokenEncodingJSON TokenEncoding = "json"
)

// Validate returns ErrInvalidTokenEncoding unless e is empty (which
// defaults to TokenEncodingForm), TokenEncodingForm, or TokenEncodingJSON.
func (e TokenEncoding) Validate() error {
	switch e {
	case "", TokenEncodingForm, TokenEncodingJSON:
		return nil
	default:
		return &DetailError{Err: ErrInvalidTokenEncoding, Detail: fmt.Sprintf(": %q", string(e))}
	}
}

// orDefault returns e, defaulting to TokenEncodingForm when e is empty.
func (e TokenEncoding) orDefault() TokenEncoding {
	if e == "" {
		return TokenEncodingForm
	}
	return e
}

// EncodeTokenRequestBody encodes token request parameters per encoding,
// returning the request body and the Content-Type header value to send
// with it. It is the single place that decides how a token endpoint is
// addressed, shared by the Client's own token requests and by cmd/xkey's
// CLI login/refresh path so the two callers never diverge on encoding.
//
// An empty encoding defaults to TokenEncodingForm so existing callers that
// never set it see no behavior change.
func EncodeTokenRequestBody(encoding TokenEncoding, data url.Values) (body []byte, contentType string, err error) {
	if err := encoding.Validate(); err != nil {
		return nil, "", err
	}

	switch encoding.orDefault() {
	case TokenEncodingJSON:
		fields := make(map[string]string, len(data))
		for key := range data {
			fields[key] = data.Get(key)
		}
		body, err = json.Marshal(fields)
		if err != nil {
			return nil, "", &SentinelCauseError{Sentinel: ErrTokenExchangeFailed, Cause: err}
		}
		return body, "application/json", nil
	default:
		return []byte(data.Encode()), "application/x-www-form-urlencoded", nil
	}
}
