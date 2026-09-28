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

package main

import (
	"net/url"
	"strings"

	webauthnclient "github.com/jeremyhahn/go-xkms/sdk/go/webauthnclient"
	"github.com/spf13/cobra"
)

// originFlag names the flag every xkmsctl WebAuthn ceremony verb reads its
// origin from.
const originFlag = "origin"

// addOriginFlag declares --origin on a WebAuthn ceremony verb, so "user
// register", "user login" and "admin create" share one name and help text.
func addOriginFlag(cmd *cobra.Command) {
	cmd.Flags().String(originFlag, "",
		"WebAuthn origin bound into the ceremony, e.g. https://kms.example.com (default: derived from an http(s) --server)")
}

// resolveWebAuthnOrigin returns the WebAuthn origin a ceremony binds into its
// clientDataJSON: --origin when given, otherwise the scheme and authority of
// an http:// or https:// --server URL. Any other transport (the default Unix
// socket, grpc://, quic://) has no web origin to derive, so the operator must
// name it with --origin.
//
// The origin is never derived from the relying party ID the server supplies in
// its ceremony options: that would let the server choose the origin the
// authenticator's rpId is checked against (fido2.ValidateRPID).
func resolveWebAuthnOrigin(cmd *cobra.Command, server string) (string, error) {
	fr := newFlagReader(cmd)
	origin := fr.String(originFlag)
	if err := fr.Err(); err != nil {
		return "", err
	}
	if origin != "" {
		return origin, nil
	}

	parsed, err := url.Parse(strings.TrimSpace(server))
	if err != nil {
		return "", ErrWebAuthnOriginRequired
	}
	switch parsed.Scheme {
	case "http", "https":
		if derived := webauthnclient.OriginFromURL(server); derived != "" {
			return derived, nil
		}
	}
	return "", ErrWebAuthnOriginRequired
}
