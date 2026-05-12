// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// MapDAONotFound checks if the error is a DAO not-found error and returns
// the appropriate ACME error. Returns nil if the error is not a not-found
// error, indicating the caller should handle it differently.
func MapDAONotFound(err error, entityType string) *entities.Error {
	if !qrdbsdk.IsDAONotFound(err) {
		return nil
	}
	switch entityType {
	case "account":
		return common.AccountDoesNotExist("Account not found")
	case "order":
		return common.MalformedError("Order not found", nil)
	case "authorization":
		return common.MalformedError("Authorization not found", nil)
	case "challenge":
		return common.MalformedError("Challenge not found", nil)
	case "certificate":
		return common.MalformedError("Certificate not found", nil)
	case "nonce":
		return common.BadNonce("Nonce not found")
	case "eab":
		return common.Unauthorized("External account binding not found")
	case "tenant":
		return common.ServerInternal("Tenant not found")
	default:
		return common.ServerInternal("Entity not found: " + entityType)
	}
}
