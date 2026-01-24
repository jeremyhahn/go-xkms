// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import "context"

// AutoGrantHandler always grants user presence and verification requests.
// This is the default handler for automation and testing scenarios.
// All methods are safe for concurrent use.
type AutoGrantHandler struct {
	// simulatedPIN is the PIN to return for verification requests
	// when PINRequired is true. If empty, verification succeeds without PIN.
	simulatedPIN string
}

// NewAutoGrantHandler creates a new AutoGrantHandler that automatically
// approves all user presence and verification requests.
func NewAutoGrantHandler() *AutoGrantHandler {
	return &AutoGrantHandler{}
}

// NewAutoGrantHandlerWithPIN creates an AutoGrantHandler that returns
// a simulated PIN for verification requests requiring PIN entry.
func NewAutoGrantHandlerWithPIN(pin string) *AutoGrantHandler {
	return &AutoGrantHandler{simulatedPIN: pin}
}

// RequestUserPresence always returns approved.
// It respects context cancellation.
func (h *AutoGrantHandler) RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return &UserPresenceResult{Approved: true}, nil
	}
}

// RequestUserVerification always returns verified with the simulated PIN if set.
// It respects context cancellation.
func (h *AutoGrantHandler) RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return &UserVerificationResult{
			Verified: true,
			PIN:      h.simulatedPIN,
		}, nil
	}
}

// Ensure AutoGrantHandler implements UserPresenceHandler at compile time.
var _ UserPresenceHandler = (*AutoGrantHandler)(nil)
