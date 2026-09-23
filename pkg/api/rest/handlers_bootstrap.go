// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package rest

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// bootstrapServicer is the subset of the XKMS service the bootstrap handlers
// need. Keeping it an interface lets the handler be driven directly in tests
// without standing up a qrdb node.
type bootstrapServicer interface {
	BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error)
}

// BootstrapHandlers serves read access to the running trust-bootstrap
// listener's public keys (go-xkms#632). There is no write surface: the
// listener generates or unseals its own key at startup
// (pkg/server/bootstrap_key_custody.go), and it is never accepted from the
// API.
type BootstrapHandlers struct {
	svc    bootstrapServicer
	logger *slog.Logger
}

// NewBootstrapHandlers creates BootstrapHandlers over the given servicer.
func NewBootstrapHandlers(svc bootstrapServicer, logger *slog.Logger) *BootstrapHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &BootstrapHandlers{svc: svc, logger: logger}
}

// ShowKeysHandler handles GET /api/v1/bootstrap/keys.
func (h *BootstrapHandlers) ShowKeysHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.svc.BootstrapListenerKeys(r.Context())
	if err != nil {
		h.writeBootstrapError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// writeBootstrapError maps trust-bootstrap listener failures onto HTTP
// status codes. An unenabled listener is a deployment shape, not a caller
// mistake, so it reports 503 rather than 500.
func (h *BootstrapHandlers) writeBootstrapError(w http.ResponseWriter, err error) {
	if errors.Is(err, xkms.ErrBootstrapListenerNotEnabled) {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}

	h.logger.Error("bootstrap listener keys failed", "error", err)
	writeErrorWithMessage(w, ErrInternalError, "bootstrap listener keys failed", http.StatusInternalServerError)
}
