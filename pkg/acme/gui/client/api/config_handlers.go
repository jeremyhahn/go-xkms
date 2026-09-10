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

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
)

// configResponseBody is the JSON representation of the ACME client configuration.
type configResponseBody struct {
	DirectoryURL        string `json:"directoryURL"`
	AccountEmail        string `json:"accountEmail"`
	Timeout             string `json:"timeout"`
	RequestServerBundle bool   `json:"requestServerBundle"`
	ChallengeType       string `json:"challengeType"`
	ChallengeHost       string `json:"challengeHost"`
	ChallengePort       string `json:"challengePort"`
	ChallengeWebRoot    string `json:"challengeWebRoot"`
	StorageBackend      string `json:"storageBackend"`
	XKMSBackend         string `json:"xkmsBackend"`
	LogLevel            string `json:"logLevel"`
	LogFormat           string `json:"logFormat"`
}

// configUpdateBody is the JSON request body for updating configuration.
type configUpdateBody struct {
	DirectoryURL        *string `json:"directoryURL,omitempty"`
	AccountEmail        *string `json:"accountEmail,omitempty"`
	Timeout             *string `json:"timeout,omitempty"`
	RequestServerBundle *bool   `json:"requestServerBundle,omitempty"`
	ChallengeHost       *string `json:"challengeHost,omitempty"`
	ChallengePort       *string `json:"challengePort,omitempty"`
	ChallengeWebRoot    *string `json:"challengeWebRoot,omitempty"`
	LogLevel            *string `json:"logLevel,omitempty"`
	LogFormat           *string `json:"logFormat,omitempty"`
}

// getConfig handles GET /api/v1/config.
//
//nolint:staticcheck // cfg.Client is deprecated but still used during Phase 4 migration
func (h *handlers) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg := h.service.Config()

	writeJSON(w, http.StatusOK, &configResponseBody{
		DirectoryURL:        cfg.Client.DirectoryURL,
		AccountEmail:        cfg.Client.AccountEmail,
		Timeout:             cfg.Client.Timeout.String(),
		RequestServerBundle: cfg.Client.RequestServerBundle,
		ChallengeHost:       cfg.Challenge.HTTP01.Host,
		ChallengePort:       cfg.Challenge.HTTP01.Port,
		ChallengeWebRoot:    cfg.Challenge.HTTP01.WebRoot,
		StorageBackend:      cfg.Storage.Backend,
		XKMSBackend:         cfg.XKMS.Backend,
		LogLevel:            cfg.Logging.Level,
		LogFormat:           cfg.Logging.Format,
	})
}

// updateConfig handles PUT /api/v1/config.
//
//nolint:staticcheck // cfg.Client is deprecated but still used during Phase 4 migration
func (h *handlers) updateConfig(w http.ResponseWriter, r *http.Request) {
	var req configUpdateBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	cfg := h.service.Config()

	if req.DirectoryURL != nil {
		cfg.Client.DirectoryURL = *req.DirectoryURL
	}
	if req.AccountEmail != nil {
		cfg.Client.AccountEmail = *req.AccountEmail
	}
	if req.Timeout != nil {
		if d, err := time.ParseDuration(*req.Timeout); err == nil {
			cfg.Client.Timeout = d
		} else {
			h.logger.Warn("invalid timeout duration, ignoring",
				slog.String("value", *req.Timeout),
				slog.String("error", err.Error()),
			)
		}
	}
	if req.RequestServerBundle != nil {
		cfg.Client.RequestServerBundle = *req.RequestServerBundle
	}
	if req.ChallengeHost != nil {
		cfg.Challenge.HTTP01.Host = *req.ChallengeHost
	}
	if req.ChallengePort != nil {
		cfg.Challenge.HTTP01.Port = *req.ChallengePort
	}
	if req.ChallengeWebRoot != nil {
		cfg.Challenge.HTTP01.WebRoot = *req.ChallengeWebRoot
	}
	if req.LogLevel != nil {
		cfg.Logging.Level = *req.LogLevel
	}
	if req.LogFormat != nil {
		cfg.Logging.Format = *req.LogFormat
	}

	writeJSON(w, http.StatusOK, &configResponseBody{
		DirectoryURL:        cfg.Client.DirectoryURL,
		AccountEmail:        cfg.Client.AccountEmail,
		Timeout:             cfg.Client.Timeout.String(),
		RequestServerBundle: cfg.Client.RequestServerBundle,
		ChallengeHost:       cfg.Challenge.HTTP01.Host,
		ChallengePort:       cfg.Challenge.HTTP01.Port,
		ChallengeWebRoot:    cfg.Challenge.HTTP01.WebRoot,
		StorageBackend:      cfg.Storage.Backend,
		XKMSBackend:         cfg.XKMS.Backend,
		LogLevel:            cfg.Logging.Level,
		LogFormat:           cfg.Logging.Format,
	})
}

// Compile-time check that configUpdateBody fields align with svc.Config.
//
//nolint:staticcheck // deprecated field used in compile-time check
var _ = func() {
	_ = svc.Config{}.Client.DirectoryURL
	_ = svc.Config{}.Challenge.HTTP01.Port
}
