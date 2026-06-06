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

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// renewalStatusResponse is the JSON response for renewal service status.
type renewalStatusResponse struct {
	Enabled          bool   `json:"enabled"`
	CheckInterval    string `json:"checkInterval"`
	RenewalThreshold string `json:"renewalThreshold"`
}

// renewalConfigResponse is the JSON response for renewal configuration.
type renewalConfigResponse struct {
	Enabled          bool    `json:"enabled"`
	CheckInterval    string  `json:"checkInterval"`
	RenewalThreshold float64 `json:"renewalThreshold"`
	MaxRetries       int     `json:"maxRetries"`
	RetryInterval    string  `json:"retryInterval"`
	NotifyOnSuccess  bool    `json:"notifyOnSuccess"`
	NotifyOnFailure  bool    `json:"notifyOnFailure"`
}

// renewalConfigUpdateBody is the JSON request body for updating renewal config.
type renewalConfigUpdateBody struct {
	Enabled          *bool    `json:"enabled,omitempty"`
	CheckInterval    *string  `json:"checkInterval,omitempty"`
	RenewalThreshold *float64 `json:"renewalThreshold,omitempty"`
	MaxRetries       *int     `json:"maxRetries,omitempty"`
	RetryInterval    *string  `json:"retryInterval,omitempty"`
	NotifyOnSuccess  *bool    `json:"notifyOnSuccess,omitempty"`
	NotifyOnFailure  *bool    `json:"notifyOnFailure,omitempty"`
}

// renewalStatus handles GET /api/v1/renewal/status.
//
//nolint:staticcheck // cfg.Renewal is deprecated but still used during Phase 4 migration
func (h *handlers) renewalStatus(w http.ResponseWriter, r *http.Request) {
	cfg := h.service.Config()

	writeJSON(w, http.StatusOK, &renewalStatusResponse{
		Enabled:          cfg.Renewal.Enabled,
		CheckInterval:    cfg.Renewal.CheckInterval.String(),
		RenewalThreshold: formatThreshold(cfg.Renewal.RenewalThreshold),
	})
}

// getRenewalConfig handles GET /api/v1/renewal/config.
//
//nolint:staticcheck // cfg.Renewal is deprecated but still used during Phase 4 migration
func (h *handlers) getRenewalConfig(w http.ResponseWriter, r *http.Request) {
	cfg := h.service.Config()

	writeJSON(w, http.StatusOK, &renewalConfigResponse{
		Enabled:          cfg.Renewal.Enabled,
		CheckInterval:    cfg.Renewal.CheckInterval.String(),
		RenewalThreshold: cfg.Renewal.RenewalThreshold,
		MaxRetries:       cfg.Renewal.MaxRetries,
		RetryInterval:    cfg.Renewal.RetryInterval.String(),
		NotifyOnSuccess:  cfg.Renewal.NotifyOnSuccess,
		NotifyOnFailure:  cfg.Renewal.NotifyOnFailure,
	})
}

// updateRenewalConfig handles PUT /api/v1/renewal/config.
//
//nolint:staticcheck // cfg.Renewal is deprecated but still used during Phase 4 migration
func (h *handlers) updateRenewalConfig(w http.ResponseWriter, r *http.Request) {
	var req renewalConfigUpdateBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	cfg := h.service.Config()

	if req.Enabled != nil {
		cfg.Renewal.Enabled = *req.Enabled
	}
	if req.CheckInterval != nil {
		if d, err := time.ParseDuration(*req.CheckInterval); err == nil {
			cfg.Renewal.CheckInterval = d
		} else {
			h.logger.Warn("invalid check interval, ignoring",
				slog.String("value", *req.CheckInterval),
				slog.String("error", err.Error()),
			)
		}
	}
	if req.RenewalThreshold != nil {
		cfg.Renewal.RenewalThreshold = *req.RenewalThreshold
	}
	if req.MaxRetries != nil {
		cfg.Renewal.MaxRetries = *req.MaxRetries
	}
	if req.RetryInterval != nil {
		if d, err := time.ParseDuration(*req.RetryInterval); err == nil {
			cfg.Renewal.RetryInterval = d
		} else {
			h.logger.Warn("invalid retry interval, ignoring",
				slog.String("value", *req.RetryInterval),
				slog.String("error", err.Error()),
			)
		}
	}
	if req.NotifyOnSuccess != nil {
		cfg.Renewal.NotifyOnSuccess = *req.NotifyOnSuccess
	}
	if req.NotifyOnFailure != nil {
		cfg.Renewal.NotifyOnFailure = *req.NotifyOnFailure
	}

	writeJSON(w, http.StatusOK, &renewalConfigResponse{
		Enabled:          cfg.Renewal.Enabled,
		CheckInterval:    cfg.Renewal.CheckInterval.String(),
		RenewalThreshold: cfg.Renewal.RenewalThreshold,
		MaxRetries:       cfg.Renewal.MaxRetries,
		RetryInterval:    cfg.Renewal.RetryInterval.String(),
		NotifyOnSuccess:  cfg.Renewal.NotifyOnSuccess,
		NotifyOnFailure:  cfg.Renewal.NotifyOnFailure,
	})
}

// formatThreshold formats a renewal threshold as a percentage string.
func formatThreshold(threshold float64) string {
	pct := threshold * 100
	if pct == float64(int(pct)) {
		return string(rune('0'+int(pct)/10)) + string(rune('0'+int(pct)%10)) + "%"
	}
	// Use simple formatting for typical values
	switch threshold {
	case 0.33:
		return "33%"
	case 0.25:
		return "25%"
	case 0.5:
		return "50%"
	default:
		return formatFloat(pct) + "%"
	}
}

// formatFloat formats a float without trailing zeros.
func formatFloat(f float64) string {
	s := make([]byte, 0, 8)
	i := int(f)
	if i < 0 {
		s = append(s, '-')
		i = -i
		f = -f
	}
	if i >= 100 {
		s = append(s, byte('0'+i/100))
	}
	if i >= 10 {
		s = append(s, byte('0'+(i%100)/10))
	}
	s = append(s, byte('0'+i%10))

	frac := f - float64(int(f))
	if frac > 0.001 {
		s = append(s, '.')
		d := int(frac*100 + 0.5)
		s = append(s, byte('0'+d/10))
		if d%10 != 0 {
			s = append(s, byte('0'+d%10))
		}
	}
	return string(s)
}
