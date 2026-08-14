//go:build codec_json

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

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// auditTestEvent builds a valid audit event offset from a fixed base time.
func auditTestEvent(index int, eventType audit.EventType, actor string, result audit.Result) *audit.AuditEvent {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	return &audit.AuditEvent{
		Timestamp: base.Add(time.Duration(index) * time.Minute),
		EventType: eventType,
		Actor:     actor,
		Resource:  "certificate:" + actor,
		Action:    "issue",
		Result:    result,
		RequestID: "req-" + actor,
	}
}

// newAuditBackedHandlers writes the given events through the real audit logger
// and returns handlers wired to a querier over that trail.
func newAuditBackedHandlers(t *testing.T, events ...*audit.AuditEvent) *Handlers {
	t.Helper()

	config := &audit.Config{
		Enabled:              true,
		LogPath:              filepath.Join(t.TempDir(), "audit.log"),
		MaxSizeMB:            10,
		MaxAgeDays:           1,
		MaxBackups:           2,
		Format:               "json",
		BufferSize:           128,
		FlushIntervalSeconds: 1,
	}

	logger, err := audit.NewFileAuditLogger(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	for _, event := range events {
		require.NoError(t, logger.Log(context.Background(), event))
	}
	require.NoError(t, logger.Flush())

	querier, err := audit.NewFileQuerier(config)
	require.NoError(t, err)

	return NewHandlers(nil, slog.Default(), WithAuditQuerier(querier))
}

// listAuditLogs performs a GET against the audit endpoint and decodes the body.
func listAuditLogs(t *testing.T, h *Handlers, query string) (*httptest.ResponseRecorder, ListResponse) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/admin/audit"+query, nil)
	w := httptest.NewRecorder()
	h.ListAuditLogs(w, req)

	var resp ListResponse
	if w.Code == http.StatusOK {
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	}

	return w, resp
}

// auditItems decodes the generic list payload into audit events.
func auditItems(t *testing.T, resp ListResponse) []*audit.AuditEvent {
	t.Helper()

	raw, err := json.Marshal(resp.Items)
	require.NoError(t, err)

	var events []*audit.AuditEvent
	require.NoError(t, json.Unmarshal(raw, &events))

	return events
}

// TestHandlers_ListAuditLogs_ReturnsRecordedEvents is the regression test for
// the handler that used to answer "no events" for every deployment: a trail
// that holds events must report them.
func TestHandlers_ListAuditLogs_ReturnsRecordedEvents(t *testing.T) {
	h := newAuditBackedHandlers(t,
		auditTestEvent(0, audit.EventCertificateIssued, "alice", audit.ResultSuccess),
		auditTestEvent(1, audit.EventCertificateRevoked, "bob", audit.ResultSuccess),
		auditTestEvent(2, audit.EventAuthenticationFailed, "carol", audit.ResultFailure),
	)

	w, resp := listAuditLogs(t, h, "")
	require.Equal(t, http.StatusOK, w.Code)

	assert.Equal(t, 3, resp.Total)
	assert.Equal(t, 1, resp.Page)
	assert.Equal(t, audit.DefaultQueryPageSize, resp.PerPage)

	events := auditItems(t, resp)
	require.Len(t, events, 3)

	// Newest first.
	assert.Equal(t, audit.EventAuthenticationFailed, events[0].EventType)
	assert.Equal(t, "carol", events[0].Actor)
	assert.Equal(t, audit.ResultFailure, events[0].Result)
	assert.Equal(t, audit.EventCertificateIssued, events[2].EventType)
}

// TestHandlers_ListAuditLogs_Paging verifies page and per_page are honoured.
func TestHandlers_ListAuditLogs_Paging(t *testing.T) {
	events := make([]*audit.AuditEvent, 0, 9)
	for i := 0; i < 9; i++ {
		events = append(events, auditTestEvent(i, audit.EventOrderCreated, "actor", audit.ResultSuccess))
	}
	h := newAuditBackedHandlers(t, events...)

	tests := []struct {
		name    string
		query   string
		wantLen int
		wantTop int
	}{
		{"first page", "?page=1&per_page=4", 4, 8},
		{"second page", "?page=2&per_page=4", 4, 4},
		{"final partial page", "?page=3&per_page=4", 1, 0},
		{"page past the end", "?page=4&per_page=4", 0, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, resp := listAuditLogs(t, h, tt.query)
			require.Equal(t, http.StatusOK, w.Code)

			assert.Equal(t, 9, resp.Total)
			got := auditItems(t, resp)
			require.Len(t, got, tt.wantLen)

			if tt.wantTop >= 0 {
				assert.Equal(t, events[tt.wantTop].Timestamp.UTC(), got[0].Timestamp.UTC())
			}
		})
	}
}

// TestHandlers_ListAuditLogs_Filters verifies every filter reaches the trail.
func TestHandlers_ListAuditLogs_Filters(t *testing.T) {
	issued := auditTestEvent(0, audit.EventCertificateIssued, "alice", audit.ResultSuccess)
	revoked := auditTestEvent(1, audit.EventCertificateRevoked, "bob", audit.ResultSuccess)
	failed := auditTestEvent(2, audit.EventAuthenticationFailed, "alice", audit.ResultFailure)
	failed.Action = "authenticate"

	h := newAuditBackedHandlers(t, issued, revoked, failed)

	tests := []struct {
		name  string
		query string
		want  int
	}{
		{"event type", "?event_type=CERTIFICATE_ISSUED", 1},
		{"actor", "?actor=alice", 2},
		{"resource", "?resource=certificate:bob", 1},
		{"action", "?action=authenticate", 1},
		{"result", "?result=failure", 1},
		{"request id", "?request_id=req-bob", 1},
		{"combined", "?actor=alice&result=success", 1},
		{"start time", "?start_time=" + revoked.Timestamp.Format(time.RFC3339), 2},
		{"end time", "?end_time=" + revoked.Timestamp.Format(time.RFC3339), 2},
		{
			"time range",
			"?start_time=" + revoked.Timestamp.Format(time.RFC3339) +
				"&end_time=" + revoked.Timestamp.Format(time.RFC3339),
			1,
		},
		{"no match", "?actor=nobody", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, resp := listAuditLogs(t, h, tt.query)
			require.Equal(t, http.StatusOK, w.Code)

			assert.Equal(t, tt.want, resp.Total)
			assert.Len(t, auditItems(t, resp), tt.want)
		})
	}
}

// TestHandlers_ListAuditLogs_EmptyTrailIsGenuine verifies an empty result is
// reported only when the configured trail really holds nothing.
func TestHandlers_ListAuditLogs_EmptyTrailIsGenuine(t *testing.T) {
	h := newAuditBackedHandlers(t)

	w, resp := listAuditLogs(t, h, "")
	require.Equal(t, http.StatusOK, w.Code)

	assert.Equal(t, 0, resp.Total)
	assert.Empty(t, auditItems(t, resp))

	// The same handler shape reports events once the trail has them, which is
	// what distinguishes this empty answer from a fabricated one.
	withEvents := newAuditBackedHandlers(t, auditTestEvent(0, audit.EventCAInitialized, "system", audit.ResultSuccess))
	w, resp = listAuditLogs(t, withEvents, "")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, resp.Total)
}

// TestHandlers_ListAuditLogs_NotConfigured verifies a server without an audit
// trail says so instead of reporting an empty trail.
func TestHandlers_ListAuditLogs_NotConfigured(t *testing.T) {
	h := NewHandlers(nil, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	w := httptest.NewRecorder()
	h.ListAuditLogs(w, req)

	require.Equal(t, http.StatusNotImplemented, w.Code)

	var problem ProblemDetail
	require.NoError(t, json.NewDecoder(w.Body).Decode(&problem))
	assert.Equal(t, http.StatusNotImplemented, problem.Status)
	assert.Contains(t, problem.Detail, "no audit trail")
}

// TestHandlers_ListAuditLogs_BadRequests verifies malformed queries are
// rejected rather than silently ignored.
func TestHandlers_ListAuditLogs_BadRequests(t *testing.T) {
	h := newAuditBackedHandlers(t, auditTestEvent(0, audit.EventOrderCreated, "actor", audit.ResultSuccess))

	tests := []struct {
		name  string
		query string
	}{
		{"invalid start time", "?start_time=yesterday"},
		{"invalid end time", "?end_time=2026-13-45"},
		{"inverted range", "?start_time=2026-03-02T00:00:00Z&end_time=2026-03-01T00:00:00Z"},
		{"window exceeded", "?page=1000&per_page=100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/audit"+tt.query, nil)
			w := httptest.NewRecorder()
			h.ListAuditLogs(w, req)

			require.Equal(t, http.StatusBadRequest, w.Code)

			var problem ProblemDetail
			require.NoError(t, json.NewDecoder(w.Body).Decode(&problem))
			assert.NotEmpty(t, problem.Detail)
		})
	}
}

// failingQuerier reports a storage failure for every query.
type failingQuerier struct {
	err error
}

func (f *failingQuerier) Query(context.Context, audit.Query) (*audit.QueryResult, error) {
	return nil, f.err
}

// TestHandlers_ListAuditLogs_QueryFailure verifies a trail that cannot be read
// surfaces as a server error rather than an empty page.
func TestHandlers_ListAuditLogs_QueryFailure(t *testing.T) {
	h := NewHandlers(nil, slog.Default(),
		WithAuditQuerier(&failingQuerier{err: errors.New("audit: disk failure")}))

	req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	w := httptest.NewRecorder()
	h.ListAuditLogs(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// countingQuerier records the query it received.
type countingQuerier struct {
	received audit.Query
	result   *audit.QueryResult
}

func (c *countingQuerier) Query(_ context.Context, q audit.Query) (*audit.QueryResult, error) {
	c.received = q
	return c.result, nil
}

// TestHandlers_ListAuditLogs_ReportsDamagedRecords verifies undecodable
// records are surfaced through the result rather than dropped silently.
func TestHandlers_ListAuditLogs_ReportsDamagedRecords(t *testing.T) {
	querier := &countingQuerier{
		result: &audit.QueryResult{
			Events:    []*audit.AuditEvent{auditTestEvent(0, audit.EventOrderCreated, "actor", audit.ResultSuccess)},
			Total:     1,
			Page:      1,
			PerPage:   25,
			Malformed: 3,
		},
	}

	h := NewHandlers(nil, slog.Default(), WithAuditQuerier(querier))

	req := httptest.NewRequest(http.MethodGet, "/admin/audit?event_type=ORDER_CREATED&actor=actor", nil)
	w := httptest.NewRecorder()
	h.ListAuditLogs(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, audit.EventOrderCreated, querier.received.EventType)
	assert.Equal(t, "actor", querier.received.Actor)
}

// TestWithAuditQuerier_NilOptions verifies option handling is defensive.
func TestWithAlgorithmDiscoverer_NilKeepsDefault(t *testing.T) {
	h := NewHandlers(nil, slog.Default(), WithAlgorithmDiscoverer(nil))
	require.NotNil(t, h.discoverAlgorithms, "nil discoverer must not clear the default")
}

// ==========================================================================
// GetAlgorithms
// ==========================================================================

// getAlgorithms performs a GET against the algorithms endpoint.
func getAlgorithms(t *testing.T, h *Handlers) AlgorithmsResponse {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/admin/algorithms", nil)
	w := httptest.NewRecorder()
	h.GetAlgorithms(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp AlgorithmsResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	return resp
}

// algorithmBackends returns the backends reported for a named algorithm.
func algorithmBackends(algorithms []AlgorithmInfo, name string) []string {
	for _, info := range algorithms {
		if info.Algorithm == name {
			return info.Backends
		}
	}
	return nil
}

// discovererFor builds a discoverer over a fixed backend capability set, the
// same way the xkms service reports its configured backends.
func discovererFor(caps map[string]xkmssdk.Capabilities) AlgorithmDiscoverer {
	backends := make([]xkmssdk.ServiceBackendType, 0, len(caps))
	for name := range caps {
		backends = append(backends, xkmssdk.ServiceBackendType(name))
	}

	return func() *AlgorithmsResponse {
		return xkmssdk.ServiceBuildAlgorithmsResponse(backends, func(name string) (xkmssdk.Capabilities, error) {
			capability, ok := caps[name]
			if !ok {
				return xkmssdk.Capabilities{}, errors.New("backend not configured")
			}
			return capability, nil
		})
	}
}

// TestHandlers_GetAlgorithms_SoftwareOnlyDeployment verifies a software-only
// deployment reports software algorithms and claims nothing else.
func TestHandlers_GetAlgorithms_SoftwareOnlyDeployment(t *testing.T) {
	h := NewHandlers(nil, slog.Default(), WithAlgorithmDiscoverer(discovererFor(
		map[string]xkmssdk.Capabilities{
			"software": {Keys: true},
		})))

	resp := getAlgorithms(t, h)

	assert.Equal(t, []string{"software"}, algorithmBackends(resp.Signing, "ECDSA"))
	assert.Equal(t, []string{"software"}, algorithmBackends(resp.Signing, "RSA"))
	assert.Equal(t, []string{"software"}, algorithmBackends(resp.Signing, "Ed25519"))

	// No hardware backend is configured, so no hardware backend is advertised.
	for _, info := range resp.Signing {
		assert.NotContains(t, info.Backends, "tpm2")
		assert.NotContains(t, info.Backends, "pkcs11")
	}

	// No backend advertises key encapsulation, so none is claimed.
	assert.Empty(t, resp.KeyEncapsulation)
}

// TestHandlers_GetAlgorithms_QuantumProvider verifies a deployment with a
// quantum-capable backend reports the KEM and post-quantum signing algorithms.
func TestHandlers_GetAlgorithms_QuantumProvider(t *testing.T) {
	h := NewHandlers(nil, slog.Default(), WithAlgorithmDiscoverer(discovererFor(
		map[string]xkmssdk.Capabilities{
			"software": {Keys: true},
			"quantum":  {QuantumSigning: true, KeyEncapsulation: true},
		})))

	resp := getAlgorithms(t, h)

	require.NotEmpty(t, resp.KeyEncapsulation)
	assert.Equal(t, []string{"quantum"}, algorithmBackends(resp.KeyEncapsulation, "ML-KEM-1024"))
	assert.Equal(t, []string{"quantum"}, algorithmBackends(resp.Signing, "ML-DSA-65"))
	assert.Equal(t, []string{"quantum"}, algorithmBackends(resp.Signing, "ML-DSA-87"))

	for _, info := range resp.KeyEncapsulation {
		assert.True(t, info.PostQuantum, "key encapsulation algorithms are post-quantum")
	}
}

// TestHandlers_GetAlgorithms_HardwareDeployment verifies configured hardware
// backends are reported alongside software ones.
func TestHandlers_GetAlgorithms_HardwareDeployment(t *testing.T) {
	h := NewHandlers(nil, slog.Default(), WithAlgorithmDiscoverer(discovererFor(
		map[string]xkmssdk.Capabilities{
			"software": {Keys: true},
			"tpm2":     {Keys: true, HardwareBacked: true},
		})))

	resp := getAlgorithms(t, h)

	backends := algorithmBackends(resp.Signing, "ECDSA")
	assert.Contains(t, backends, "software")
	assert.Contains(t, backends, "tpm2")
}

// TestHandlers_GetAlgorithms_NoBackends verifies a deployment with nothing
// configured reports nothing rather than a fabricated software list.
func TestHandlers_GetAlgorithms_NoBackends(t *testing.T) {
	h := NewHandlers(nil, slog.Default(), WithAlgorithmDiscoverer(discovererFor(nil)))

	resp := getAlgorithms(t, h)

	assert.Empty(t, resp.Signing)
	assert.Empty(t, resp.KeyEncapsulation)
}

// TestHandlers_GetAlgorithms_NilResponse verifies a discoverer that returns
// nothing still produces a well-formed response.
func TestHandlers_GetAlgorithms_NilResponse(t *testing.T) {
	h := NewHandlers(nil, slog.Default(), WithAlgorithmDiscoverer(func() *AlgorithmsResponse { return nil }))

	resp := getAlgorithms(t, h)

	assert.NotNil(t, resp.Signing)
	assert.NotNil(t, resp.KeyEncapsulation)
	assert.Empty(t, resp.Signing)
}
