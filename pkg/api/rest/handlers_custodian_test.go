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

package rest

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
)

// setupCustodianTestHandlers creates a CustodianHandlers backed by an in-memory
// store and mounts the routes on a chi router for testing.
func setupCustodianTestHandlers(t *testing.T) (*CustodianHandlers, *chi.Mux) {
	t.Helper()
	store := custodian.NewMemoryStore()
	svc, err := custodian.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	handlers := NewCustodianHandlers(svc)
	r := chi.NewRouter()
	r.Route("/custodian/groups", func(r chi.Router) {
		r.Post("/", handlers.CreateGroupHandler)
		r.Get("/", handlers.ListGroupsHandler)
		r.Get("/{id}", handlers.GetGroupHandler)
		r.Delete("/{id}", handlers.DeleteGroupHandler)
		r.Post("/{id}/members", handlers.AddMemberHandler)
		r.Delete("/{id}/members/{userID}", handlers.RemoveMemberHandler)
		r.Post("/{id}/distribute", handlers.DistributeSharesHandler)
	})
	return handlers, r
}

// createTestGroup is a helper that creates a group through the router and
// returns the decoded CustodianGroup from the wrapped response body.
func createTestGroup(t *testing.T, router *chi.Mux, id, name, purpose string, threshold, total int) *custodian.CustodianGroup {
	t.Helper()
	body := createCustodianGroupRequest{
		ID:        id,
		Name:      name,
		Purpose:   purpose,
		Threshold: threshold,
		Total:     total,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/custodian/groups", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("createTestGroup: expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
	var resp createCustodianGroupResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp.Group
}

// addTestMember is a helper that adds a member to a group through the router
// and returns the decoded CustodianMember from the wrapped response body.
func addTestMember(t *testing.T, router *chi.Mux, groupID, userID, username, method string) *custodian.CustodianMember {
	t.Helper()
	body := addCustodianMemberRequest{
		UserID:   userID,
		Username: username,
		Method:   method,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/"+groupID+"/members", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("addTestMember: expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
	var resp addCustodianMemberResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp.Member
}

func TestCreateGroupHandler_Success(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	body := createCustodianGroupRequest{
		ID:        "grp-001",
		Name:      "Barrier Custodians",
		Purpose:   custodian.PurposeBarrier,
		Threshold: 3,
		Total:     5,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var resp createCustodianGroupResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	group := resp.Group
	if group.ID != "grp-001" {
		t.Errorf("expected group ID %q, got %q", "grp-001", group.ID)
	}
	if group.Name != "Barrier Custodians" {
		t.Errorf("expected group name %q, got %q", "Barrier Custodians", group.Name)
	}
	if group.Purpose != custodian.PurposeBarrier {
		t.Errorf("expected purpose %q, got %q", custodian.PurposeBarrier, group.Purpose)
	}
	if group.Threshold != 3 {
		t.Errorf("expected threshold 3, got %d", group.Threshold)
	}
	if group.Total != 5 {
		t.Errorf("expected total 5, got %d", group.Total)
	}
	if len(group.Members) != 0 {
		t.Errorf("expected 0 members, got %d", len(group.Members))
	}
	if group.CreatedAt.IsZero() {
		t.Error("expected non-zero created_at")
	}
}

func TestCreateGroupHandler_InvalidRequest(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups", bytes.NewReader([]byte("")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrInvalidRequest.Error() {
		t.Errorf("expected error %q, got %q", ErrInvalidRequest.Error(), errResp.Error)
	}
}

func TestCreateGroupHandler_MissingName(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	body := createCustodianGroupRequest{
		ID:        "grp-no-name",
		Purpose:   custodian.PurposeBarrier,
		Threshold: 2,
		Total:     3,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrMissingGroupName.Error() {
		t.Errorf("expected error %q, got %q", ErrMissingGroupName.Error(), errResp.Error)
	}
}

func TestCreateGroupHandler_InvalidThreshold(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	body := createCustodianGroupRequest{
		ID:        "grp-bad-thresh",
		Name:      "Bad Threshold",
		Purpose:   custodian.PurposeBarrier,
		Threshold: 0,
		Total:     3,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrInvalidThreshold.Error() {
		t.Errorf("expected error %q, got %q", ErrInvalidThreshold.Error(), errResp.Error)
	}
}

func TestCreateGroupHandler_InvalidTotal(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	body := createCustodianGroupRequest{
		ID:        "grp-bad-total",
		Name:      "Bad Total",
		Purpose:   custodian.PurposeBarrier,
		Threshold: 5,
		Total:     3,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrInvalidTotal.Error() {
		t.Errorf("expected error %q, got %q", ErrInvalidTotal.Error(), errResp.Error)
	}
}

func TestCreateGroupHandler_MissingPurpose(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	// The handler does not check purpose, but the domain Validate does.
	// threshold=1 passes handler check (1 < 1 is false) but not Validate (1 < 2).
	// Use threshold=2 so handler passes, but empty purpose triggers domain error.
	body := createCustodianGroupRequest{
		ID:        "grp-no-purpose",
		Name:      "No Purpose",
		Threshold: 2,
		Total:     3,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != custodian.ErrInvalidPurpose.Error() {
		t.Errorf("expected error %q, got %q", custodian.ErrInvalidPurpose.Error(), errResp.Error)
	}
}

func TestCreateGroupHandler_DuplicateGroup(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	createTestGroup(t, router, "grp-dup", "First", custodian.PurposeBarrier, 2, 3)

	// Attempt to create the same group ID again.
	body := createCustodianGroupRequest{
		ID:        "grp-dup",
		Name:      "Second",
		Purpose:   custodian.PurposeBarrier,
		Threshold: 2,
		Total:     3,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d: %s", http.StatusConflict, rr.Code, rr.Body.String())
	}
}

func TestListGroupsHandler_Empty(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/custodian/groups", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp listCustodianGroupsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(resp.Groups))
	}
}

func TestListGroupsHandler_WithGroups(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	createTestGroup(t, router, "grp-list-1", "Group One", custodian.PurposeBarrier, 2, 3)
	createTestGroup(t, router, "grp-list-2", "Group Two", custodian.PurposeBackup, 3, 5)

	req := httptest.NewRequest(http.MethodGet, "/custodian/groups", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp listCustodianGroupsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(resp.Groups))
	}
}

func TestGetGroupHandler_Success(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	created := createTestGroup(t, router, "grp-get-ok", "Get Me", custodian.PurposeSigningKey, 2, 4)

	req := httptest.NewRequest(http.MethodGet, "/custodian/groups/"+created.ID, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp getCustodianGroupResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	group := resp.Group
	if group.ID != created.ID {
		t.Errorf("expected group ID %q, got %q", created.ID, group.ID)
	}
	if group.Name != "Get Me" {
		t.Errorf("expected group name %q, got %q", "Get Me", group.Name)
	}
	if group.Threshold != 2 {
		t.Errorf("expected threshold 2, got %d", group.Threshold)
	}
	if group.Total != 4 {
		t.Errorf("expected total 4, got %d", group.Total)
	}
}

func TestGetGroupHandler_NotFound(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/custodian/groups/nonexistent-id", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != custodian.ErrGroupNotFound.Error() {
		t.Errorf("expected error %q, got %q", custodian.ErrGroupNotFound.Error(), errResp.Error)
	}
}

func TestDeleteGroupHandler_Success(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	created := createTestGroup(t, router, "grp-del-ok", "Delete Me", custodian.PurposeBarrier, 2, 3)

	req := httptest.NewRequest(http.MethodDelete, "/custodian/groups/"+created.ID, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNoContent, rr.Code, rr.Body.String())
	}

	// Verify the group is no longer retrievable.
	getReq := httptest.NewRequest(http.MethodGet, "/custodian/groups/"+created.ID, nil)
	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusNotFound {
		t.Fatalf("expected GET after delete to return %d, got %d", http.StatusNotFound, getRR.Code)
	}
}

func TestDeleteGroupHandler_NotFound(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/custodian/groups/nonexistent-id", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

func TestAddMemberHandler_Success(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	group := createTestGroup(t, router, "grp-add-member", "Members Group", custodian.PurposeBarrier, 2, 3)

	body := addCustodianMemberRequest{
		UserID:   "user-001",
		Username: "alice",
		Method:   custodian.MethodFIDO2,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/"+group.ID+"/members", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var resp addCustodianMemberResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	member := resp.Member
	if member.UserID != "user-001" {
		t.Errorf("expected user_id %q, got %q", "user-001", member.UserID)
	}
	if member.Username != "alice" {
		t.Errorf("expected username %q, got %q", "alice", member.Username)
	}
	if member.Method != custodian.MethodFIDO2 {
		t.Errorf("expected method %q, got %q", custodian.MethodFIDO2, member.Method)
	}
	if member.ShareIndex != 1 {
		t.Errorf("expected share_index 1, got %d", member.ShareIndex)
	}
	if member.AssignedAt.IsZero() {
		t.Error("expected non-zero assigned_at")
	}

	// Verify the group now shows the member.
	getReq := httptest.NewRequest(http.MethodGet, "/custodian/groups/"+group.ID, nil)
	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	var getResp getCustodianGroupResponse
	if err := json.NewDecoder(getRR.Body).Decode(&getResp); err != nil {
		t.Fatal(err)
	}
	if len(getResp.Group.Members) != 1 {
		t.Errorf("expected 1 member after add, got %d", len(getResp.Group.Members))
	}
}

func TestAddMemberHandler_MissingUserID(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	group := createTestGroup(t, router, "grp-add-no-uid", "No UID Group", custodian.PurposeBarrier, 2, 3)

	body := addCustodianMemberRequest{
		Username: "bob",
		Method:   custodian.MethodManual,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/"+group.ID+"/members", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrMissingUserID.Error() {
		t.Errorf("expected error %q, got %q", ErrMissingUserID.Error(), errResp.Error)
	}
}

func TestAddMemberHandler_GroupNotFound(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	body := addCustodianMemberRequest{
		UserID:   "user-orphan",
		Username: "charlie",
		Method:   custodian.MethodPKCS11,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/no-such-group/members", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

func TestAddMemberHandler_InvalidBody(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	group := createTestGroup(t, router, "grp-add-bad-body", "Bad Body", custodian.PurposeBarrier, 2, 3)

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/"+group.ID+"/members", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestAddMemberHandler_DuplicateMember(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	group := createTestGroup(t, router, "grp-dup-member", "Dup Member", custodian.PurposeBarrier, 2, 3)
	addTestMember(t, router, group.ID, "user-dup", "alice", custodian.MethodFIDO2)

	// Attempt to add the same user again.
	body := addCustodianMemberRequest{
		UserID:   "user-dup",
		Username: "alice",
		Method:   custodian.MethodFIDO2,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/"+group.ID+"/members", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d: %s", http.StatusConflict, rr.Code, rr.Body.String())
	}
}

func TestAddMemberHandler_GroupFull(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	// Create a 2-of-2 group so it is full after 2 members.
	group := createTestGroup(t, router, "grp-full", "Full Group", custodian.PurposeBarrier, 2, 2)
	addTestMember(t, router, group.ID, "user-a", "alice", custodian.MethodFIDO2)
	addTestMember(t, router, group.ID, "user-b", "bob", custodian.MethodPKCS11)

	// Third member should be rejected.
	body := addCustodianMemberRequest{
		UserID:   "user-c",
		Username: "charlie",
		Method:   custodian.MethodManual,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/"+group.ID+"/members", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d: %s", http.StatusConflict, rr.Code, rr.Body.String())
	}
}

func TestRemoveMemberHandler_Success(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	group := createTestGroup(t, router, "grp-remove-ok", "Remove Group", custodian.PurposeBarrier, 2, 3)
	addTestMember(t, router, group.ID, "user-rm", "removable", custodian.MethodManual)

	req := httptest.NewRequest(http.MethodDelete, "/custodian/groups/"+group.ID+"/members/user-rm", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNoContent, rr.Code, rr.Body.String())
	}

	// Verify the member is gone.
	getReq := httptest.NewRequest(http.MethodGet, "/custodian/groups/"+group.ID, nil)
	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	var resp getCustodianGroupResponse
	if err := json.NewDecoder(getRR.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Group.Members) != 0 {
		t.Errorf("expected 0 members after remove, got %d", len(resp.Group.Members))
	}
}

func TestRemoveMemberHandler_NotFound(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	group := createTestGroup(t, router, "grp-remove-nf", "Remove NF", custodian.PurposeBarrier, 2, 3)

	req := httptest.NewRequest(http.MethodDelete, "/custodian/groups/"+group.ID+"/members/nonexistent-user", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

func TestRemoveMemberHandler_GroupNotFound(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/custodian/groups/no-such-group/members/user-x", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

func TestCustodianHandlers_NilService(t *testing.T) {
	handlers := NewCustodianHandlers(nil)
	r := chi.NewRouter()
	r.Route("/custodian/groups", func(r chi.Router) {
		r.Post("/", handlers.CreateGroupHandler)
		r.Get("/", handlers.ListGroupsHandler)
		r.Get("/{id}", handlers.GetGroupHandler)
		r.Delete("/{id}", handlers.DeleteGroupHandler)
		r.Post("/{id}/members", handlers.AddMemberHandler)
		r.Delete("/{id}/members/{userID}", handlers.RemoveMemberHandler)
		r.Post("/{id}/distribute", handlers.DistributeSharesHandler)
	})

	tests := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{
			name:   "CreateGroup",
			method: http.MethodPost,
			path:   "/custodian/groups",
			body:   []byte(`{"name":"test","threshold":2,"total":3}`),
		},
		{
			name:   "ListGroups",
			method: http.MethodGet,
			path:   "/custodian/groups",
		},
		{
			name:   "GetGroup",
			method: http.MethodGet,
			path:   "/custodian/groups/some-id",
		},
		{
			name:   "DeleteGroup",
			method: http.MethodDelete,
			path:   "/custodian/groups/some-id",
		},
		{
			name:   "AddMember",
			method: http.MethodPost,
			path:   "/custodian/groups/some-id/members",
			body:   []byte(`{"user_id":"u1"}`),
		},
		{
			name:   "RemoveMember",
			method: http.MethodDelete,
			path:   "/custodian/groups/some-id/members/user-1",
		},
		{
			name:   "DistributeShares",
			method: http.MethodPost,
			path:   "/custodian/groups/some-id/distribute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != nil {
				req = httptest.NewRequest(tt.method, tt.path, bytes.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, tt.path, nil)
			}
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
			}

			var errResp ErrorResponse
			if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
				t.Fatal(err)
			}
			if errResp.Error != ErrCustodianNotConfigured.Error() {
				t.Errorf("expected error %q, got %q", ErrCustodianNotConfigured.Error(), errResp.Error)
			}
		})
	}
}

func TestHandleCustodianError_MapsAllErrorTypes(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "GroupNotFound",
			err:            custodian.ErrGroupNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "GroupAlreadyExists",
			err:            custodian.ErrGroupAlreadyExists,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "GroupFull",
			err:            custodian.ErrGroupFull,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "MemberAlreadyExists",
			err:            custodian.ErrMemberAlreadyExists,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "MemberNotFound",
			err:            custodian.ErrMemberNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "EmptyGroupID",
			err:            custodian.ErrEmptyGroupID,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "EmptyGroupName",
			err:            custodian.ErrEmptyGroupName,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "EmptyUserID",
			err:            custodian.ErrEmptyUserID,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidThreshold",
			err:            custodian.ErrInvalidThreshold,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidTotalShares",
			err:            custodian.ErrInvalidTotalShares,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidPurpose",
			err:            custodian.ErrInvalidPurpose,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "GroupEmpty",
			err:            custodian.ErrGroupEmpty,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "UnknownError",
			err:            errors.New("something unexpected"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			handleCustodianError(rr, tt.err)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestDistributeSharesHandler_Success(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	group := createTestGroup(t, router, "grp-dist", "Distribute Group", custodian.PurposeBarrier, 2, 3)
	addTestMember(t, router, group.ID, "user-a", "alice", custodian.MethodFIDO2)
	addTestMember(t, router, group.ID, "user-b", "bob", custodian.MethodManual)

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/"+group.ID+"/distribute", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp distributeSharesResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Distributed != 2 {
		t.Errorf("expected distributed 2, got %d", resp.Distributed)
	}
}

func TestDistributeSharesHandler_GroupNotFound(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/nonexistent/distribute", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != custodian.ErrGroupNotFound.Error() {
		t.Errorf("expected error %q, got %q", custodian.ErrGroupNotFound.Error(), errResp.Error)
	}
}

func TestDistributeSharesHandler_EmptyGroup(t *testing.T) {
	_, router := setupCustodianTestHandlers(t)

	createTestGroup(t, router, "grp-empty-dist", "Empty Group", custodian.PurposeBarrier, 2, 3)

	req := httptest.NewRequest(http.MethodPost, "/custodian/groups/grp-empty-dist/distribute", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != custodian.ErrGroupEmpty.Error() {
		t.Errorf("expected error %q, got %q", custodian.ErrGroupEmpty.Error(), errResp.Error)
	}
}
