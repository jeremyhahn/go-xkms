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

package agent

import (
	"context"
	"errors"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// DAOStore errors.
var (
	// ErrNilKVStore is returned when a nil KVStore is provided.
	ErrNilKVStore = errors.New("agent: kvstore is required")

	// ErrDAOCreation is returned when the DAO cannot be created.
	ErrDAOCreation = errors.New("agent: failed to create DAO")
)

// DAOStore implements EnrollmentStore using go-qrdb GenericDAOs for
// persistent storage: agent records, one-time codes, and pending
// enrollment requests each get their own entity type namespace ("agents",
// "codes", "pending"), converting to and from their respective domain
// types. Thread-safe via the underlying DAO implementation.
//
// ConsumeCode is not atomic here the way FileStore's is: the underlying
// GenericDAO exposes no compare-and-delete or transactional primitive, so
// this implementation does a Get followed by a Delete, the same
// check-then-act pattern SaveAgent already uses for its existence check.
// A DAOStore is the backend for the clustered/embedded qrdb deployment,
// not the default CLI/GUI path (FileStore); closing this gap needs a
// primitive from go-qrdb's SDK that does not exist yet.
type DAOStore struct {
	agentDAO   qrdbsdk.GenericDAO[*AgentEntity]
	codeDAO    qrdbsdk.GenericDAO[*CodeEntity]
	pendingDAO qrdbsdk.GenericDAO[*PendingEntity]
}

// Compile-time interface check.
var _ EnrollmentStore = (*DAOStore)(nil)

// NewDAOStore creates a new DAOStore backed by the given KVStore. Each
// record type gets its own DAO namespace ("agents", "codes", "pending")
// with its unique index registered for efficient lookups.
func NewDAOStore(kvStore qrdbsdk.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore
	}

	agentDAO, err := qrdbsdk.NewDAO[*AgentEntity](
		kvStore,
		"agents",
		func() *AgentEntity { return &AgentEntity{} },
	)
	if err != nil {
		return nil, &AgentError{Operation: "new_dao_store", Err: ErrDAOCreation, Cause: err}
	}

	codeDAO, err := qrdbsdk.NewDAO[*CodeEntity](
		kvStore,
		"codes",
		func() *CodeEntity { return &CodeEntity{} },
	)
	if err != nil {
		return nil, &AgentError{Operation: "new_dao_store", Err: ErrDAOCreation, Cause: err}
	}

	pendingDAO, err := qrdbsdk.NewDAO[*PendingEntity](
		kvStore,
		"pending",
		func() *PendingEntity { return &PendingEntity{} },
	)
	if err != nil {
		return nil, &AgentError{Operation: "new_dao_store", Err: ErrDAOCreation, Cause: err}
	}

	return &DAOStore{agentDAO: agentDAO, codeDAO: codeDAO, pendingDAO: pendingDAO}, nil
}

// SaveAgent persists an agent record. If an agent with the same
// DeviceID already exists, it is updated. The DeviceID from
// AgentInfo.ID is used as the lookup key.
func (s *DAOStore) SaveAgent(agent *AgentInfo) error {
	if agent == nil || agent.ID == "" {
		return &AgentError{Operation: "save_agent", Err: ErrAgentNotFound}
	}

	ctx := context.Background()

	// Check if an entity with this DeviceID already exists.
	existing, err := s.findByDeviceID(ctx, agent.ID)
	if err != nil && !errors.Is(err, ErrAgentNotFound) {
		return &AgentError{Operation: "save_agent", Err: ErrStoreWrite, Cause: err}
	}

	entity := AgentEntityFromInfo(agent)
	if existing != nil {
		// Preserve the existing entity ID for update.
		entity.ID = existing.ID
	}

	if err := s.agentDAO.Save(ctx, entity); err != nil {
		return &AgentError{Operation: "save_agent", Err: ErrStoreWrite, Cause: err}
	}

	return nil
}

// GetAgent retrieves an agent by its DeviceID. Returns ErrAgentNotFound
// if the agent does not exist.
func (s *DAOStore) GetAgent(id string) (*AgentInfo, error) {
	if id == "" {
		return nil, &AgentError{Operation: "get_agent", Err: ErrAgentNotFound}
	}

	ctx := context.Background()
	entity, err := s.findByDeviceID(ctx, id)
	if err != nil {
		return nil, err
	}

	return entity.ToAgentInfo(), nil
}

// ListAgents returns all enrolled agents.
func (s *DAOStore) ListAgents() ([]*AgentInfo, error) {
	ctx := context.Background()

	result, err := s.agentDAO.Page(ctx, qrdbsdk.PageQuery{
		Page:     1,
		PageSize: 10000,
	})
	if err != nil {
		return nil, &AgentError{Operation: "list_agents", Err: ErrStoreRead, Cause: err}
	}

	agents := make([]*AgentInfo, 0, len(result.Entities))
	for _, entity := range result.Entities {
		agents = append(agents, entity.ToAgentInfo())
	}

	return agents, nil
}

// DeleteAgent removes an agent by its DeviceID. Returns ErrAgentNotFound
// if the agent does not exist.
func (s *DAOStore) DeleteAgent(id string) error {
	if id == "" {
		return &AgentError{Operation: "delete_agent", Err: ErrAgentNotFound}
	}

	ctx := context.Background()
	entity, err := s.findByDeviceID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.agentDAO.Delete(ctx, entity); err != nil {
		return &AgentError{Operation: "delete_agent", Err: ErrStoreDelete, Cause: err}
	}

	return nil
}

// SaveCode persists a one-time enrollment code by its hash. If a code
// with the same hash already exists, it is updated.
func (s *DAOStore) SaveCode(hash string, expiresAt time.Time) error {
	if hash == "" {
		return &AgentError{Operation: "save_code", Err: ErrEnrollmentCodeInvalid}
	}

	ctx := context.Background()

	existing, err := s.findCodeByHash(ctx, hash)
	if err != nil && !errors.Is(err, ErrEnrollmentCodeInvalid) {
		return &AgentError{Operation: "save_code", Err: ErrStoreWrite, Cause: err}
	}

	entity := &CodeEntity{Hash: hash, ExpiresAt: expiresAt}
	if existing != nil {
		entity.ID = existing.ID
	}

	if err := s.codeDAO.Save(ctx, entity); err != nil {
		return &AgentError{Operation: "save_code", Err: ErrStoreWrite, Cause: err}
	}
	return nil
}

// ConsumeCode validates and single-use-consumes the code identified by
// hash. This is a Get followed by a Delete, not an atomic
// compare-and-delete - see DAOStore's doc comment.
func (s *DAOStore) ConsumeCode(hash string) error {
	if hash == "" {
		return ErrEnrollmentCodeInvalid
	}

	ctx := context.Background()
	entity, err := s.findCodeByHash(ctx, hash)
	if err != nil {
		return err
	}

	if err := s.codeDAO.Delete(ctx, entity); err != nil {
		return &AgentError{Operation: "consume_code", Err: ErrStoreDelete, Cause: err}
	}

	if time.Now().After(entity.ExpiresAt) {
		return ErrEnrollmentCodeExpired
	}
	return nil
}

// CleanExpiredCodes removes every expired code entity and reports how
// many were removed.
func (s *DAOStore) CleanExpiredCodes() (int, error) {
	ctx := context.Background()

	result, err := s.codeDAO.Page(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 10000})
	if err != nil {
		return 0, &AgentError{Operation: "clean_expired_codes", Err: ErrStoreRead, Cause: err}
	}

	now := time.Now()
	removed := 0
	for _, entity := range result.Entities {
		if now.After(entity.ExpiresAt) {
			if err := s.codeDAO.Delete(ctx, entity); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}

// SavePending persists a pending enrollment request. If a request with
// the same ID already exists, it is updated.
func (s *DAOStore) SavePending(p *PendingEnrollment) error {
	if p == nil || p.ID == "" {
		return &AgentError{Operation: "save_pending", Err: ErrRequestNotFound}
	}

	ctx := context.Background()

	existing, err := s.findPendingByRequestID(ctx, p.ID)
	if err != nil && !errors.Is(err, ErrRequestNotFound) {
		return &AgentError{Operation: "save_pending", Err: ErrStoreWrite, Cause: err}
	}

	entity := PendingEntityFromDomain(p)
	if existing != nil {
		entity.ID = existing.ID
	}

	if err := s.pendingDAO.Save(ctx, entity); err != nil {
		return &AgentError{Operation: "save_pending", Err: ErrStoreWrite, Cause: err}
	}
	return nil
}

// GetPending retrieves a pending enrollment request by its ID. Returns
// ErrRequestNotFound if it does not exist.
func (s *DAOStore) GetPending(id string) (*PendingEnrollment, error) {
	if id == "" {
		return nil, &AgentError{Operation: "get_pending", Err: ErrRequestNotFound}
	}

	ctx := context.Background()
	entity, err := s.findPendingByRequestID(ctx, id)
	if err != nil {
		return nil, err
	}
	return entity.ToPendingEnrollment(), nil
}

// ListPending returns every persisted pending enrollment request.
func (s *DAOStore) ListPending() ([]*PendingEnrollment, error) {
	ctx := context.Background()

	result, err := s.pendingDAO.Page(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 10000})
	if err != nil {
		return nil, &AgentError{Operation: "list_pending", Err: ErrStoreRead, Cause: err}
	}

	pending := make([]*PendingEnrollment, 0, len(result.Entities))
	for _, entity := range result.Entities {
		pending = append(pending, entity.ToPendingEnrollment())
	}
	return pending, nil
}

// DeletePending removes a pending enrollment request by its ID. Returns
// ErrRequestNotFound if it does not exist.
func (s *DAOStore) DeletePending(id string) error {
	if id == "" {
		return &AgentError{Operation: "delete_pending", Err: ErrRequestNotFound}
	}

	ctx := context.Background()
	entity, err := s.findPendingByRequestID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.pendingDAO.Delete(ctx, entity); err != nil {
		return &AgentError{Operation: "delete_pending", Err: ErrStoreDelete, Cause: err}
	}
	return nil
}

// Page returns a paginated result set of agent entities.
func (s *DAOStore) Page(ctx context.Context, q qrdbsdk.PageQuery) (qrdbsdk.PageResult[*AgentEntity], error) {
	return s.agentDAO.Page(ctx, q)
}

// findByDeviceID locates an agent entity by its DeviceID field.
// It first attempts an index-based lookup. If the index returns no
// results (e.g., the KVStore does not support secondary indexes),
// it falls back to a full scan.
func (s *DAOStore) findByDeviceID(ctx context.Context, deviceID string) (*AgentEntity, error) {
	// Attempt index-based lookup first.
	entity, err := s.agentDAO.QueryOneByIndex(ctx, "DeviceID", deviceID)
	if err == nil {
		return entity, nil
	}

	// On any error (index miss from a KVStore that does not support indexes,
	// or an unexpected query error), fall back to a full scan.

	// Scan fallback: iterate all entities and match by DeviceID.
	result, scanErr := s.agentDAO.Page(ctx, qrdbsdk.PageQuery{
		Page:     1,
		PageSize: 10000,
	})
	if scanErr != nil {
		return nil, ErrAgentNotFound
	}

	for _, e := range result.Entities {
		if e.DeviceID == deviceID {
			return e, nil
		}
	}

	return nil, ErrAgentNotFound
}

// findCodeByHash locates a code entity by its Hash field, following the
// same index-lookup-with-scan-fallback pattern as findByDeviceID.
func (s *DAOStore) findCodeByHash(ctx context.Context, hash string) (*CodeEntity, error) {
	entity, err := s.codeDAO.QueryOneByIndex(ctx, "Hash", hash)
	if err == nil {
		return entity, nil
	}

	result, scanErr := s.codeDAO.Page(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 10000})
	if scanErr != nil {
		return nil, ErrEnrollmentCodeInvalid
	}
	for _, e := range result.Entities {
		if e.Hash == hash {
			return e, nil
		}
	}
	return nil, ErrEnrollmentCodeInvalid
}

// findPendingByRequestID locates a pending entity by its RequestID field,
// following the same index-lookup-with-scan-fallback pattern as
// findByDeviceID.
func (s *DAOStore) findPendingByRequestID(ctx context.Context, requestID string) (*PendingEntity, error) {
	entity, err := s.pendingDAO.QueryOneByIndex(ctx, "RequestID", requestID)
	if err == nil {
		return entity, nil
	}

	result, scanErr := s.pendingDAO.Page(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 10000})
	if scanErr != nil {
		return nil, ErrRequestNotFound
	}
	for _, e := range result.Entities {
		if e.RequestID == requestID {
			return e, nil
		}
	}
	return nil, ErrRequestNotFound
}
