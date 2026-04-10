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

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// DAOStore errors.
var (
	// ErrNilKVStore is returned when a nil KVStore is provided.
	ErrNilKVStore = errors.New("agent: kvstore is required")

	// ErrDAOCreation is returned when the DAO cannot be created.
	ErrDAOCreation = errors.New("agent: failed to create DAO")
)

// DAOStore implements EnrollmentStore using a go-qrdb GenericDAO for
// persistent storage. It stores AgentEntity records and converts
// between AgentEntity and AgentInfo domain types. Thread-safe via
// the underlying DAO implementation.
type DAOStore struct {
	dao dao.GenericDAO[*AgentEntity]
}

// Compile-time interface check.
var _ EnrollmentStore = (*DAOStore)(nil)

// NewDAOStore creates a new DAOStore backed by the given KVStore.
// The DAO uses the "agents" entity type namespace and registers the
// DeviceID unique index for efficient lookups.
func NewDAOStore(kvStore kvstore.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore
	}

	agentDAO, err := dao.New[*AgentEntity](
		kvStore,
		"agents",
		func() *AgentEntity { return &AgentEntity{} },
	)
	if err != nil {
		return nil, &AgentError{Operation: "new_dao_store", Err: ErrDAOCreation}
	}

	return &DAOStore{dao: agentDAO}, nil
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
		return &AgentError{Operation: "save_agent", Err: ErrStoreWrite}
	}

	entity := AgentEntityFromInfo(agent)
	if existing != nil {
		// Preserve the existing entity ID for update.
		entity.ID = existing.ID
	}

	if err := s.dao.Save(ctx, entity); err != nil {
		return &AgentError{Operation: "save_agent", Err: ErrStoreWrite}
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

	result, err := s.dao.Page(ctx, dao.PageQuery{
		Page:     1,
		PageSize: 10000,
	})
	if err != nil {
		return nil, &AgentError{Operation: "list_agents", Err: ErrStoreRead}
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

	if err := s.dao.Delete(ctx, entity); err != nil {
		return &AgentError{Operation: "delete_agent", Err: ErrStoreDelete}
	}

	return nil
}

// Page returns a paginated result set of agent entities.
func (s *DAOStore) Page(ctx context.Context, q dao.PageQuery) (dao.PageResult[*AgentEntity], error) {
	return s.dao.Page(ctx, q)
}

// findByDeviceID locates an agent entity by its DeviceID field.
// It first attempts an index-based lookup. If the index returns no
// results (e.g., the KVStore does not support secondary indexes),
// it falls back to a full scan.
func (s *DAOStore) findByDeviceID(ctx context.Context, deviceID string) (*AgentEntity, error) {
	// Attempt index-based lookup first.
	entity, err := s.dao.QueryOneByIndex(ctx, "DeviceID", deviceID)
	if err == nil {
		return entity, nil
	}

	// If the error is not "not found", it may be an index miss from a
	// KVStore that doesn't support indexes. Fall back to scan.
	if !dao.IsNotFound(err) {
		// Unexpected error from index query; still try scan fallback.
	}

	// Scan fallback: iterate all entities and match by DeviceID.
	result, scanErr := s.dao.Page(ctx, dao.PageQuery{
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
