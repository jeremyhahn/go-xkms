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
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileStore implements EnrollmentStore using the filesystem. Each agent
// record is stored as a JSON file named by the agent ID. Thread-safe.
type FileStore struct {
	dir    string
	logger *slog.Logger
	mu     sync.RWMutex
}

// NewFileStore creates a new FileStore at the given directory. The
// directory is created with 0700 permissions if it does not exist.
func NewFileStore(dir string, logger *slog.Logger) (*FileStore, error) {
	if dir == "" {
		return nil, &AgentError{Operation: "new_file_store", Err: ErrStoreDir}
	}
	if logger == nil {
		return nil, ErrNilLogger
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, &AgentError{Operation: "new_file_store", Err: ErrStoreDir}
	}
	return &FileStore{
		dir:    dir,
		logger: logger,
	}, nil
}

// SaveAgent persists an agent record as a JSON file. If an agent with
// the same ID already exists, it is overwritten.
func (s *FileStore) SaveAgent(agent *AgentInfo) error {
	if agent == nil || agent.ID == "" {
		return &AgentError{Operation: "save_agent", Err: ErrAgentNotFound}
	}

	data, err := json.MarshalIndent(agent, "", "  ")
	if err != nil {
		return &AgentError{Operation: "save_agent", Err: ErrStoreMarshal}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.agentPath(agent.ID)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return &AgentError{Operation: "save_agent", Err: ErrStoreWrite}
	}

	s.logger.Debug("saved agent", "id", agent.ID, "path", path)
	return nil
}

// GetAgent retrieves an agent by its ID. Returns ErrAgentNotFound if
// the agent file does not exist.
func (s *FileStore) GetAgent(id string) (*AgentInfo, error) {
	if id == "" {
		return nil, &AgentError{Operation: "get_agent", Err: ErrAgentNotFound}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	path := s.agentPath(id)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrAgentNotFound
		}
		return nil, &AgentError{Operation: "get_agent", Err: ErrStoreRead}
	}

	var agent AgentInfo
	if err := json.Unmarshal(data, &agent); err != nil {
		return nil, &AgentError{Operation: "get_agent", Err: ErrStoreUnmarshal}
	}

	return &agent, nil
}

// ListAgents returns all enrolled agents by reading agent JSON files
// from the store directory.
func (s *FileStore) ListAgents() ([]*AgentInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, &AgentError{Operation: "list_agents", Err: ErrStoreRead}
	}

	agents := make([]*AgentInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(s.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			s.logger.Warn("skipping unreadable agent file",
				"path", path, "error", err)
			continue
		}

		var agent AgentInfo
		if err := json.Unmarshal(data, &agent); err != nil {
			s.logger.Warn("skipping malformed agent file",
				"path", path, "error", err)
			continue
		}

		agents = append(agents, &agent)
	}

	return agents, nil
}

// DeleteAgent removes an agent by its ID. Returns ErrAgentNotFound if
// the agent file does not exist.
func (s *FileStore) DeleteAgent(id string) error {
	if id == "" {
		return &AgentError{Operation: "delete_agent", Err: ErrAgentNotFound}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.agentPath(id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ErrAgentNotFound
	}

	if err := os.Remove(path); err != nil {
		return &AgentError{Operation: "delete_agent", Err: ErrStoreDelete}
	}

	s.logger.Debug("deleted agent", "id", id, "path", path)
	return nil
}

// agentPath returns the filesystem path for an agent record.
func (s *FileStore) agentPath(id string) string {
	// Sanitize the ID to prevent directory traversal.
	safe := filepath.Base(id)
	return filepath.Join(s.dir, safe+".json")
}

// Compile-time interface check.
var _ EnrollmentStore = (*FileStore)(nil)

// MemoryStore implements EnrollmentStore using an in-memory map.
// Useful for testing and short-lived agent sessions.
type MemoryStore struct {
	agents map[string]*AgentInfo
	mu     sync.RWMutex
}

// NewMemoryStore creates a new in-memory enrollment store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		agents: make(map[string]*AgentInfo),
	}
}

// SaveAgent stores an agent record in memory.
func (s *MemoryStore) SaveAgent(agent *AgentInfo) error {
	if agent == nil || agent.ID == "" {
		return &AgentError{Operation: "save_agent", Err: ErrAgentNotFound}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agent.ID] = agent
	return nil
}

// GetAgent retrieves an agent by ID from memory.
func (s *MemoryStore) GetAgent(id string) (*AgentInfo, error) {
	if id == "" {
		return nil, &AgentError{Operation: "get_agent", Err: ErrAgentNotFound}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[id]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return agent, nil
}

// ListAgents returns all agents from memory.
func (s *MemoryStore) ListAgents() ([]*AgentInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*AgentInfo, 0, len(s.agents))
	for _, a := range s.agents {
		result = append(result, a)
	}
	return result, nil
}

// DeleteAgent removes an agent by ID from memory.
func (s *MemoryStore) DeleteAgent(id string) error {
	if id == "" {
		return &AgentError{Operation: "delete_agent", Err: ErrAgentNotFound}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.agents[id]; !ok {
		return ErrAgentNotFound
	}
	delete(s.agents, id)
	return nil
}

// Compile-time interface check.
var _ EnrollmentStore = (*MemoryStore)(nil)
