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
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
)

// FileStore implements EnrollmentStore using the filesystem. Agent
// records, one-time codes, and pending enrollment requests each live as
// JSON files under their own subdirectory of dir (agents/, codes/,
// pending/), keyed by agent ID, code hash, or request ID respectively.
// Separate subdirectories keep ListAgents from ever having to skip a code
// or pending-request file it cannot parse as an AgentInfo. Thread-safe,
// and safe across separate processes sharing the same dir: ConsumeCode's
// single-use guarantee rests on the filesystem's atomic unlink, not on
// this type's in-process mutex.
type FileStore struct {
	dir    string
	logger *slog.Logger
	mu     sync.RWMutex
}

// fileStoreSubdirs are the record-type subdirectories FileStore manages
// under its base directory.
var fileStoreSubdirs = []string{"agents", "codes", "pending"}

// NewFileStore creates a new FileStore at the given directory. The
// directory and its agents/, codes/, and pending/ subdirectories are
// created with 0700 permissions if they do not exist.
func NewFileStore(dir string, logger *slog.Logger) (*FileStore, error) {
	if dir == "" {
		return nil, &AgentError{Operation: "new_file_store", Err: ErrStoreDir}
	}
	if logger == nil {
		return nil, ErrNilLogger
	}
	for _, sub := range fileStoreSubdirs {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
			return nil, &AgentError{Operation: "new_file_store", Err: ErrStoreDir, Cause: err}
		}
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
		return &AgentError{Operation: "save_agent", Err: ErrStoreMarshal, Cause: err}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.agentPath(agent.ID)
	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return &AgentError{Operation: "save_agent", Err: ErrStoreWrite, Cause: err}
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
// from the agents/ subdirectory.
func (s *FileStore) ListAgents() ([]*AgentInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.agentsDir())
	if err != nil {
		return nil, &AgentError{Operation: "list_agents", Err: ErrStoreRead, Cause: err}
	}

	agents := make([]*AgentInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(s.agentsDir(), entry.Name())
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

// codeFile is the on-disk representation of a one-time enrollment code.
// Only the code's hash is ever written here; the plaintext code value
// never reaches the store.
type codeFile struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// SaveCode persists a one-time enrollment code by its hash.
func (s *FileStore) SaveCode(hash string, expiresAt time.Time) error {
	if hash == "" {
		return &AgentError{Operation: "save_code", Err: ErrEnrollmentCodeInvalid}
	}

	data, err := json.Marshal(&codeFile{ExpiresAt: expiresAt})
	if err != nil {
		return &AgentError{Operation: "save_code", Err: ErrStoreMarshal, Cause: err}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := fsutil.WriteFileAtomic(s.codePath(hash), data, 0600); err != nil {
		return &AgentError{Operation: "save_code", Err: ErrStoreWrite, Cause: err}
	}
	return nil
}

// ConsumeCode atomically validates and single-use-consumes the code
// identified by hash. Removing the file is the one step that decides
// which caller - in this process or another sharing dir - wins a race to
// consume the same hash: os.Remove succeeds for exactly one caller: every
// other caller's Remove (or, for a caller that loses the race to Stat the
// file first, its ReadFile) observes the file already gone and reports
// ErrEnrollmentCodeInvalid, indistinguishable from the code never having
// existed. The in-process mutex serializes calls within one FileStore
// instance for consistency with every other method here, but the
// cross-process guarantee rests entirely on the filesystem's atomic
// unlink, not on this lock.
func (s *FileStore) ConsumeCode(hash string) error {
	if hash == "" {
		return ErrEnrollmentCodeInvalid
	}
	path := s.codePath(hash)

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrEnrollmentCodeInvalid
		}
		return &AgentError{Operation: "consume_code", Err: ErrStoreRead, Cause: err}
	}

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrEnrollmentCodeInvalid
		}
		return &AgentError{Operation: "consume_code", Err: ErrStoreDelete, Cause: err}
	}

	var record codeFile
	if err := json.Unmarshal(data, &record); err != nil {
		return &AgentError{Operation: "consume_code", Err: ErrStoreUnmarshal, Cause: err}
	}
	if time.Now().After(record.ExpiresAt) {
		return ErrEnrollmentCodeExpired
	}
	return nil
}

// CleanExpiredCodes removes every expired code file from the codes/
// subdirectory and reports how many were removed. Unreadable or
// malformed entries are skipped, matching ListAgents' tolerance for a
// damaged individual record.
func (s *FileStore) CleanExpiredCodes() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.codesDir())
	if err != nil {
		return 0, &AgentError{Operation: "clean_expired_codes", Err: ErrStoreRead, Cause: err}
	}

	now := time.Now()
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.codesDir(), entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var record codeFile
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}
		if now.After(record.ExpiresAt) {
			if err := os.Remove(path); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}

// SavePending persists a pending enrollment request as a JSON file. If a
// request with the same ID already exists, it is overwritten.
func (s *FileStore) SavePending(p *PendingEnrollment) error {
	if p == nil || p.ID == "" {
		return &AgentError{Operation: "save_pending", Err: ErrRequestNotFound}
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return &AgentError{Operation: "save_pending", Err: ErrStoreMarshal, Cause: err}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := fsutil.WriteFileAtomic(s.pendingPath(p.ID), data, 0600); err != nil {
		return &AgentError{Operation: "save_pending", Err: ErrStoreWrite, Cause: err}
	}
	return nil
}

// GetPending retrieves a pending enrollment request by its ID. Returns
// ErrRequestNotFound if it does not exist.
func (s *FileStore) GetPending(id string) (*PendingEnrollment, error) {
	if id == "" {
		return nil, &AgentError{Operation: "get_pending", Err: ErrRequestNotFound}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.pendingPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrRequestNotFound
		}
		return nil, &AgentError{Operation: "get_pending", Err: ErrStoreRead, Cause: err}
	}

	var p PendingEnrollment
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, &AgentError{Operation: "get_pending", Err: ErrStoreUnmarshal, Cause: err}
	}
	return &p, nil
}

// ListPending returns every persisted pending enrollment request.
func (s *FileStore) ListPending() ([]*PendingEnrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.pendingDir())
	if err != nil {
		return nil, &AgentError{Operation: "list_pending", Err: ErrStoreRead, Cause: err}
	}

	result := make([]*PendingEnrollment, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.pendingDir(), entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			s.logger.Warn("skipping unreadable pending request file",
				"path", path, "error", err)
			continue
		}
		var p PendingEnrollment
		if err := json.Unmarshal(data, &p); err != nil {
			s.logger.Warn("skipping malformed pending request file",
				"path", path, "error", err)
			continue
		}
		result = append(result, &p)
	}
	return result, nil
}

// DeletePending removes a pending enrollment request by its ID. Returns
// ErrRequestNotFound if it does not exist.
func (s *FileStore) DeletePending(id string) error {
	if id == "" {
		return &AgentError{Operation: "delete_pending", Err: ErrRequestNotFound}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.pendingPath(id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ErrRequestNotFound
	}
	if err := os.Remove(path); err != nil {
		return &AgentError{Operation: "delete_pending", Err: ErrStoreDelete, Cause: err}
	}
	return nil
}

// agentsDir, codesDir, and pendingDir return the record-type
// subdirectories under the store's base directory.
func (s *FileStore) agentsDir() string  { return filepath.Join(s.dir, "agents") }
func (s *FileStore) codesDir() string   { return filepath.Join(s.dir, "codes") }
func (s *FileStore) pendingDir() string { return filepath.Join(s.dir, "pending") }

// agentPath returns the filesystem path for an agent record.
func (s *FileStore) agentPath(id string) string {
	// Sanitize the ID to prevent directory traversal.
	safe := filepath.Base(id)
	return filepath.Join(s.agentsDir(), safe+".json")
}

// codePath returns the filesystem path for a one-time code record.
func (s *FileStore) codePath(hash string) string {
	safe := filepath.Base(hash)
	return filepath.Join(s.codesDir(), safe+".json")
}

// pendingPath returns the filesystem path for a pending request record.
func (s *FileStore) pendingPath(id string) string {
	safe := filepath.Base(id)
	return filepath.Join(s.pendingDir(), safe+".json")
}

// Compile-time interface check.
var _ EnrollmentStore = (*FileStore)(nil)

// MemoryStore implements EnrollmentStore using in-memory maps. Useful for
// testing and short-lived agent sessions; state is lost when the process
// exits.
type MemoryStore struct {
	agents  map[string]*AgentInfo
	codes   map[string]time.Time // hash -> expiry
	pending map[string]*PendingEnrollment
	mu      sync.RWMutex
}

// NewMemoryStore creates a new in-memory enrollment store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		agents:  make(map[string]*AgentInfo),
		codes:   make(map[string]time.Time),
		pending: make(map[string]*PendingEnrollment),
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

// SaveCode stores a one-time enrollment code's hash and expiry in memory.
func (s *MemoryStore) SaveCode(hash string, expiresAt time.Time) error {
	if hash == "" {
		return &AgentError{Operation: "save_code", Err: ErrEnrollmentCodeInvalid}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[hash] = expiresAt
	return nil
}

// ConsumeCode atomically validates and single-use-consumes the code
// identified by hash, guarded by the store's mutex.
func (s *MemoryStore) ConsumeCode(hash string) error {
	if hash == "" {
		return ErrEnrollmentCodeInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	expiresAt, ok := s.codes[hash]
	if !ok {
		return ErrEnrollmentCodeInvalid
	}
	delete(s.codes, hash)
	if time.Now().After(expiresAt) {
		return ErrEnrollmentCodeExpired
	}
	return nil
}

// CleanExpiredCodes removes every expired, unconsumed code from memory.
func (s *MemoryStore) CleanExpiredCodes() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0
	for hash, expiresAt := range s.codes {
		if now.After(expiresAt) {
			delete(s.codes, hash)
			removed++
		}
	}
	return removed, nil
}

// SavePending stores a pending enrollment request in memory.
func (s *MemoryStore) SavePending(p *PendingEnrollment) error {
	if p == nil || p.ID == "" {
		return &AgentError{Operation: "save_pending", Err: ErrRequestNotFound}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[p.ID] = p
	return nil
}

// GetPending retrieves a pending enrollment request by ID from memory.
func (s *MemoryStore) GetPending(id string) (*PendingEnrollment, error) {
	if id == "" {
		return nil, &AgentError{Operation: "get_pending", Err: ErrRequestNotFound}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pending[id]
	if !ok {
		return nil, ErrRequestNotFound
	}
	return p, nil
}

// ListPending returns every pending enrollment request from memory.
func (s *MemoryStore) ListPending() ([]*PendingEnrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PendingEnrollment, 0, len(s.pending))
	for _, p := range s.pending {
		result = append(result, p)
	}
	return result, nil
}

// DeletePending removes a pending enrollment request by ID from memory.
func (s *MemoryStore) DeletePending(id string) error {
	if id == "" {
		return &AgentError{Operation: "delete_pending", Err: ErrRequestNotFound}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[id]; !ok {
		return ErrRequestNotFound
	}
	delete(s.pending, id)
	return nil
}

// Compile-time interface check.
var _ EnrollmentStore = (*MemoryStore)(nil)
