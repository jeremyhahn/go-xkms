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

package kmip

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeObject is a single object held by the fakeKMIPServer.
type fakeObject struct {
	opaque  kmip.OpaqueObject
	name    string
	comment string
	revoked bool
	destroy bool
}

// fakeKMIPServer is a minimal in-memory KMIP server used to test KMIPAgent
// without a real KMIP deployment. It implements just enough of Register,
// Get, Locate, GetAttributes, Revoke and Destroy to exercise KMIPAgent's
// operation mapping and error handling.
type fakeKMIPServer struct {
	mu      sync.Mutex
	objects map[string]*fakeObject
	nextID  int
	// locateErr, when set, is the refusal every Locate request receives.
	locateErr error
}

func newFakeKMIPServer() *fakeKMIPServer {
	return &fakeKMIPServer{objects: map[string]*fakeObject{}}
}

func (s *fakeKMIPServer) handler() kmipserver.RequestHandler {
	exec := kmipserver.NewBatchExecutor()
	exec.Route(kmip.OperationRegister, kmipserver.HandleFunc(s.handleRegister))
	exec.Route(kmip.OperationGet, kmipserver.HandleFunc(s.handleGet))
	exec.Route(kmip.OperationLocate, kmipserver.HandleFunc(s.handleLocate))
	exec.Route(kmip.OperationGetAttributes, kmipserver.HandleFunc(s.handleGetAttributes))
	exec.Route(kmip.OperationRevoke, kmipserver.HandleFunc(s.handleRevoke))
	exec.Route(kmip.OperationDestroy, kmipserver.HandleFunc(s.handleDestroy))
	exec.Route(kmip.OperationQuery, kmipserver.HandleFunc(s.handleQuery))
	return exec
}

func (s *fakeKMIPServer) handleRegister(_ context.Context, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	opaque, ok := req.Object.(*kmip.OpaqueObject)
	if !ok {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "unsupported object type")
	}

	var name, comment string
	for _, attr := range req.TemplateAttribute.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameName:
			if n, ok := attr.AttributeValue.(kmip.Name); ok {
				name = n.NameValue
			}
		case kmip.AttributeNameComment:
			if c, ok := attr.AttributeValue.(string); ok {
				comment = c
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, obj := range s.objects {
		if obj.name == name && !obj.destroy {
			return nil, kmipserver.Errorf(kmip.ResultReasonObjectAlreadyExists, "object already exists")
		}
	}

	s.nextID++
	id := "id-" + strconv.Itoa(s.nextID)
	s.objects[id] = &fakeObject{opaque: *opaque, name: name, comment: comment}
	return &payloads.RegisterResponsePayload{UniqueIdentifier: id}, nil
}

func (s *fakeKMIPServer) handleGet(_ context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	if req.UniqueIdentifier == "denied" {
		return nil, kmipserver.ErrPermissionDenied
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	obj, ok := s.objects[req.UniqueIdentifier]
	if !ok || obj.destroy {
		return nil, kmipserver.ErrItemNotFound
	}
	opaque := obj.opaque
	return &payloads.GetResponsePayload{
		ObjectType:       kmip.ObjectTypeOpaqueObject,
		UniqueIdentifier: req.UniqueIdentifier,
		Object:           &opaque,
	}, nil
}

func (s *fakeKMIPServer) handleLocate(_ context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
	var nameFilter *string
	for _, attr := range req.Attribute {
		if attr.AttributeName == kmip.AttributeNameName {
			if n, ok := attr.AttributeValue.(kmip.Name); ok {
				v := n.NameValue
				nameFilter = &v
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locateErr != nil {
		return nil, s.locateErr
	}

	var ids []string
	for id, obj := range s.objects {
		if obj.destroy {
			continue
		}
		if nameFilter != nil && obj.name != *nameFilter {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return &payloads.LocateResponsePayload{UniqueIdentifier: ids}, nil
}

// listDeniedName is a fake object Name that makes handleGetAttributes
// reject the request with PermissionDenied, exercising the fatal
// short-circuit in KMIPAgent.ListEscrowed when metadata for one of several
// located objects cannot be fetched.
const listDeniedName = "list-denied"

func (s *fakeKMIPServer) handleGetAttributes(_ context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	obj, ok := s.objects[req.UniqueIdentifier]
	if !ok || obj.destroy {
		return nil, kmipserver.ErrItemNotFound
	}
	if obj.name == listDeniedName {
		return nil, kmipserver.ErrPermissionDenied
	}

	resp := &payloads.GetAttributesResponsePayload{UniqueIdentifier: req.UniqueIdentifier}
	for _, name := range req.AttributeName {
		switch name {
		case kmip.AttributeNameName:
			resp.Attribute = append(resp.Attribute, kmip.Attribute{
				AttributeName:  kmip.AttributeNameName,
				AttributeValue: kmip.Name{NameValue: obj.name, NameType: kmip.NameTypeUninterpretedTextString},
			})
		case kmip.AttributeNameComment:
			resp.Attribute = append(resp.Attribute, kmip.Attribute{
				AttributeName:  kmip.AttributeNameComment,
				AttributeValue: obj.comment,
			})
		}
	}
	return resp, nil
}

func (s *fakeKMIPServer) handleRevoke(_ context.Context, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	obj, ok := s.objects[req.UniqueIdentifier]
	if !ok || obj.destroy {
		return nil, kmipserver.ErrItemNotFound
	}
	obj.revoked = true
	return &payloads.RevokeResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
}

// destroyDeniedName is a fake object Name that makes handleDestroy reject
// the Destroy call with PermissionDenied even though the preceding Revoke
// succeeds, exercising KMIPAgent.RevokeEscrow's second (Destroy) failure
// path.
const destroyDeniedName = "destroy-denied"

func (s *fakeKMIPServer) handleDestroy(_ context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	obj, ok := s.objects[req.UniqueIdentifier]
	if !ok || obj.destroy {
		return nil, kmipserver.ErrItemNotFound
	}
	if obj.name == destroyDeniedName {
		return nil, kmipserver.ErrPermissionDenied
	}
	obj.destroy = true
	return &payloads.DestroyResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
}

func (s *fakeKMIPServer) handleQuery(_ context.Context, _ *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
	return &payloads.QueryResponsePayload{}, nil
}

// newTestAgent starts a fakeKMIPServer and returns a KMIPAgent dialed
// against it over TLS, using the kmiptest in-process test harness.
func newTestAgent(t *testing.T) *KMIPAgent {
	t.Helper()
	agent, _ := newTestAgentAndServer(t)
	return agent
}

// newTestAgentAndServer is like newTestAgent but also returns the
// fakeKMIPServer so tests can inspect or mutate server-side state directly.
func newTestAgentAndServer(t *testing.T) (*KMIPAgent, *fakeKMIPServer) {
	t.Helper()

	srv := newFakeKMIPServer()
	addr, ca := kmiptest.NewServer(t, srv.handler())

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(ca), 0600))

	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://" + addr,
		CACert:   caPath,
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = agent.Close() })
	return agent, srv
}

func TestNewKMIPAgent_NilConfig(t *testing.T) {
	_, err := NewKMIPAgent(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentNotConfigured))
}

func TestNewKMIPAgent_InvalidClientCert(t *testing.T) {
	_, err := NewKMIPAgent(&KMIPConfig{
		Endpoint:   "kmip://escrow.company.com:5696",
		ClientCert: "/nonexistent/cert.pem",
		ClientKey:  "/nonexistent/key.pem",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestNewKMIPAgent_InvalidCACert_MissingFile(t *testing.T) {
	_, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
		CACert:   "/nonexistent/ca.pem",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestNewKMIPAgent_InvalidCACert_BadPEM(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "bad-ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not-a-pem-certificate"), 0600))

	_, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
		CACert:   caPath,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestNewKMIPAgent_CustomTimeout(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "kmip://escrow.company.com:5696",
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, agent.config.timeout())
}

func TestKMIPConfig_Timeout_Default(t *testing.T) {
	cfg := &KMIPConfig{Endpoint: "kmip://escrow.company.com:5696"}
	assert.Equal(t, defaultTimeout, cfg.timeout())
}

func TestDialAddr(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{"kmip scheme", "kmip://escrow.company.com:5696", "escrow.company.com:5696"},
		{"kmips scheme", "kmips://escrow.company.com:5696", "escrow.company.com:5696"},
		{"no scheme", "escrow.company.com:5696", "escrow.company.com:5696"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dialAddr(tt.endpoint))
		})
	}
}

func TestKMIPAgent_Type(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{Endpoint: "kmip://escrow.company.com:5696"})
	require.NoError(t, err)
	assert.Equal(t, escrow.AgentTypeKMIP, agent.Type())
}

func TestKMIPAgent_Available_Success(t *testing.T) {
	agent := newTestAgent(t)
	assert.True(t, agent.Available(context.Background()))
}

func TestKMIPAgent_Available_ServerUnreachable(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "127.0.0.1:1",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	assert.False(t, agent.Available(context.Background()))
}

func TestKMIPAgent_Available_AfterClose(t *testing.T) {
	agent := newTestAgent(t)
	require.NoError(t, agent.Close())
	assert.False(t, agent.Available(context.Background()))
}

func TestKMIPAgent_EscrowKey_NilRequest(t *testing.T) {
	agent := newTestAgent(t)
	_, err := agent.EscrowKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNilRequest))
}

func TestKMIPAgent_EscrowKey_InvalidRequest(t *testing.T) {
	agent := newTestAgent(t)
	_, err := agent.EscrowKey(context.Background(), &escrow.EscrowRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestKMIPAgent_EscrowKey_AfterClose(t *testing.T) {
	agent := newTestAgent(t)
	require.NoError(t, agent.Close())

	_, err := agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentClosed))
}

func TestKMIPAgent_EscrowKey_ServerUnavailable(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "127.0.0.1:1",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentUnavailable))
}

func TestKMIPAgent_EscrowKey_AlreadyEscrowed(t *testing.T) {
	agent := newTestAgent(t)

	req := &escrow.EscrowRequest{
		KeyID:      "dup-key",
		WrappedKey: []byte("wrapped-key-material"),
	}
	_, err := agent.EscrowKey(context.Background(), req)
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAlreadyEscrowed))
}

// TestKMIPAgent_EscrowRecoverListRevoke_RoundTrip exercises the full escrow
// lifecycle against the fake KMIP server: escrow, recover by KeyID, recover
// by EscrowID, list, then revoke.
func TestKMIPAgent_EscrowRecoverListRevoke_RoundTrip(t *testing.T) {
	agent := newTestAgent(t)
	ctx := context.Background()

	receipt, err := agent.EscrowKey(ctx, &escrow.EscrowRequest{
		KeyID:             "key-001",
		WrappedKey:        []byte("wrapped-key-material"),
		WrappingAlgorithm: "AES-KW",
		KeyType:           "aes-256",
		TenantID:          "tenant-a",
		Purpose:           "barrier",
		Metadata:          map[string]string{"region": "us-east-1"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, receipt.EscrowID)
	assert.Equal(t, "key-001", receipt.KeyID)
	assert.Equal(t, escrow.AgentTypeKMIP, receipt.Agent)

	// Recover by KeyID (requires a Locate lookup).
	recovered, err := agent.RecoverKey(ctx, &escrow.RecoverRequest{KeyID: "key-001"})
	require.NoError(t, err)
	assert.Equal(t, "key-001", recovered.KeyID)
	assert.Equal(t, []byte("wrapped-key-material"), recovered.WrappedKey)
	assert.Equal(t, "AES-KW", recovered.WrappingAlgorithm)

	// Recover by EscrowID directly.
	recovered, err = agent.RecoverKey(ctx, &escrow.RecoverRequest{EscrowID: receipt.EscrowID})
	require.NoError(t, err)
	assert.Equal(t, []byte("wrapped-key-material"), recovered.WrappedKey)

	// List should include the escrowed key with its metadata.
	records, err := agent.ListEscrowed(ctx)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, receipt.EscrowID, records[0].EscrowID)
	assert.Equal(t, "key-001", records[0].KeyID)
	assert.Equal(t, "aes-256", records[0].KeyType)
	assert.Equal(t, "tenant-a", records[0].TenantID)
	assert.Equal(t, "barrier", records[0].Purpose)
	assert.Equal(t, "us-east-1", records[0].Metadata["region"])

	// Revoke removes the key; subsequent recovery fails with not-found.
	require.NoError(t, agent.RevokeEscrow(ctx, receipt.EscrowID))

	_, err = agent.RecoverKey(ctx, &escrow.RecoverRequest{EscrowID: receipt.EscrowID})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrKeyNotFound))

	records, err = agent.ListEscrowed(ctx)
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestKMIPAgent_RecoverKey_CorruptMetadata(t *testing.T) {
	agent, srv := newTestAgentAndServer(t)

	srv.mu.Lock()
	srv.objects["corrupt-id"] = &fakeObject{
		opaque:  kmip.OpaqueObject{OpaqueDataValue: []byte("wrapped")},
		name:    "corrupt-key",
		comment: "{not-valid-json",
	}
	srv.mu.Unlock()

	_, err := agent.RecoverKey(context.Background(), &escrow.RecoverRequest{EscrowID: "corrupt-id"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrRecoverFailed))
	assert.Contains(t, err.Error(), "failed to decode escrow metadata")
}

func TestKMIPAgent_RecoverKey_NilRequest(t *testing.T) {
	agent := newTestAgent(t)
	_, err := agent.RecoverKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNilRequest))
}

func TestKMIPAgent_RecoverKey_InvalidRequest(t *testing.T) {
	agent := newTestAgent(t)
	_, err := agent.RecoverKey(context.Background(), &escrow.RecoverRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestKMIPAgent_RecoverKey_NotFoundByKeyID(t *testing.T) {
	agent := newTestAgent(t)
	_, err := agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "nonexistent"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrKeyNotFound))
}

func TestKMIPAgent_RecoverKey_PermissionDenied(t *testing.T) {
	agent := newTestAgent(t)
	_, err := agent.RecoverKey(context.Background(), &escrow.RecoverRequest{EscrowID: "denied"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestKMIPAgent_RecoverKey_AfterClose(t *testing.T) {
	agent := newTestAgent(t)
	require.NoError(t, agent.Close())

	_, err := agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "key-001"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentClosed))
}

func TestKMIPAgent_RecoverKey_ServerUnavailable(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "127.0.0.1:1",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "key-001"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentUnavailable))
}

func TestKMIPAgent_ListEscrowed_PartialMetadataFailure(t *testing.T) {
	agent := newTestAgent(t)
	ctx := context.Background()

	_, err := agent.EscrowKey(ctx, &escrow.EscrowRequest{
		KeyID:      "key-ok",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.NoError(t, err)

	_, err = agent.EscrowKey(ctx, &escrow.EscrowRequest{
		KeyID:      listDeniedName,
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.NoError(t, err)

	_, err = agent.ListEscrowed(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

// TestKMIPAgent_LocateRefused covers both callers of Locate: recovery by key
// ID and listing. A refused Locate must surface as the typed escrow error
// with no partial result.
func TestKMIPAgent_LocateRefused(t *testing.T) {
	refusals := []struct {
		name    string
		refusal error
		want    error
	}{
		{name: "permission denied", refusal: kmipserver.ErrPermissionDenied, want: escrow.ErrAuthenticationFailed},
		{name: "server failure", refusal: errors.New("backing store offline"), want: escrow.ErrRecoverFailed},
	}
	ops := []struct {
		name string
		call func(t *testing.T, agent *KMIPAgent) error
	}{
		{name: "RecoverKey by key ID", call: func(t *testing.T, agent *KMIPAgent) error {
			resp, err := agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "key-1"})
			assert.Nil(t, resp)
			return err
		}},
		{name: "ListEscrowed", call: func(t *testing.T, agent *KMIPAgent) error {
			records, err := agent.ListEscrowed(context.Background())
			assert.Nil(t, records)
			return err
		}},
	}

	for _, r := range refusals {
		for _, op := range ops {
			t.Run(op.name+"/"+r.name, func(t *testing.T) {
				agent, srv := newTestAgentAndServer(t)
				ctx := context.Background()
				_, err := agent.EscrowKey(ctx, &escrow.EscrowRequest{
					KeyID:      "key-1",
					WrappedKey: []byte("wrapped-key-material"),
				})
				require.NoError(t, err)

				srv.mu.Lock()
				srv.locateErr = r.refusal
				srv.mu.Unlock()

				err = op.call(t, agent)
				require.Error(t, err)
				assert.True(t, errors.Is(err, r.want), "got %v, want %v", err, r.want)
			})
		}
	}
}

func TestKMIPAgent_ListEscrowed_AfterClose(t *testing.T) {
	agent := newTestAgent(t)
	require.NoError(t, agent.Close())

	_, err := agent.ListEscrowed(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentClosed))
}

func TestKMIPAgent_ListEscrowed_ServerUnavailable(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "127.0.0.1:1",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	_, err = agent.ListEscrowed(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentUnavailable))
}

func TestKMIPAgent_RevokeEscrow_EmptyID(t *testing.T) {
	agent := newTestAgent(t)
	err := agent.RevokeEscrow(context.Background(), "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestKMIPAgent_RevokeEscrow_NotFound(t *testing.T) {
	agent := newTestAgent(t)
	err := agent.RevokeEscrow(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrKeyNotFound))
}

func TestKMIPAgent_RevokeEscrow_AfterClose(t *testing.T) {
	agent := newTestAgent(t)
	require.NoError(t, agent.Close())

	err := agent.RevokeEscrow(context.Background(), "escrow-001")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentClosed))
}

func TestKMIPAgent_RevokeEscrow_DestroyFails(t *testing.T) {
	agent := newTestAgent(t)
	ctx := context.Background()

	receipt, err := agent.EscrowKey(ctx, &escrow.EscrowRequest{
		KeyID:      destroyDeniedName,
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.NoError(t, err)

	err = agent.RevokeEscrow(ctx, receipt.EscrowID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestKMIPAgent_RevokeEscrow_ServerUnavailable(t *testing.T) {
	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint: "127.0.0.1:1",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "escrow-001")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentUnavailable))
}

func TestKMIPAgent_Close_Idempotent(t *testing.T) {
	agent := newTestAgent(t)
	require.NoError(t, agent.Close())
	require.NoError(t, agent.Close())
	assert.True(t, agent.closed.Load())
}

func TestKMIPAgent_MutualTLS_RoundTrip(t *testing.T) {
	srv := newFakeKMIPServer()
	addr, ca := kmiptest.NewServer(t, srv.handler())

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(ca), 0600))

	certPEM, keyPEM, err := kmiptest.GenerateSelfSignedCertPEM()
	require.NoError(t, err)
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	agent, err := NewKMIPAgent(&KMIPConfig{
		Endpoint:   "kmip://" + addr,
		CACert:     caPath,
		ClientCert: certPath,
		ClientKey:  keyPath,
		Timeout:    5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = agent.Close() })
	require.Len(t, agent.tlsConfig.Certificates, 1)

	receipt, err := agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "mtls-key",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, receipt.EscrowID)
}

// TestKMIPAgent_GetClient_ConcurrentDial exercises the lock-free lazy-dial
// race in getClient: multiple goroutines calling an operation before the
// client is established should all succeed, with exactly one live
// connection surviving (the CompareAndSwap loser closes its own).
func TestKMIPAgent_GetClient_ConcurrentDial(t *testing.T) {
	agent := newTestAgent(t)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := agent.getClient(context.Background())
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.NotNil(t, agent.client.Load())
}

func TestMapResultReason(t *testing.T) {
	err := mapResultReason(kmip.ResultReasonAuthenticationNotSuccessful, "detail", escrow.ErrEscrowFailed)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestMapResultReason_Default(t *testing.T) {
	err := mapResultReason(kmip.ResultReasonGeneralFailure, "boom", escrow.ErrEscrowFailed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEscrowFailed))
	assert.Contains(t, err.Error(), "boom")
}
