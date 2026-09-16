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

// Package kmip provides an escrow.EscrowAgent implementation using the
// KMIP (Key Management Interoperability Protocol) standard, backed by
// github.com/ovh/kmip-go.
//
// Operation mapping:
//   - EscrowKey  -> Register, storing the wrapped key as a KMIP OpaqueObject.
//     The wrapped key is ciphertext, not usable native key material in any
//     KMIP-defined key format, so the Opaque Object managed object type
//     (designed for exactly this: an opaque, server-uninterpreted blob) is
//     used rather than SymmetricKey/PrivateKey/SecretData. The original
//     KeyID is stored as the object's Name attribute and the remaining
//     escrow metadata (wrapping algorithm, key type, tenant, purpose,
//     caller metadata, escrow timestamp) is JSON-encoded into the Comment
//     attribute so it round-trips through GetAttributes without requiring
//     a side database.
//   - RecoverKey -> Locate (by Name, when only KeyID is supplied) followed
//     by Get to fetch the Opaque Object, plus GetAttributes to recover the
//     wrapping algorithm and KeyID metadata.
//   - ListEscrowed -> Locate for every Opaque Object's Unique Identifier,
//     followed by GetAttributes per object to reconstruct escrow.EscrowRecord.
//   - RevokeEscrow -> Revoke (CessationOfOperation) followed by Destroy.
//     KMIP servers generally require an object to be deactivated/revoked
//     before it is eligible for Destroy, so both are issued in sequence to
//     durably remove the escrowed material rather than merely marking it
//     inactive.
package kmip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
)

// defaultTimeout is the default per-request KMIP round-trip timeout.
const defaultTimeout = 30 * time.Second

// KMIPConfig configures the KMIP escrow agent.
type KMIPConfig struct {
	// Endpoint is the KMIP server address (e.g., "kmip://escrow.company.com:5696").
	// The "kmip://" and "kmips://" schemes are accepted and stripped; a bare
	// "host:port" address is also accepted.
	Endpoint string `json:"endpoint"`

	// ClientCert is the path to the client TLS certificate PEM file.
	ClientCert string `json:"client_cert"`

	// ClientKey is the path to the client TLS private key PEM file.
	ClientKey string `json:"client_key"`

	// CACert is the path to the CA certificate PEM file.
	CACert string `json:"ca_cert"`

	// Timeout overrides the default per-request KMIP round-trip timeout.
	// Zero uses defaultTimeout.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// Validate checks the configuration for required fields.
func (c *KMIPConfig) Validate() error {
	if c.Endpoint == "" {
		return escrow.ErrEmptyEndpoint
	}
	return nil
}

// timeout returns the configured timeout, or defaultTimeout if unset.
func (c *KMIPConfig) timeout() time.Duration {
	if c.Timeout <= 0 {
		return defaultTimeout
	}
	return c.Timeout
}

// escrowMetadata is the JSON envelope persisted in the Comment attribute of
// the registered KMIP Opaque Object. It carries the escrow.EscrowRequest
// fields that have no direct KMIP attribute equivalent.
type escrowMetadata struct {
	WrappingAlgorithm string            `json:"wrapping_algorithm"`
	KeyType           string            `json:"key_type,omitempty"`
	TenantID          string            `json:"tenant_id,omitempty"`
	Purpose           string            `json:"purpose,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	EscrowedAt        time.Time         `json:"escrowed_at"`
}

// KMIPAgent implements escrow.EscrowAgent using the KMIP protocol.
type KMIPAgent struct {
	config    *KMIPConfig
	addr      string
	tlsConfig *tls.Config
	client    atomic.Pointer[kmipclient.Client]
	closed    atomic.Bool
}

// Compile-time interface assertion.
var _ escrow.EscrowAgent = (*KMIPAgent)(nil)

// NewKMIPAgent creates a new KMIP escrow agent. The configuration is
// validated and TLS material (client certificate and CA bundle, if
// configured) is loaded eagerly so misconfiguration fails fast; the actual
// KMIP connection is established lazily on first use.
func NewKMIPAgent(config *KMIPConfig) (*KMIPAgent, error) {
	if config == nil {
		return nil, escrow.ErrAgentNotConfigured
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	tlsConfig, err := buildTLSConfig(config)
	if err != nil {
		return nil, err
	}

	return &KMIPAgent{
		config:    config,
		addr:      dialAddr(config.Endpoint),
		tlsConfig: tlsConfig,
	}, nil
}

// dialAddr strips the "kmip://" or "kmips://" scheme from a KMIP endpoint,
// since kmipclient.DialContext expects a bare "host:port" address.
func dialAddr(endpoint string) string {
	if addr, ok := strings.CutPrefix(endpoint, "kmips://"); ok {
		return addr
	}
	if addr, ok := strings.CutPrefix(endpoint, "kmip://"); ok {
		return addr
	}
	return endpoint
}

// buildTLSConfig loads the optional client certificate and CA bundle for
// mTLS, mirroring the xkms federation agent's transport construction.
func buildTLSConfig(config *KMIPConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if config.ClientCert != "" && config.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, &errs.Detail{Err: escrow.ErrAuthenticationFailed, Detail: fmt.Sprintf("failed to load client certificate: %s", err)}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if config.CACert != "" {
		caCert, err := os.ReadFile(config.CACert)
		if err != nil {
			return nil, &errs.Detail{Err: escrow.ErrAuthenticationFailed, Detail: fmt.Sprintf("failed to read CA certificate: %s", err)}
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, &errs.Detail{Err: escrow.ErrAuthenticationFailed, Detail: "failed to parse CA certificate"}
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// Type returns the agent type identifier.
func (a *KMIPAgent) Type() string {
	return escrow.AgentTypeKMIP
}

// Available reports whether the KMIP server can currently be reached by
// dialing (if not already connected) and issuing a lightweight Query.
func (a *KMIPAgent) Available(ctx context.Context) bool {
	if a.closed.Load() {
		return false
	}

	client, err := a.getClient(ctx)
	if err != nil {
		return false
	}

	payload, err := client.Query().Operations().Build()
	if err != nil {
		return false
	}

	_, err = a.doBatch(ctx, client, payload, escrow.ErrAgentUnavailable)
	return err == nil
}

// getClient returns the lazily-dialed KMIP client, dialing and negotiating
// the protocol version on first use. Concurrent callers race to dial; the
// loser closes its redundant connection and adopts the winner's client,
// avoiding a mutex around connection establishment.
func (a *KMIPAgent) getClient(ctx context.Context) (*kmipclient.Client, error) {
	if c := a.client.Load(); c != nil {
		return c, nil
	}

	// kmipclient.DialContext mutates the supplied *tls.Config in place
	// (populating RootCAs, appending Certificates), so each dial attempt
	// must get its own clone: concurrent callers each racing to dial share
	// a.tlsConfig, and dialing with the same pointer would be a data race.
	c, err := kmipclient.DialContext(ctx, a.addr,
		kmipclient.WithTlsConfig(a.tlsConfig.Clone()),
		kmipclient.WithMiddlewares(kmipclient.TimeoutMiddleware(a.config.timeout())),
	)
	if err != nil {
		return nil, &errs.Detail{Err: escrow.ErrAgentUnavailable, Detail: fmt.Sprintf("failed to connect to KMIP server: %s", err)}
	}

	if !a.client.CompareAndSwap(nil, c) {
		_ = c.Close()
		return a.client.Load(), nil
	}
	return c, nil
}

// doBatch sends a single-payload batch request and maps the result to a
// typed escrow error on failure, either from the transport (agent
// unavailable) or from the KMIP result reason (mapResultReason).
func (a *KMIPAgent) doBatch(ctx context.Context, client *kmipclient.Client, payload kmip.OperationPayload, opErr error) (kmip.OperationPayload, error) {
	batch, err := client.Batch(ctx, payload)
	if err != nil {
		return nil, &errs.Detail{Err: escrow.ErrAgentUnavailable, Detail: err.Error()}
	}
	bi := batch[0]
	if bi.ResultStatus != kmip.ResultStatusSuccess {
		return nil, mapResultReason(bi.ResultReason, bi.ResultMessage, opErr)
	}
	return bi.ResponsePayload, nil
}

// mapResultReason maps a KMIP ResultReason to the shared escrow sentinel
// errors, the way the xkms federation agent maps HTTP status codes.
func mapResultReason(reason kmip.ResultReason, message string, opErr error) error {
	switch reason {
	case kmip.ResultReasonItemNotFound:
		return escrow.ErrKeyNotFound
	case kmip.ResultReasonAuthenticationNotSuccessful, kmip.ResultReasonPermissionDenied:
		return escrow.ErrAuthenticationFailed
	case kmip.ResultReasonObjectAlreadyExists:
		return escrow.ErrAlreadyEscrowed
	default:
		return &errs.Detail{Err: opErr, Detail: fmt.Sprintf("server returned reason %q: %s", ttlv.EnumStr(reason), message)}
	}
}

// EscrowKey sends wrapped key material to the KMIP server as a Register
// request, storing the wrapped bytes as an Opaque Object.
func (a *KMIPAgent) EscrowKey(ctx context.Context, req *escrow.EscrowRequest) (*escrow.EscrowReceipt, error) {
	if a.closed.Load() {
		return nil, escrow.ErrAgentClosed
	}
	if req == nil {
		return nil, escrow.ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}

	meta := escrowMetadata{
		WrappingAlgorithm: req.WrappingAlgorithm,
		KeyType:           req.KeyType,
		TenantID:          req.TenantID,
		Purpose:           req.Purpose,
		Metadata:          req.Metadata,
		EscrowedAt:        time.Now().UTC(),
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, &errs.Detail{Err: escrow.ErrEscrowFailed, Detail: fmt.Sprintf("failed to encode escrow metadata: %s", err)}
	}

	payload, err := client.Register().
		Object(&kmip.OpaqueObject{OpaqueDataValue: req.WrappedKey}).
		WithName(req.KeyID).
		WithAttribute(kmip.AttributeNameComment, string(metaJSON)).
		Build()
	if err != nil {
		return nil, &errs.Detail{Err: escrow.ErrEscrowFailed, Detail: fmt.Sprintf("failed to build register request: %s", err)}
	}

	respPayload, err := a.doBatch(ctx, client, payload, escrow.ErrEscrowFailed)
	if err != nil {
		return nil, err
	}

	resp, ok := respPayload.(*payloads.RegisterResponsePayload)
	if !ok {
		return nil, &errs.Detail{Err: escrow.ErrEscrowFailed, Detail: "unexpected register response payload type"}
	}

	return &escrow.EscrowReceipt{
		EscrowID:   resp.UniqueIdentifier,
		KeyID:      req.KeyID,
		Agent:      escrow.AgentTypeKMIP,
		EscrowedAt: meta.EscrowedAt,
	}, nil
}

// RecoverKey retrieves wrapped key material from the KMIP server via Get,
// locating the object by Name first when only a KeyID is supplied.
func (a *KMIPAgent) RecoverKey(ctx context.Context, req *escrow.RecoverRequest) (*escrow.RecoverResponse, error) {
	if a.closed.Load() {
		return nil, escrow.ErrAgentClosed
	}
	if req == nil {
		return nil, escrow.ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}

	id := req.EscrowID
	if id == "" {
		id, err = a.lookupByKeyID(ctx, client, req.KeyID)
		if err != nil {
			return nil, err
		}
	}

	getPayload, err := client.Get(id).Build()
	if err != nil {
		return nil, &errs.Detail{Err: escrow.ErrRecoverFailed, Detail: fmt.Sprintf("failed to build get request: %s", err)}
	}

	respPayload, err := a.doBatch(ctx, client, getPayload, escrow.ErrRecoverFailed)
	if err != nil {
		return nil, err
	}

	getResp, ok := respPayload.(*payloads.GetResponsePayload)
	if !ok {
		return nil, &errs.Detail{Err: escrow.ErrRecoverFailed, Detail: "unexpected get response payload type"}
	}
	opaque, ok := getResp.Object.(*kmip.OpaqueObject)
	if !ok {
		return nil, &errs.Detail{Err: escrow.ErrRecoverFailed, Detail: "escrowed object is not an opaque wrapped key"}
	}

	keyID, meta, err := a.fetchMetadata(ctx, client, id, escrow.ErrRecoverFailed)
	if err != nil {
		return nil, err
	}
	if req.KeyID != "" {
		keyID = req.KeyID
	}

	return &escrow.RecoverResponse{
		KeyID:             keyID,
		WrappedKey:        opaque.OpaqueDataValue,
		WrappingAlgorithm: meta.WrappingAlgorithm,
	}, nil
}

// lookupByKeyID resolves a KeyID to its KMIP Unique Identifier via Locate,
// returning escrow.ErrKeyNotFound when no matching object exists.
func (a *KMIPAgent) lookupByKeyID(ctx context.Context, client *kmipclient.Client, keyID string) (string, error) {
	payload, err := client.Locate().
		WithAttribute(kmip.AttributeNameName, kmip.Name{
			NameValue: keyID,
			NameType:  kmip.NameTypeUninterpretedTextString,
		}).
		Build()
	if err != nil {
		return "", &errs.Detail{Err: escrow.ErrRecoverFailed, Detail: fmt.Sprintf("failed to build locate request: %s", err)}
	}

	respPayload, err := a.doBatch(ctx, client, payload, escrow.ErrRecoverFailed)
	if err != nil {
		return "", err
	}

	locateResp, ok := respPayload.(*payloads.LocateResponsePayload)
	if !ok {
		return "", &errs.Detail{Err: escrow.ErrRecoverFailed, Detail: "unexpected locate response payload type"}
	}
	if len(locateResp.UniqueIdentifier) == 0 {
		return "", escrow.ErrKeyNotFound
	}
	return locateResp.UniqueIdentifier[0], nil
}

// fetchMetadata retrieves the Name and Comment attributes for a KMIP
// object and decodes the escrowMetadata JSON envelope from Comment.
func (a *KMIPAgent) fetchMetadata(ctx context.Context, client *kmipclient.Client, id string, opErr error) (keyID string, meta escrowMetadata, err error) {
	payload, err := client.GetAttributes(id, kmip.AttributeNameName, kmip.AttributeNameComment).Build()
	if err != nil {
		return "", escrowMetadata{}, &errs.Detail{Err: opErr, Detail: fmt.Sprintf("failed to build get attributes request: %s", err)}
	}

	respPayload, err := a.doBatch(ctx, client, payload, opErr)
	if err != nil {
		return "", escrowMetadata{}, err
	}

	attrsResp, ok := respPayload.(*payloads.GetAttributesResponsePayload)
	if !ok {
		return "", escrowMetadata{}, &errs.Detail{Err: opErr, Detail: "unexpected get attributes response payload type"}
	}

	for _, attr := range attrsResp.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameName:
			if name, ok := attr.AttributeValue.(kmip.Name); ok {
				keyID = name.NameValue
			}
		case kmip.AttributeNameComment:
			comment, ok := attr.AttributeValue.(string)
			if !ok {
				continue
			}
			if err := json.Unmarshal([]byte(comment), &meta); err != nil {
				return "", escrowMetadata{}, &errs.Detail{Err: opErr, Detail: fmt.Sprintf("failed to decode escrow metadata: %s", err)}
			}
		}
	}
	return keyID, meta, nil
}

// ListEscrowed returns all keys held by the KMIP server by locating every
// Opaque Object and fetching its escrow metadata.
func (a *KMIPAgent) ListEscrowed(ctx context.Context) ([]escrow.EscrowRecord, error) {
	if a.closed.Load() {
		return nil, escrow.ErrAgentClosed
	}

	client, err := a.getClient(ctx)
	if err != nil {
		return nil, err
	}

	payload, err := client.Locate().
		WithAttribute(kmip.AttributeNameObjectType, kmip.ObjectTypeOpaqueObject).
		Build()
	if err != nil {
		return nil, &errs.Detail{Err: escrow.ErrRecoverFailed, Detail: fmt.Sprintf("failed to build locate request: %s", err)}
	}

	respPayload, err := a.doBatch(ctx, client, payload, escrow.ErrRecoverFailed)
	if err != nil {
		return nil, err
	}

	locateResp, ok := respPayload.(*payloads.LocateResponsePayload)
	if !ok {
		return nil, &errs.Detail{Err: escrow.ErrRecoverFailed, Detail: "unexpected locate response payload type"}
	}

	records := make([]escrow.EscrowRecord, 0, len(locateResp.UniqueIdentifier))
	for _, id := range locateResp.UniqueIdentifier {
		keyID, meta, err := a.fetchMetadata(ctx, client, id, escrow.ErrRecoverFailed)
		if err != nil {
			return nil, err
		}
		records = append(records, escrow.EscrowRecord{
			EscrowID:          id,
			KeyID:             keyID,
			Agent:             escrow.AgentTypeKMIP,
			WrappingAlgorithm: meta.WrappingAlgorithm,
			KeyType:           meta.KeyType,
			TenantID:          meta.TenantID,
			Purpose:           meta.Purpose,
			EscrowedAt:        meta.EscrowedAt,
			Metadata:          meta.Metadata,
		})
	}
	return records, nil
}

// RevokeEscrow removes an escrowed key from the KMIP server. The object is
// first Revoked (marking it no longer usable) and then Destroyed, since
// KMIP servers commonly require an object to be deactivated before it is
// eligible for destruction.
func (a *KMIPAgent) RevokeEscrow(ctx context.Context, escrowID string) error {
	if a.closed.Load() {
		return escrow.ErrAgentClosed
	}
	if escrowID == "" {
		return escrow.ErrEmptyKeyID
	}

	client, err := a.getClient(ctx)
	if err != nil {
		return err
	}

	revokePayload, err := client.Revoke(escrowID).
		WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).
		Build()
	if err != nil {
		return &errs.Detail{Err: escrow.ErrRevokeFailed, Detail: fmt.Sprintf("failed to build revoke request: %s", err)}
	}
	if _, err := a.doBatch(ctx, client, revokePayload, escrow.ErrRevokeFailed); err != nil {
		return err
	}

	destroyPayload, err := client.Destroy(escrowID).Build()
	if err != nil {
		return &errs.Detail{Err: escrow.ErrRevokeFailed, Detail: fmt.Sprintf("failed to build destroy request: %s", err)}
	}
	if _, err := a.doBatch(ctx, client, destroyPayload, escrow.ErrRevokeFailed); err != nil {
		return err
	}

	return nil
}

// Close releases resources held by the KMIP agent. It is idempotent and
// never blocks on network I/O beyond closing the underlying connection.
func (a *KMIPAgent) Close() error {
	a.closed.Store(true)
	if c := a.client.Load(); c != nil {
		return c.Close()
	}
	return nil
}
