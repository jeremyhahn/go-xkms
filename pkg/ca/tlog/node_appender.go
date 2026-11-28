package tlog

import (
	"context"
	"errors"
	"sync"

	"github.com/jeremyhahn/go-qrdb/pkg/vlog"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/vlogwire"
)

// VlogSource is a qrdb client exposing the node's verifiable logs
// (*qrdbsdk.Client).
type VlogSource interface {
	Vlog() transport.VlogClient
}

// KeyTypeSource names the head-signature type of the key that signs the
// logs' checkpoints (*HeadSignerProvider).
type KeyTypeSource interface {
	KeyType(ctx context.Context) (qrdbsdk.HeadSignatureType, error)
}

// NodeAppenderConfig configures a NodeAppender.
type NodeAppenderConfig struct {
	// Tenant prefixes each log's checkpoint origin: "<Tenant>/<log>".
	Tenant string
	// Keys gives the signature type a log is created with.
	Keys KeyTypeSource
	// Context, when set, derives the context every node call runs in
	// (tenant and caller identity the node's log service authorizes).
	Context func(context.Context) (context.Context, error)
}

// NodeAppender appends entries to the node's verifiable logs, creating a
// log, signed by the CA key, on first use.
type NodeAppender struct {
	client VlogSource
	cfg    NodeAppenderConfig
	mu     sync.Mutex
}

// NewNodeAppender returns an Appender over client.
func NewNodeAppender(client VlogSource, cfg NodeAppenderConfig) *NodeAppender {
	return &NodeAppender{client: client, cfg: cfg}
}

// Append appends one entry to log, creating the log when the node reports
// it missing.
func (a *NodeAppender) Append(ctx context.Context, log string, entry []byte) error {
	if a.cfg.Context != nil {
		c, err := a.cfg.Context(ctx)
		if err != nil {
			return err
		}
		ctx = c
	}
	vl := a.client.Vlog()
	req := &vlogwire.AppendRequest{Log: log, Entries: [][]byte{entry}}
	_, err := vl.VlogAppend(ctx, req)
	var nf *vlog.LogNotFoundError
	if !errors.As(err, &nf) {
		return err
	}
	if err := a.create(ctx, vl, log); err != nil {
		return err
	}
	_, err = vl.VlogAppend(ctx, req)
	return err
}

func (a *NodeAppender) create(ctx context.Context, vl transport.VlogClient, log string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.Keys == nil {
		return ErrCANotBound
	}
	typ, err := a.cfg.Keys.KeyType(ctx)
	if err != nil {
		return err
	}
	_, err = vl.VlogCreate(ctx, &vlogwire.CreateRequest{
		Log: log, Origin: a.cfg.Tenant + "/" + log, SigningKeyType: typ,
	})
	var exists *vlog.LogExistsError
	if errors.As(err, &exists) {
		return nil
	}
	return err
}
