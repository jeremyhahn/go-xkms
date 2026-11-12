# 2042: merge the coverage-hang fix

## Cause

Run 43242873250: Coverage shard 1/6 was cancelled at its 90-minute limit and
CI Gate failed. pkg/server tests leaked Servers (no Shutdown), so qrdb
schedulers piled up until the shard hung.

## Method

One signed merge of 990d44601b (PR #2116 head, row/1794-coverage-hang, which
adds newServerWithCleanup at the pkg/server test sites), then the checks:
go build ./..., go vet ./pkg/server/, go test ./pkg/server/, make lint.

## Results

Results to follow.

mf2042j: checks rerun after the lost container (18:12Z); results below
- go build ./...: pass.
- go vet ./pkg/server/: pass.
- go test ./pkg/server/ (tags codec_cbor codec_json codec_msgpack, binary run
  from pkg/server with TMPDIR=../../.git/t because the lane clone path makes
  unix-socket paths exceed 108 bytes): 24 s, no hang, all Servers shut down;
  one failure, TestServer_UnixGRPC_GetCACertificate_WithCA
  (server_ca_grpc_unix_test.go:228, "invalid (non-empty) authority: ..").
  That failure comes from the relative socket path the lane workaround needs,
  not from the code; with an absolute TMPDIR this test cannot bind here. CI's
  /tmp path is not affected.
- make lint: pass (0 issues, all modules and tag sets).
