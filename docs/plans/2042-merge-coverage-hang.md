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
