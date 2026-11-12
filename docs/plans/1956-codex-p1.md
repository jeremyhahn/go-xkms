Findings: (P1) grpc Connect publishes plaintextChannel/dialedTarget/credsOpt before grpc.NewClient succeeds, so a failed TLS reconnect leaves the old plaintext client classified as TLS; (P1) SignImage admits one OpSign use but signs twice (CSR + DSSE), bypassing MaxUsageCount.
Plan: test(grpc) failed reconnect then credentialed SignImage refused, fix(grpc) publish client and security state together only after NewClient succeeds; test(xkms) MaxUsageCount=1 SignImage fails and records <=1 use, =2 succeeds and records 2, fix(xkms) admit and charge both signatures.
Results to follow.
Result: go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/api/transport/grpc/... ./pkg/xkms/... passed (both new tests failed before their fix commits).
Result: make lint passed (actionlint and golangci-lint, 0 issues in every module and tag set).
