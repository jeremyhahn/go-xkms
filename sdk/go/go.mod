module github.com/jeremyhahn/go-keychain/sdk/go

go 1.25.6

require (
	github.com/jeremyhahn/go-keychain v0.0.0-00010101000000-000000000000
	github.com/quic-go/quic-go v0.57.1
	google.golang.org/grpc v1.77.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/jeremyhahn/go-keychain => ../..
