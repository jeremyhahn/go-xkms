- **Fixed `xkey/cmd/xkey/cmd` failing to compile its tests without the `ble`
  build tag**: `oath_barrier_test.go` and `oidc_barrier_test.go` (no build
  tag) called `captureDefaultLog`, but the only definition lived in
  `device_pair_flow_test.go` behind `//go:build ble`, so `go vet` / `go test`
  on the package failed to compile under the default tag set or under
  `codec_json` alone -- any tag set that omits `ble`. `captureDefaultLog`
  moved to a new untagged helper file, `log_capture_test.go`; nothing else in
  the package crossed a build-tag boundary the same way, confirmed by `go vet`
  across every tag set the xkey Makefile and CI use (untagged, `codec_json`,
  `ble`, `ble codec_json`, and the widest `make vet` combination). No test
  behaviour changed, only where the helper is declared. (go-xkms#944)
