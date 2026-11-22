# F2 (#2076) fold: vet-integration and RBAC test fixes (lane fdp2076c)

- Causes: go-qrdb v0.58.2-alpha grants the built-in admin role roles:create and roles:update (pkg/permission built-in role grants), and resolves an identity's roles by role ID inside the request's tenant (pkg/auth Identity.Roles), with a grant guard that lets a grantor grant only permissions it holds in the target tenant; two integration tests also imported sdk/go as qrdbsdk without using it.
- Checks: make vet-integration; go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/acme/...; make lint.
- Results: make vet-integration and make lint pass; pkg/acme/admin and pkg/acme/api/server pass. pkg/acme/client's TestDeviceAttestDICE* fail only because the tfwsim-atecc608a simulator is not built in the lane (make tfwsim-atecc608a builds it).
