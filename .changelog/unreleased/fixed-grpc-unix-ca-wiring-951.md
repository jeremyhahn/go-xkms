- **CA RPCs (`GetCACertificate`, `SignCSR`, `IssueCertificate`,
  `RevokeCertificate`, `GenerateCRL`, `IsRevoked`, and the TCG
  EK/AK/enroll/sign-CSR variants) now work over `unix://`, `grpc://` and
  `grpcs://`, not only REST.** `pkg/api/grpc.Service`'s CA and CA-bundle
  servicers were package-level globals (`SetCA`/`GetCA`,
  `SetCABundler`/`GetCABundler`) that no production composition root ever
  called, so these RPCs always answered `codes.Unavailable` regardless of
  whether a CA was configured — only the REST transport, which reads
  `Config.CA` per `*Server`, actually worked. They are now per-`Service`
  state (`ca any`, `caBundler CABundler` fields) set through instance
  methods `(*Service).SetCA` / `(*Service).SetCABundler`, mirroring the
  existing `SetSSHClient` pattern. `pkg/server`'s Unix listener
  (`unix.GRPCConfig.CA`/`CABundler`, wired in `startUnix`) and
  `pkg/apimodule.Module`'s unified-server gRPC surface (`Module.keystore`,
  wired whenever the resolved `XKMSService.CA() != nil`) now forward the
  configured CA under the same condition REST's `buildRESTConfig` uses.
  **BREAKING for any binary embedding `pkg/api/grpc.Service` directly**: the
  removed package-level `SetCA`, `GetCA`, `SetCABundler`, `GetCABundler`
  have no free-function replacement — call the instance methods on the
  constructed `*Service` instead. (go-xkms#951)
