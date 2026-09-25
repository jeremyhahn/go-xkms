- **ACME client deploy validation failures are typed sentinels.**
  `ErrDeployFailed` now wraps `ErrDeployConfigNil`, `ErrDeployCertPEMEmpty`,
  `ErrDeployCertPathEmpty`, `ErrDeployKeyPathEmpty` or `ErrDeployKeyPEMEmpty`,
  so callers can match with `errors.Is` instead of error text. (go-xkms#895,
  #980)
