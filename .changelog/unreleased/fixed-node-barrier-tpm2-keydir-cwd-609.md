- **The TPM2 node-barrier key directory can no longer resolve relative to
  the process's working directory.** `resolveNodeSeal` and `initTPM2Backend`
  both derived the TPM2-sealed key directory as `Storage.Path + "/tpm2-keys"`
  with no guard on an empty `Storage.Path`; a caller that constructs
  `*config.Config` programmatically (embedded/library use of `pkg/server`,
  which never runs `config.Config.Validate`) got the cwd-relative path
  `tpm2-keys`, writing TPM key material wherever the process happened to be
  started from. Both call sites now share one
  `Server.resolveTPM2KeyDir` helper that fails closed with a typed
  `*ErrConfigRequired{Field: "storage.path", Backend: "tpm2"}` (wrapped in
  `*NodeSealError` from `resolveNodeSeal`, in `*ErrBackendCreate` from
  `initTPM2Backend`) when `Storage.Path` is unset, instead of ever writing
  key material under the working directory. Files: `pkg/server/node_seal.go`,
  `pkg/server/backend_tpm2.go`. Fixes go-xkms#609.
