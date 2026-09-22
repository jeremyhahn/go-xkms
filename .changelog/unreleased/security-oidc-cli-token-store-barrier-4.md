- **`xkey oidc login`'s CLI token store now moves behind the go-qrdb barrier
  the same way the OATH, FIDO2, and Noise-key stores already do, and holds
  the access/refresh/ID tokens in mlocked protected memory while resident in
  the process (go-xkms#4). BREAKING: existing logins do not survive the
  upgrade — the CLI never reads the old plaintext `~/.xkey/tokens.json`
  format, and there is no migration; run `xkey oidc login` again.** The CLI's
  own hand-rolled plaintext JSON writer/reader (`storeToken`/`loadToken`/
  `saveTokenStore` over `os.WriteFile`) is deleted outright and replaced by
  `openOIDCTokenStore` (`xkey/cmd/xkey/cmd/oidc_token_store.go`), which
  reuses the CLI's one barrier-or-warn decision
  (`resolveSecretStoreBackend`, `barrier_store.go`): a barrier-encrypted
  `xkms.StorageBackend` when a barrier is initialized, or the historical
  unencrypted file with the one standard "unencrypted at rest" warning
  otherwise — never a second encryption scheme. An explicit `--token-store
  <path>` still bypasses barrier auto-detection and writes exactly that
  file, matching `xkey oath`'s `--store` override.

  `OIDCStoredToken.AccessToken`/`RefreshToken`/`IDToken` are no longer plain
  Go string fields: they live in `*secure.Buffer` (`sdk/go/secure`), reached
  through accessor/setter methods (`AccessToken()`, `SetAccessToken`, …),
  mirroring how `xkey/pkg/oath`'s `Credential` holds its shared secret.
  `Destroy()` wipes them; every command and the auto-refresh loop now calls
  it once the token is no longer needed.

  The `--background`/`--auto-refresh` worker (`runAutoRefresh`) opens its
  token store once, before the refresh loop starts, and reuses that same
  open store — and, for a barrier-backed store, the same unsealed barrier —
  on every tick, rather than reopening (and re-unsealing) it each interval.
  The detached background process forwards `--barrier-password-file` to
  itself when set, since it has no terminal to prompt on; a bare
  `--barrier-password` value is never forwarded on argv, to keep it out of
  `ps` output, and `XKEY_BARRIER_PASSWORD` reaches the child through normal
  environment inheritance instead.
