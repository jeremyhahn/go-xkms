---
name: xkey-agent
description: "Use every xKey identity and access function from the CLI: website logins (FIDO2/WebAuthn, passwords, TOTP, OIDC), secrets, SSH, PIV and certificates, the CA, trust, TPM, device pairing, backup, and the barrier and PINs that protect them."
---

# xKey for agents

xKey is a hardware-backed identity and credential vault. It is a virtual FIDO2 security key and smartcard, a password and TOTP store, an SSH key and host-key manager, a PIV and certificate toolkit, and a client of the xkmsd key-management server. You have full control of your own xKey instance and can use every command below. The xkmsd server's roles and permissions decide what you may do, and a refused operation returns a typed error.

Mechanics that apply everywhere:

- Home is `~/.xkey`. `XKEY_HOME` overrides it, and is what makes an xKey instance yours: every path — data, config, barrier, and the IPC socket a bare command connects to — resolves relative to it. Data lives in `<home>/data`, which `XKEY_DATA_DIR` overrides (as does `--data-dir` on `barrier` and `pin`). The config file is `~/.config/xkey/xkey.yaml` unless you pass `--config`. You can set any config key as an `XKEY_`-prefixed environment variable.
- Every command accepts these global flags: `--xkmsd-url` (unix://, grpc://, grpcs://, https://, quic://, or `XKMSD_URL`), `--backend software|tpm2|pkcs11`, `--log-level`, `--log-file`, and `--socket` (or `XKEY_IPC_SOCKET`) to name the IPC socket explicitly instead of deriving it from `XKEY_HOME`. `XKMSD_TOKEN` supplies a bearer token and `XKMSD_TLS_CA` the CA bundle for TLS transports.
- `ps` shows argv to every process on the host, so no `xkey` command accepts a secret as a flag value: no `--password`, `--pin`, `--secret`, `--value`, `--key` or `--barrier-password`. Every secret-bearing flag instead has a `-stdin` boolean form that reads the value from standard input (e.g. `--pin-stdin`/`XKEY_PIN`, `--so-pin-stdin`/`XKEY_SO_PIN`, `--password-stdin`/`XKEY_STATIC_PASSWORD`, `--secret-stdin`/`XKEY_OATH_SECRET`, `--value-stdin`/`XKEY_PLATFORM_STORE_VALUE`, `--key-stdin`/`XKEY_BACKUP_KEY`, `--barrier-password-stdin`/`XKEY_BARRIER_PASSWORD`), plus a `--barrier-password-file` where a file path applies. Standard input is one stream, so only one secret per invocation may come from it — supply any others via environment variable or file.
- Daemons (`fido2`, `extension serve`, `agent start`, `device listen`, `usb device start`) run in the foreground. Start them in the background and check them with their `status` verb.
- `/dev/uhid`, LUKS, USB-image and TPM-clear operations need root. Run them with `sudo`.

## Running as one of several instances on this host

Every agent gets its own xKey instance. Instances sharing a host and a UID are
distinguished only by `XKEY_HOME` — set it to a private directory before
running any xKey command, and nothing else changes: barrier, PINs, password
and OATH stores, PIV, and the IPC socket a bare command connects to all
resolve relative to it.

```bash
export XKEY_HOME=~/agents/agent-a/.xkey
xkey barrier init --strategy tpm2
xkey fido2 start --storage barrier --barrier-password-file <file> &
```

The IPC socket defaults to `<XKEY_HOME>/run/xkey.sock` (or, only when that path
would not fit a Unix domain socket, a runtime-directory path keyed by a hash
of `XKEY_HOME` — you will not need to know which case you are in). `--socket
<path>` or `XKEY_IPC_SOCKET` always overrides the derived default, including
over `XKEY_HOME`, so an explicit value follows you even if `XKEY_HOME` is
wrong or unset.

**Verify you are talking to your own instance**, not another agent's, before
trusting a command's output:

```bash
echo "$XKEY_HOME"                    # the instance your environment names
xkey fido2 status                    # prints "Socket:  <path>" it actually used
xkey pin status --json | jq -r .source_location   # ditto for pin/password/barrier status
```

Compare the printed socket or `source_location` against `<XKEY_HOME>/run/xkey.sock`
(or your own explicit `--socket`). A mismatch means the command reached a
different instance's daemon, not yours — most often because `XKEY_HOME` was
unset or pointed somewhere unexpected in the calling shell.

**Pairing a browser profile with your instance.** `xkey extension install
chrome --profile-dir <chrome-user-data-dir>` installs a native-messaging
manifest scoped to one Chrome profile instead of the OS-wide default every
profile on the host shares. Use the same directory you start Chrome with
(`chrome --user-data-dir=<dir>`): Chrome resolves native-messaging manifests
relative to it, so a distinct `--user-data-dir` gets a manifest no other
profile sees. The manifest launches a small generated script under your
instance's home (`<XKEY_HOME>/run/extension-host-launcher.sh`) that pins the
native messaging host it starts to your instance, regardless of which user or
environment Chrome itself runs under — this is what lets two agents sharing a
UID each pair their own Chrome profile with their own xKey instance.
`xkey extension uninstall chrome --profile-dir <dir>` removes it.
`--profile-dir` requires the `chrome` argument explicitly: Firefox has no
per-profile manifest location to install into. Installing without
`--profile-dir` keeps working exactly as before, for the common case of one
xKey instance per host.

## Provision an agent instance

`xkey provision --agent <name>` runs the whole first-time setup above —
barrier init, the host PIN service, the FIDO2 authenticator's Security
Officer PIN, all four primary PIV slots, and an SSH key — in one
non-interactive call, against one target home:

```bash
export XKEY_SO_PIN="$SO_PIN"
export XKEY_BARRIER_PASSWORD="$BARRIER_PASSWORD"
printf '%s' "$USER_PIN" | xkey provision --home ~/agents/agent-a/.xkey \
    --agent agent-a --pin-stdin
```

A target home is required, explicitly: `--home`, or an inherited
`XKEY_HOME`. There is no fallback to xKey's own default home resolution —
provisioning into your own default `~/.xkey` by accident is exactly what
this refuses to do.

It takes three separate secrets, each through the input xKey already uses
for it elsewhere — never one standing in for another: the user PIN
(`--pin-stdin`/`XKEY_PIN`) becomes the host PIN service's User PIN; the SO
PIN (`--so-pin-stdin`/`XKEY_SO_PIN`) becomes both the host PIN service's SO
PIN and the FIDO2 authenticator's own, separate Security Officer PIN; the
barrier password (`--barrier-password-stdin`/`--barrier-password-file`/
`XKEY_BARRIER_PASSWORD`) initializes the barrier. Making the SO PIN equal
the user PIN would erase the separation the host PIN service exists to
enforce (the SO can reset or unblock the user; the user cannot reset the
SO), so all three are required and a missing one refuses by name. Standard
input is one stream, so only one of the three may read from it — supply the
other two via file or environment variable.

Re-running against an already-provisioned home refuses unless you pass
`--force`, in which case it completes whatever it still can (PIN, FIDO2,
PIV) and reports the SSH step as skipped, since the SSH store refuses every
operation once a barrier exists and the CLI has no barrier-unlock flow of
its own.

Add `--chrome-profile-dir <dir>` to also pair a Chrome profile with this
instance in the same call, and `--json` for a machine-readable report. The
report names the socket, the FIDO2 AAGUID and token state, the PIV slots
that were set up, and the SSH public key and fingerprint — never a secret.

## Get started: config, unseal, unlock

```bash
xkey version; xkey config init      # default config file (--force overwrites)
xkey config show                    # effective config as YAML; config path lists search order
xkey barrier init --strategy tpm2   # first time only: software|tpm2|pkcs11 (default auto-detect)
# pkcs11: add --pkcs11-library <module> --pkcs11-token <label>; the token PIN is the first stdin line, sealed to the TPM
xkey barrier status --json          # sealed? which strategy?
xkey barrier unseal --auto          # TPM-policy auto-unseal, reads no secret
xkey barrier unseal < "$BARRIER_PASSWORD_FILE"   # otherwise, password on stdin
printf '%s' "$PIN" | xkey unlock --pin-stdin      # unlock a running daemon (app lock + barrier)
xkey barrier seal                   # lock the barrier again
```

The barrier encrypts every local store at rest. When a running daemon answers CTAP2 calls with "operation denied", it is locked, and `unlock` releases it. After 8 wrong PINs it stays locked until `xkey pin reset-lockout` is run.

## PINs

The host PIN service has an SO PIN (admin) and a User PIN (daily use). The virtual FIDO2 authenticator has its own, separate SO PIN (see the FIDO2 section).

```bash
xkey pin status --json
xkey pin set-so                     # first SO PIN (prompts, minimum 6 characters)
xkey pin set-user                   # needs the SO PIN
xkey pin change-user
xkey pin change-so
xkey pin verify --type user         # or --type so
xkey pin reset-lockout              # needs the SO PIN
```

## Log in to websites

**Passkeys and security keys (FIDO2/WebAuthn).** Run xKey as a virtual authenticator and approve user presence with `touch`.

```bash
sudo xkey fido2 start --storage barrier --barrier-password-file <file> --backend tpm2 --notify log &
xkey fido2 status                   # exits non-zero when no daemon is running
xkey touch                          # approve the pending WebAuthn presence request
xkey fido2 start --cdp --cdp-port 9222 --storage barrier --barrier-password-file <file> &
```

The `--cdp` form is for automated Chrome and replaces the USB device. xKey connects to a Chrome instance started with remote debugging on `--cdp-port`, loads its stored credentials into Chrome, and saves new credentials back to `--storage`. The default `--storage memory` loses credentials on exit. Other start flags are `--backend software|tpm2|phone`, `--attestation none|packed|tpm`, `--require-touch`, `--set-pin-stdin` (sets the first PIN only, read from standard input) and `--default-password`.

FIDO2 administration (stop the daemon before the SO operations):

```bash
xkey fido2 init-token               # set the authenticator's SO PIN (once)
xkey fido2 change-so-pin
xkey fido2 provision-attestation --profile <profile> --validity-days 730   # CA-issued attestation, --rotate replaces it
xkey fido2 profile set --transports usb,internal --enterprise-attestation   # profile show reads it back
xkey fido2 policy set --rpid example.com --uv required    # also --up, --attestation, --enterprise, --blocked
xkey fido2 policy list
xkey fido2 policy delete --rpid example.com         # also: policy get --rpid <rpid>
```

**Browser and extension.** Launch a browser that trusts the xKey trust store, and connect the extension for autofill.

```bash
xkey browser launch --include-extensions [url]            # --browser <path>, --extension <id>
xkey extension install all          # native-messaging manifest: chrome|firefox|all
xkey extension status
xkey extension serve --barrier-password-file <file> --auto-lock-minutes 15 &   # headless autofill server
xkey extension unpair               # forget the paired extension (pair-status shows it)
xkey extension uninstall all
```

With a tpm2 barrier, `extension serve` tries TPM auto-unseal first. `--so-pin-stdin` honours a sealed enterprise policy.

**Typed passwords.** `xkey password type [name]` or `xkey touch --password <name>` types a stored password through the virtual keyboard of a running `fido2` daemon.

**OIDC and SSO.** Log in with the authorization-code flow and PKCE against any OIDC provider, or sign in to the AWS console.

```bash
xkey oidc providers add --name okta --issuer https://id.example.com --client-id <id> --scopes openid,profile,email
xkey oidc login --provider okta --no-browser        # print the URL instead of opening a browser
xkey oidc login --issuer https://id.example.com --client-id <id> --exec ./on-login.sh --auto-refresh 2700 --background
xkey oidc token --show-full
xkey oidc refresh --provider okta
xkey oidc status                    # running background refreshers
xkey oidc stop [provider]           # or --all
xkey oidc logout --all
xkey oidc providers remove [name]   # providers list shows them
xkey oidc aws --region us-east-1 --profile prod --output aws-credentials --no-browser
```

The `--exec` script receives the tokens as JSON on stdin and as `OIDC_*` environment variables.

## Authenticate to xkmsd servers

```bash
xkey auth register --server https://kms.example.com:8443 --email agent@example.com --setup-token <token> --pin-stdin
xkey auth register --server https://kms.example.com:8443 --email agent@example.com --spki-pin <hex>
xkey auth login --server https://kms.example.com:8443 --email agent@example.com --pin-stdin   # WebAuthn via fido2
xkey auth login --server https://kms.example.com:8443 --email agent@example.com --piv --slot 9a --backend pkcs11
xkey auth status
xkey auth token --server https://kms.example.com:8443     # raw JWT on stdout
xkey auth refresh --server https://kms.example.com:8443   # only PIV sessions carry refresh tokens
xkey auth logout --server https://kms.example.com:8443
```

WebAuthn login needs a CTAP2 authenticator, and a running `xkey fido2` counts as one. PIV login uses the slot key over mTLS. PIV keys made with `--backend software` exist only in the process that generated them, so use `pkcs11` for a persistent key.

## Passwords

```bash
xkey password add --name GitHubWork --username agent --url https://github.com --generate --length 32
XKEY_STATIC_PASSWORD="$DB_PASS" xkey password add --name DatabaseProd --title "Prod DB" --notes "rotated monthly"
xkey password list                  # values masked
xkey password list --source disk --show-passwords
xkey password get [name]            # prints only the value, for piping
xkey password remove --force [name...]
xkey password status
```

The browser extension matches entries to sites by `--url`. The `unlock`, `lock`, `access-mode` and `vault` verbs act on an xkmsd session and need `--xkmsd-url`. Personal entries unlock with the caller's own vault passphrase, never the user PIN. There is no `--password` or `--passphrase` value flag -- a value on the command line is visible to every other process on the host via `ps` -- so the password comes from `--password-stdin`/`XKEY_STATIC_PASSWORD`, the vault passphrase from `--passphrase-stdin`/`XKEY_VAULT_PASSPHRASE`, and the recovery code from `--recovery-code-stdin`/`XKEY_VAULT_RECOVERY_CODE`.

```bash
xkey password access-mode --mode session_based --xkmsd-url <url>   # or pin_per_operation
XKEY_VAULT_PASSPHRASE="$PASSPHRASE" xkey password vault enroll --label ci --xkmsd-url <url>   # first time: prints the recovery code ONCE
XKEY_VAULT_PASSPHRASE="$PASSPHRASE" xkey password unlock --xkmsd-url <url>
xkey password vault status --xkmsd-url <url>
xkey password lock --xkmsd-url <url>
xkey password status --source xkmsd --xkmsd-url <url>
```

Storing the recovery code that `vault enroll` and `vault recover` print is a human-only step: it is shown exactly once.

## Secrets (platform store)

The platform store holds key-value secrets that xkmsd seals with TPM2, PKCS#11 or software.

```bash
xkey platform-store put <name> --file <path>              # or --value-stdin / XKEY_PLATFORM_STORE_VALUE
xkey platform-store get <name> --output <path>      # stdout by default
xkey platform-store list
xkey platform-store delete <name>
xkey platform-store reseal --all                    # after key rotation or a TPM ownership change
xkey platform-store status
```

## One-time codes (TOTP/HOTP)

```bash
xkey oath add --uri "otpauth://totp/..."            # or --name --issuer --secret-stdin/XKEY_OATH_SECRET --type totp|hotp --digits --period --algorithm
xkey oath scan --yes                                # read an otpauth QR code from the screen
xkey oath generate [name]                           # or --all
xkey oath list --uri                                # --secrets shows the shared secrets
xkey oath remove --force [name...]
```

Add `--barrier-password-file <file>` when the store is barrier-encrypted. Phone sync is covered in the Devices section.

## SSH

xKey generates and holds the keys, locally or on xkmsd (with `--server` or `XKMSD_URL`), and serves them through an in-process SSH agent. The private key never leaves its backend.

```bash
xkey ssh keys generate --name deploy --type ed25519 --backend tpm2 --comment agent
xkey ssh keys import --name legacy [file]           # PEM private key, passphrase prompted
xkey ssh keys list
xkey ssh keys export --name deploy                  # authorized_keys line to install on servers
xkey ssh keys delete --name deploy
xkey ssh profile add --name prod --host db.example.com --user ops --key deploy --folder work/prod
xkey ssh profile list --folder work
xkey ssh profile remove [name]
xkey ssh connect --key deploy [profile|user@host]   # runs the system ssh client
xkey ssh console --key deploy [profile|user@host]   # in-process PTY console
xkey ssh host-keys add --host db.example.com --key "ssh-ed25519 AAAA..."   # or --file
xkey ssh host-keys list
xkey ssh host-keys remove --host db.example.com
xkey ssh authorized-keys add --name laptop [line]
xkey ssh authorized-keys list
xkey ssh authorized-keys remove --name laptop
xkey ssh local hosts                # ssh_config Host aliases
xkey ssh local keys                 # ssh-agent and ~/.ssh identities
xkey ssh sessions list              # persisted console sessions
```

`keys get`, `profile get`, `profile mv` and `sessions remove` inspect and tidy single entries. `--owner` and `--scope tenant|user|service` pick whose keys a command acts on. The `connect --local`, `--identity` and `--ssh-config-alias` flags use your own ssh-agent identities instead. `--known-hosts-policy barrier|system|both` sets where host-key pins are recorded.

## PIV smartcard and client certificates

Slots are 9a (authentication), 9c (signature), 9d (key management) and 9e (card authentication). Group flags: `--backend software|tpm2|pkcs11`, `--pkcs11-library`, `--pkcs11-token`, `--pkcs11-pin` and `--storage-path`.

```bash
xkey piv generate <slot> --algorithm ECCP256 --pin-policy once --touch-policy never --output-format csr -o slot.csr
xkey piv csr <slot> --cn agent --san-dns host.example.com -o req.csr
xkey piv import <slot> <cert-file>                  # checks that the cert matches the slot key
xkey piv store <slot> <cert-file>
xkey piv list
xkey piv show <slot>
xkey piv export <slot> --format pem --output cert.pem
xkey piv delete <slot> --force
xkey piv status
xkey cert request --server <url> --cn agent --profile client --slot 9a   # server CA signs, cert is stored in the slot
xkey cert show --slot 9a
xkey cert export --slot 9a --file client.pem
```

For PIV slots on a paired phone, use `piv phone-list`, `piv phone-generate <slot>`, `piv phone-pull-cert <slot>` and `piv phone-push-cert <slot> <cert-file>`. Each takes `--device`.

`xkey usb device start --device-backend tpm2 --transport uhid` presents xKey as a CCID smartcard reader with PIV and OpenPGP applets, for OpenSC, GPG and VMs. Check and stop it with `usb device status` and `usb device stop`.

## Certificate authority (xkmsd)

```bash
xkey ca info
xkey ca bundle --output ca.pem
xkey ca issue --profile server --cn host.example.com --san DNS:host.example.com --algorithm ecdsa-p256 --output host.pem
xkey ca sign-csr --csr req.csr --profile client --validity-days 90 --output cert.pem
xkey ca revoke <serial> --reason key-compromise
xkey ca check-revocation <serial>
xkey ca crl --output crl.pem
```

## Trust store

```bash
xkey trust bootstrap --method dane,noise,spki,direct   # fetch and verify a CA bundle
xkey trust import-platform <host:port> --spki-pin <hex>
xkey trust fetch <url> --spki-pin <hex> --install-system
xkey trust add <pem-file> --purpose user-ca --source manual
xkey trust list
xkey trust show <fingerprint>
xkey trust classify <fingerprint> --purpose <purpose>
xkey trust install <fingerprint>                     # into the OS trust store (trust uninstall reverses)
xkey trust remove <fingerprint>
```

Direct fetches never trust on first use. Get the SPKI pin out of band.

## TPM and auto-unseal policy

```bash
xkey tpm info
xkey tpm status
xkey tpm pcrs --bank sha256 --indices 0,7
xkey tpm install --golden-pcrs 0,1,2,7               # non-destructive, keeps the manufacturer EK
xkey tpm quote --pcrs 0,1,7 --nonce <hex> --output quote.bin
xkey tpm ek export --output ek.pem                   # --ec for the EC EK; ek show prints it
xkey tpm ek backup --output <dir>
xkey tpm ek restore --input ek.pem
xkey tpm iak create --template ecc256
xkey tpm iak csr --subject "CN=device-001" --output iak.csr
xkey tpm iak export --output iak.pem                 # iak show prints key and cert
xkey tpm idevid create --model <model> --serial <serial>
xkey tpm idevid csr --subject "CN=device-001" --output idevid.csr
xkey tpm idevid csr export --organization Example --output idevid.csr
xkey tpm idevid cert import --cert idevid.pem
xkey tpm idevid export --output idevid.pem           # idevid show prints key and cert
xkey tpm provision --confirm                         # clears the TPM, the manufacturer EK cert is lost
xkey tpm clear --hierarchy lockout --yes
```

TPM group flags are `--device`, `--simulator`, `--hierarchy-auth` and `-o json`. Named TPM policies bind keys and sealed data to a PCR state the TPM enforces; the built-in `platform` policy (PCR 16 or the object's password) is the default. With `--xkmsd-url` (or `XKMSD_URL`) they run on the server, otherwise on this host's TPM:

```bash
xkey tpm policy create <name> --pcrs 0,7 --bank sha256   # values are read from the TPM
xkey tpm policy list                                     # object counts per policy
xkey tpm policy verify <name>                            # exits non-zero when the PCRs changed
xkey tpm policy update <name>                            # re-capture + re-approve after a known-good update (no re-key)
xkey tpm policy revoke <name>
xkey tpm policy objects <name>
xkey tpm policy delete <name>                            # refused, listing them, while objects are bound
echo "$BARRIER_PASSWORD" | xkey tpm policy auto-unseal <name>   # seals the barrier password under it
xkey tpm policy auto-unseal --off
xkey tpm authority rotate
```

## Devices: phones and remote agents

Phones pair over BLE through a Noise channel with hardware attestation. A paired phone can hold keys, sign with biometrics and sync stores.

```bash
xkey device scan --timeout 30s
xkey device pair --device "<name>" --barrier-password-file <file>
xkey device list
xkey device status --device "<name>"
xkey device device-info [device-name]
xkey device attest-device --device "<name>" --barrier-password-file <file>
xkey device attest <key-id> --device "<name>"
xkey device enroll-phone --ca xkms --validity 720h    # Android-attested LDevID for the phone
xkey device listen --attestation-mode tpm2 &          # accept phone-initiated requests (--tpm-enrollment, --allow-sync)
xkey device relay --device "<name>"                   # TCP counterpart of listen; 127.0.0.1:8444 unless --listen
xkey device share <backend> <key-id> --device "<name>" --label deploy
xkey device import <key-id> --device "<name>" --backend software
xkey device share-policy set <backend> <key-id> --allow --share-public
xkey device share-policy remove <backend> <key-id>   # share-policy list shows all
xkey device sync --device "<name>" --barrier-password-file <file>   # --oath, --passwords, --trust-store, --dry-run
xkey device sync-status --device "<name>" --barrier-password-file <file>   # one-way: sync-pull, sync-push
xkey oath sync --device "<name>"                      # also oath pull and oath push <name-or-id>
xkey device unpair <device-name> --force
```

For remote agents, a master machine runs the agent server. It proxies PKCS#11, FIDO2, PIV, crypto and SSH requests from enrolled machines, and key material stays on the master. The xkmsd CA issues the agent certificates.

```bash
xkey agent start --xkmsd-url <url> --listen :9443 --tls-cert server.pem --tls-key server-key.pem &
xkey agent status
xkey agent stop
xkey agent code                                        # one-time enrollment code for a new machine
xkey agent pending                                     # enrollment requests awaiting a decision
xkey agent approve <request-id>                        # or: xkey agent reject <request-id>
xkey agent remove <agent-id>                           # revoke an enrolled agent
xkey device enroll --server master.example.com:9443 --xkmsd-url <url> --name build-01
xkey device connect <address>
```

## Backup and restore

A backup holds the trust store, OATH credentials and passwords, sealed with XChaCha20-Poly1305. A backup password (Argon2id, salted) comes from `--password-stdin` or `XKEY_BACKUP_PASSWORD`; there is no `--password` flag. Version 1 (unsalted) backups are refused.

```bash
xkey backup create --barrier-password-file <file> --output ~/xkey.xkb   # no password: prints a random hex key
xkey backup create --password-stdin --output ~/xkey.xkb < pw.txt
xkey backup contents <file> --password-stdin < pw.txt
XKEY_BACKUP_KEY=<hex> xkey backup contents <file>    # backup list shows ~/.xkey/backups
XKEY_BACKUP_KEY=<hex> xkey backup restore <file> --barrier-password-file <file>
xkey backup to-device --device "<name>" --barrier-password-file <file>
XKEY_BACKUP_KEY=<hex> xkey backup from-device --device "<name>" --barrier-password-file <file>
```

## Encrypted storage: LUKS2 and USB

```bash
sudo xkey luks2 seal --size 500M --unseal            # move ~/.xkey into ~/.xkey.luks
sudo xkey luks2 unseal
sudo xkey luks2 lock
sudo xkey luks2 import-data --source ~/.xkey --cleanup --backup
sudo xkey luks2 migrate --size 1G --wipe
sudo xkey luks2 wipe --standard dod3 --force
sudo xkey usb create <device-or-image> --size 4G      # portable xKey: FAT32 binaries + LUKS2 data
xkey usb status [device-or-image]
sudo xkey usb update <device-or-image>
```

Complete flag reference: reference/cli.md
