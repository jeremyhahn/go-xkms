# Web console: SSH Sign view (row web-console, docs/SPEC.md:139, lane sujl)

## Gap

Main serves POST `/xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign` (ssh:write,
pkg/api/rest/routes.go:600) and sdk/ts has `ssh.sign`, but no console view calls
it: SshView.svelte only lists, generates and deletes keys.

## Slice

- Helper `web/app/src/lib/sshSign.ts`: `signLabel(key)`, `signDigest(message, isBase64)`
  (null on an empty message or a base64 input that fails `isB64`), `signWithKey(key, digest)`
  over `getSDKClient().ssh.sign`.
- View `web/app/src/views/SshSignView.svelte`: PageHeader "SSH Sign"; a card with the key
  select (from `ssh.listKeys` on mount), the message textarea, a "Message is base64"
  checkbox and the Sign button (busy state); a Result card with format, blob and rest
  (when present) in monospace with copy buttons; Alert for errors. The digest field
  holds the raw message bytes (the key's signer hashes them).
- Route `#/ssh/sign` (`sshSign`), nav entry "SSH Sign" after SSH (capability ssh,
  requires ssh:write).
- One added line per place in nav.ts, two in router.svelte.ts, two in App.svelte; no
  other change there.

## Tests

`web/app/test/view3_ssh_sign.test.ts`: list on mount, sign text, sign base64 (valid and
invalid), rest line, empty inputs keep Sign disabled, errors from listKeys and sign.

## Checks

sdk/ts build (dist restored), svelte-auth and web/app npm ci, the new vitest file, the
web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

Key generation, import, deletion, export, known hosts, authorized keys, certificates,
an interactive SSH console, SshView.svelte, Go code, sdk/ts, docs/SPEC.md.

## Results

- sdk/ts npm ci + build: pass (sdk/ts/dist restored).
- svelte-auth npm ci: pass. web/app npm ci: pass.
- vitest test/view3_ssh_sign.test.ts: pass (8 tests).
- web/app npm test: pass (51 files, 420 tests).
- npm run check (svelte-check): pass, 0 errors.
- vite build: pass.
- go test -race pkg/api/rest (codec tags): pass.
- sdk/go go build ./...: pass.
- make lint: not run to completion; the typecheck of pkg/api/grpc hit "no space left
  on device" (lane disk /dev/sdc1 at 99%, 3.4G free); a disk failure, not a lint finding.
