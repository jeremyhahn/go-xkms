# Web console: SSH Trust view (epic #1443, lane suid)

## Gap

xkms stores host-key pins (known hosts) and authorized_keys entries per scope
and owner, and the REST verbs under `/xkms/v1/ssh` plus the TS SDK methods on
`getSDKClient().ssh` exist on main. The console's SshView calls only the key
verbs: no view lists, pins, verifies or removes a known host, or adds,
verifies or removes an authorized key.

## The view

`web/app/src/views/SshTrustView.svelte`, route `#/ssh/trust`, titled
"SSH Trust":

- Scope and owner fields with a Load button; both lists reload on Load.
- Known hosts panel: table (host, algorithm, fingerprint, added time), add
  form (host, fingerprint, algorithm), verify form (host, fingerprint; a 409
  shows a mismatch alert with the server message), Remove with a confirm
  modal naming the host.
- Authorized keys panel: table (name, comment, options), add form (name,
  line, comma-separated options, omitted when empty), verify form
  (fingerprint; names the matched entry), Remove with a confirm modal.
- Load errors show an `Alert`; remove errors show an error toast and keep
  the row.

## Wiring (one added line per place)

Lanes suia (Signing Keys), suib (Seal) and suic (Key Versions) touch the
same files. This lane adds exactly one line in each place and changes no
other line, so the merges are trivial:

- `router.svelte.ts`: `| "sshTrust"` in `RouteName`; `"/ssh/trust": "sshTrust",` in the path map.
- `App.svelte`: one import line, one dispatch line.
- `nav.ts`: one Security entry directly after SSH (capability `ssh`,
  requires `ssh:read`, icon `Fingerprint`).

## Tests

`web/app/test/view3_ssh_trust.test.ts` (test commit before the feat
commit, ruling 286): mount and Load, known-host add/remove/cancel/verify
match/409 mismatch, authorized-key add (options split)/remove/verify, list
error alert, remove error toast keeps the row.

## Checks

sdk/ts build, web/app npm ci, the new vitest file, `npm test`,
`npm run check`, vite build, `go test -race ./pkg/api/rest/`, sdk/go build,
`make lint`. Baseline failures on main (theme localStorage under Node 26,
view1/view2 svelte-auth tests, UsersView.svelte:121 svelte-check) are not
fixed here.

## Follow-ups (out of scope)

- A link from SshView to SSH Trust.
- An emit helper (`emitAuthorizedKey`) in the view.

## Results

- sdk/ts `npm ci && npm run build`: pass (the build rewrites the tracked sdk/ts/dist; restored, nothing committed).
- web/app `npm ci`: pass.
- `npx vitest run test/view3_ssh_trust.test.ts`: 13/13 pass.
- `npm test`: pass apart from baseline (store_theme_extra and theme localStorage tests; view1_login and view2_register svelte-auth tests).
- `npm run check`: 0 errors once sdk/ts/svelte-auth has `npm ci`; without it, the svelte-auth module errors and UsersView.svelte:121 role/roles (baseline).
- `npx vite build`: pass once sdk/ts/svelte-auth has `npm ci` (without it, rollup cannot resolve `@go-xkms/sdk` from svelte-auth/src/provider.ts).
- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./pkg/api/rest/`: pass.
- `cd sdk/go && go build ./...`: pass.
- `make lint`: pass.
