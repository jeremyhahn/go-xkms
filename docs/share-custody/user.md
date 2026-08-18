# Share Custody — User Guide

> **Status: NORMATIVE** · Feature: `share-custody` · Repo: `go-xkms` · Last verified: 2026-08-19

## The idea

The barrier's root key is split into N pieces. Any M of them reconstruct it;
any M-1 reveal nothing. So no single person can open the barrier alone, and
losing one holder does not lose the key.

There are two roles: the **operator** who organises the split, and the
**custodians** who hold the pieces.

## Choosing M and N

This is the only decision that matters and it cannot be changed later without
rekeying the barrier.

- **M** is security. M-1 people colluding learn nothing.
- **N − M** is availability. That many shares can be lost, forgotten, or
  unreachable without consequence.

3-of-5 is a reasonable default for a small team: any three can unseal, any two
cannot, and two people can be unavailable. **M = N is a trap** — it is maximum
security and a guaranteed outage the first time someone leaves.

## Operator: setting up

```
xkmsctl custodian create --name "Production barrier" --threshold 3 --total 5 \
    --purpose "root key custody"

xkmsctl custodian add-member --group-id grp-1 --user-id alice --username "Alice" --method encrypted
xkmsctl custodian add-member --group-id grp-1 --user-id bob   --username "Bob"   --method encrypted
# … three more

xkmsctl custodian distribute --group-id grp-1
```

`distribute` is the moment the split becomes real, and it **happens once**.
There is no command that reissues a share to someone who lost theirs.

`--method encrypted` delivers to the member's key. `--method manual` means you
move it yourself, out of band — and it is your responsibility that "out of band"
does not mean a chat message that lives forever.

## Custodian: holding a share

Keep the share somewhere that will still exist, and still be findable, in a
year. Somewhere different from where the other custodians keep theirs — the
threshold only helps if the shares are actually separated.

```
xkmsctl share list -o json
```

## Custodian: contributing to an unseal

```
xkmsctl share submit --group-id grp-1 --share-index 2 --file alice.share
```

You do not need to coordinate a time. Each custodian submits independently and
the server counts toward M; the barrier opens when the third one arrives.

Watch progress:

```
xkmsctl share status --group-id grp-1 -o json
```

"Below threshold" is not an error. It means the collection is working and not
finished.

There is a time limit — quorum sessions expire. If a collection stalls for long
enough, the accumulated shares are discarded and everyone submits again. That is
deliberate: a half-open quorum should not sit there indefinitely.

## Serving more than one deployment

If you hold shares for two servers, you have index 2 twice. That is why every
`get` and `delete` takes `--server-url` as well:

```
xkmsctl share get --server-url https://kms.example.com:8443 --group-id grp-1 --share-index 2
```

Submitting a share to the wrong server is rejected rather than silently
counted — but the addressing exists so the mistake is hard to make in the first
place.

## When someone leaves

Remove them from the group, but understand what that does and does not do:

```
xkmsctl custodian remove-member --group-id grp-1 --user-id alice
```

**They still have their share.** Removing a member, or even deleting the whole
group, does not reach into anyone's storage. The only thing that invalidates a
distributed share is rekeying the barrier:

```
xkmsctl barrier rekey --so-pin - --threshold 3 --total 5
```

Then distribute the new shares. Plan for the gap between those two steps.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "below threshold" | fewer than M shares have arrived | not an error — chase the remaining custodians |
| share rejected as invalid | corrupt or truncated bytes | check the file survived transport intact |
| share rejected — wrong group | it belongs to a different group or server | check `--server-url` and `--group-id` |
| "already submitted" | that index has already counted | it does not count twice; you need a *different* holder |
| quorum expired | the collection window elapsed | start over; everyone resubmits |
| old shares stopped working | someone rekeyed the barrier | redistribute |
| a custodian lost their share | it cannot be reissued | with M still reachable you are fine; below M, you need the barrier's recovery keys |
| a custodian lost their share and there are no recovery keys and you are below M | the root key is unrecoverable | this is what the barrier is; plan for it before it happens |

## Where to go next

- What the shares open: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- Where the first shares come from: [`../init-ceremony/user.md`](../init-ceremony/user.md)
- Holding shares on the desktop: [`../../xkey/docs/share-custody/user.md`](../../xkey/docs/share-custody/user.md)
