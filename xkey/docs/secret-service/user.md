# Secret Service — User Guide

> **Status: NORMATIVE** · Feature: `secret-service` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## What this is for

Letting ordinary Linux desktop tools — `git`, browsers, `secret-tool`, and
anything else that expects GNOME Keyring or KWallet — store and retrieve
passwords through xkey's own encrypted vault, instead of running a second
secret store alongside xkey.

## Prerequisites

- A barrier already initialized: `xkey barrier init` (see
  [`../seal/user.md`](../seal/user.md)).
- A D-Bus session bus — present on any normal desktop login session.

## Running the daemon

```
xkey secret-service
```

Leave it running (in a terminal, a systemd user service, or similar) for as
long as you want xkey to answer as the system's secret store. The first
time some client asks it to unlock, and no password was supplied up front,
it prompts on its own terminal:

```
Enter barrier password to unlock the secret service:
```

To avoid that prompt, supply the password up front:

```
xkey secret-service --barrier-password-file ~/.xkey/barrier-password
```

Keep that file's permissions restrictive (`chmod 600`) — anyone who can read
it can unlock your secret store.

## Locking and unlocking

There is one lock for everything this daemon exposes: the barrier itself.
Locking it (from another terminal: `xkey barrier seal`, or a client that
calls the Secret Service `Lock` method) locks every collection and item at
once; nothing sealed can be read until it is unlocked again — no session-bus
client, including a compromised one, can read a secret while it is locked.

## Using it with git

```
git config --global credential.helper libsecret
```

After that, the first `git push`/`pull` against a host you have not
authenticated to prompts once; the credential is then stored through xkey
and reused silently on every later request, exactly as it would be with
GNOME Keyring.

## Using it with secret-tool

```
secret-tool store --label="My API token" service myservice username me
# (prompts for the secret value on stdin)

secret-tool lookup service myservice username me

secret-tool clear service myservice username me
```

## What "collections" mean here

Every folder in xkey's password manager (see
[`../password/user.md`](../password/user.md)) is a Secret Service
"collection". The default collection (what most tools use when they do not
ask for one by name) is the root folder. Passwords you already stored
through the `xkey` password-manager CLI or GUI are visible to Secret
Service clients too — this is the same store, viewed through a different
protocol, not a separate copy.

## FIPS mode

Under `GODEBUG=fips140=only` (or a FIPS build), the encrypted D-Bus session
transport is unavailable; the daemon falls back to its unencrypted
transport instead. This is safe: that transport only ever crosses the local
D-Bus session bus on this machine, never a network.
