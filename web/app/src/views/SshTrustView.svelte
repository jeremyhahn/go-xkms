<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { SSHPin, SSHAuthorizedEntry, SSHAddKnownHostRequest, SSHAddAuthorizedKeyRequest } from "@go-xkms/sdk";

  // A confirm carries the displayed row's scope and owner, so editing the
  // Scope/Owner inputs before confirming never retargets the delete.
  type Confirm =
    | { kind: "host"; host: string; scope: string; owner: string }
    | { kind: "key"; name: string; scope: string; owner: string };
  // A verdict carries the snapshot of the inputs it was verified for and is
  // shown only while the inputs still equal it: an edit after a completed
  // verify hides the earlier verdict until the new inputs are verified.
  type Result = { ok: boolean; message: string; at: string };

  // Empty scope and owner list without a filter (every pin the caller may
  // read); pkg/scope accepts only tenant, user and service when one is set.
  let scope = $state("");
  let owner = $state("");
  let pins = $state<SSHPin[]>([]);
  let entries = $state<SSHAuthorizedEntry[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let confirm = $state<Confirm | null>(null);

  let hHost = $state("");
  let hPublicKey = $state("");
  let vHost = $state("");
  let vPublicKey = $state("");
  let hostResult = $state<Result | null>(null);

  let kName = $state("");
  let kLine = $state("");
  let kOptions = $state("");
  let kFingerprint = $state("");
  let keyResult = $state<Result | null>(null);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // XkmsApiError carries the HTTP status; a 409 verify is a fingerprint mismatch.
  function statusOf(e: unknown): number | undefined {
    return (e as { status?: number } | null)?.status;
  }

  // Each list and verify request carries a sequence number and a snapshot
  // of the inputs it was made for; a reply is applied only while both still
  // match. Scope, owner and the add inputs are frozen while a mutation runs.
  let listSeq = 0;
  let hostSeq = 0;
  let keySeq = 0;

  function filter(): [string | undefined, string | undefined] {
    return [scope.trim() === "" ? undefined : scope.trim(), owner.trim() === "" ? undefined : owner.trim()];
  }

  async function load(): Promise<void> {
    const mine = ++listSeq;
    const [s, o] = filter();
    const at = JSON.stringify([s, o]);
    const current = () => mine === listSeq && at === JSON.stringify(filter());
    loading = true;
    error = null;
    try {
      const ssh = getSDKClient().ssh;
      const [hosts, keys] = await Promise.all([ssh.listKnownHosts(s, o), ssh.listAuthorizedKeys(s, o)]);
      if (!current()) return;
      pins = hosts.items;
      entries = keys.items;
    } catch (e) {
      if (!current()) return;
      pins = [];
      entries = [];
      error = message(e);
    } finally {
      if (mine === listSeq) loading = false;
    }
  }

  async function addHost(): Promise<void> {
    busy = true;
    try {
      // The server derives the pin's fingerprint and algorithm from the key.
      const req: SSHAddKnownHostRequest = { scope, owner, host: hHost, public_key: hPublicKey.trim() };
      await getSDKClient().ssh.addKnownHost(req);
      showToast("success", `Pinned "${req.host}".`);
      hHost = ""; hPublicKey = "";
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  function hostInputs(): string {
    return JSON.stringify({ host: vHost, scope, owner, public_key: vPublicKey.trim() });
  }

  function keyInputs(): string {
    return JSON.stringify({ scope, owner, fingerprint: kFingerprint });
  }

  const shownHostResult = $derived(hostResult !== null && hostResult.at === hostInputs() ? hostResult : null);
  const shownKeyResult = $derived(keyResult !== null && keyResult.at === keyInputs() ? keyResult : null);

  async function verifyHost(): Promise<void> {
    const mine = ++hostSeq;
    const req = { host: vHost, scope, owner, public_key: vPublicKey.trim() };
    const at = hostInputs();
    const current = () => mine === hostSeq && at === hostInputs();
    hostResult = null;
    try {
      await getSDKClient().ssh.verifyKnownHost(req.host, { scope: req.scope, owner: req.owner, public_key: req.public_key });
      if (current()) hostResult = { ok: true, message: `Fingerprint matches the pin for ${req.host}.`, at };
    } catch (e) {
      if (!current()) return;
      if (statusOf(e) === 409) {
        hostResult = { ok: false, message: message(e), at };
      } else {
        showToast("error", message(e));
      }
    }
  }

  async function addKey(): Promise<void> {
    busy = true;
    try {
      const req: SSHAddAuthorizedKeyRequest = { scope, owner, name: kName, line: kLine };
      const options = kOptions.split(",").map((o) => o.trim()).filter((o) => o !== "");
      if (options.length > 0) req.options = options;
      await getSDKClient().ssh.addAuthorizedKey(req);
      showToast("success", `Authorized key "${req.name}" added.`);
      kName = ""; kLine = ""; kOptions = "";
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  async function verifyKey(): Promise<void> {
    const mine = ++keySeq;
    const req = { scope, owner, fingerprint: kFingerprint };
    const at = keyInputs();
    const current = () => mine === keySeq && at === keyInputs();
    keyResult = null;
    try {
      const matched = await getSDKClient().ssh.verifyAuthorizedKey(req);
      if (current()) keyResult = { ok: true, message: `Fingerprint matches ${matched.name}.`, at };
    } catch (e) {
      if (!current()) return;
      const status = statusOf(e);
      if (status === 409 || status === 404) {
        keyResult = { ok: false, message: message(e), at };
      } else {
        showToast("error", message(e));
      }
    }
  }

  async function remove(): Promise<void> {
    const c = confirm;
    if (c === null) return;
    busy = true;
    try {
      if (c.kind === "host") {
        await getSDKClient().ssh.removeKnownHost(c.host, c.scope, c.owner);
        showToast("success", `Pin for "${c.host}" removed.`);
      } else {
        await getSDKClient().ssh.removeAuthorizedKey(c.scope, c.owner, c.name);
        showToast("success", `Authorized key "${c.name}" removed.`);
      }
      confirm = null;
      await load();
    } catch (e) {
      confirm = null;
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  const confirmText = $derived(
    confirm === null
      ? ""
      : confirm.kind === "host"
        ? `Remove the pin for ${confirm.host}?`
        : `Remove the authorized key ${confirm.name}?`,
  );

  // Mount-time load is unfiltered; later loads are explicit (Load).
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="SSH Trust" subtitle="Known-host pins and authorized_keys entries" />

<div class="flex flex-wrap items-end gap-2 mb-4">
  <input class="input input-bordered input-sm" aria-label="Scope" placeholder="Scope (tenant, user, service)" bind:value={scope} disabled={busy} />
  <input class="input input-bordered input-sm" aria-label="Owner" placeholder="Owner" bind:value={owner} disabled={busy} />
  <button class="btn btn-sm" onclick={load} disabled={loading}>Load</button>
</div>

{#if error}
  <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
{/if}

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  <section class="mb-8" aria-labelledby="known-hosts-title">
    <h2 id="known-hosts-title" class="text-lg font-semibold mb-2">Known hosts</h2>
    <div class="overflow-x-auto">
      <table class="table table-sm">
        <caption class="sr-only">Known-host pins</caption>
        <thead>
          <tr>
            <th scope="col">Host</th><th scope="col">Algorithm</th><th scope="col">Fingerprint</th>
            <th scope="col">Added</th><th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each pins as p (JSON.stringify([p.scope, p.owner, p.host]))}
            <tr>
              <td>{p.host}</td>
              <td>{p.algorithm ?? ""}</td>
              <td class="font-mono text-xs">{p.fingerprint}</td>
              <td>{p.added_at}</td>
              <td class="text-right">
                <button class="btn btn-ghost btn-xs text-error" aria-label={`Remove ${p.host}`} onclick={() => (confirm = { kind: "host", host: p.host, scope: p.scope, owner: p.owner })}>Remove</button>
              </td>
            </tr>
          {/each}
          {#if pins.length === 0}
            <tr><td colspan="5" class="text-center text-base-content/60 py-6">No known hosts pinned.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
    <div class="flex flex-wrap gap-2 mt-3">
      <input class="input input-bordered input-sm" aria-label="Host" placeholder="Host" bind:value={hHost} disabled={busy} />
      <input class="input input-bordered input-sm flex-1" aria-label="Host public key" placeholder="ssh-ed25519 AAAA..." bind:value={hPublicKey} disabled={busy} />
      <button class="btn btn-primary btn-sm" onclick={addHost} disabled={busy || hHost === "" || hPublicKey.trim() === ""}>Add pin</button>
    </div>
    <div class="flex flex-wrap gap-2 mt-3">
      <input class="input input-bordered input-sm" aria-label="Host to verify" placeholder="Host" bind:value={vHost} />
      <input class="input input-bordered input-sm flex-1" aria-label="Offered public key" placeholder="ssh-ed25519 AAAA..." bind:value={vPublicKey} />
      <button class="btn btn-sm" onclick={verifyHost} disabled={vHost === "" || vPublicKey.trim() === ""}>Verify host</button>
    </div>
    {#if shownHostResult}
      {#if shownHostResult.ok}
        <Alert kind="success" class="mt-3"><span>{shownHostResult.message}</span></Alert>
      {:else}
        <Alert kind="error" class="mt-3"><strong>Fingerprint mismatch</strong><span>{shownHostResult.message}</span></Alert>
      {/if}
    {/if}
  </section>

  <section aria-labelledby="authorized-keys-title">
    <h2 id="authorized-keys-title" class="text-lg font-semibold mb-2">Authorized keys</h2>
    <div class="overflow-x-auto">
      <table class="table table-sm">
        <caption class="sr-only">Authorized keys</caption>
        <thead>
          <tr>
            <th scope="col">Name</th><th scope="col">Comment</th><th scope="col">Options</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each entries as k (JSON.stringify([k.scope, k.owner, k.name]))}
            <tr>
              <td>{k.name}</td>
              <td>{k.comment ?? ""}</td>
              <td>{(k.options ?? []).join(", ")}</td>
              <td class="text-right">
                <button class="btn btn-ghost btn-xs text-error" aria-label={`Remove ${k.name}`} onclick={() => (confirm = { kind: "key", name: k.name, scope: k.scope, owner: k.owner })}>Remove</button>
              </td>
            </tr>
          {/each}
          {#if entries.length === 0}
            <tr><td colspan="4" class="text-center text-base-content/60 py-6">No authorized keys.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
    <div class="flex flex-wrap gap-2 mt-3">
      <input class="input input-bordered input-sm" aria-label="Key name" placeholder="Name" bind:value={kName} disabled={busy} />
      <input class="input input-bordered input-sm flex-1" aria-label="Authorized key line" placeholder="ssh-ed25519 AAAA... comment" bind:value={kLine} disabled={busy} />
      <input class="input input-bordered input-sm" aria-label="Options" placeholder="no-pty, restrict" bind:value={kOptions} disabled={busy} />
      <button class="btn btn-primary btn-sm" onclick={addKey} disabled={busy || kName === "" || kLine === ""}>Add key</button>
    </div>
    <div class="flex flex-wrap gap-2 mt-3">
      <input class="input input-bordered input-sm" aria-label="Key fingerprint" placeholder="SHA256:..." bind:value={kFingerprint} />
      <button class="btn btn-sm" onclick={verifyKey} disabled={kFingerprint === ""}>Verify key</button>
    </div>
    {#if shownKeyResult}
      <Alert kind={shownKeyResult.ok ? "success" : "error"} class="mt-3"><span>{shownKeyResult.message}</span></Alert>
    {/if}
  </section>
{/if}

{#if confirm}
  <Modal open={confirm !== null} onClose={() => (confirm = null)} labelledby="ssh-trust-remove-title">
    <h3 id="ssh-trust-remove-title" class="text-lg font-semibold mb-4">
      {confirm.kind === "host" ? "Remove known host" : "Remove authorized key"}
    </h3>
    <p>{confirmText}</p>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (confirm = null)} disabled={busy}>Cancel</button>
      <button class="btn btn-error" onclick={remove} disabled={busy}>Confirm remove</button>
    </div>
  </Modal>
{/if}
