<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { SSHPin, SSHAuthorizedEntry, SSHAddKnownHostRequest, SSHAddAuthorizedKeyRequest } from "@go-xkms/sdk";

  type Confirm = { kind: "host"; host: string } | { kind: "key"; name: string };
  type Result = { ok: boolean; message: string };

  let scope = $state("global");
  let owner = $state("default");
  let pins = $state<SSHPin[]>([]);
  let entries = $state<SSHAuthorizedEntry[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let confirm = $state<Confirm | null>(null);

  let hHost = $state("");
  let hFingerprint = $state("");
  let hAlgorithm = $state("");
  let vHost = $state("");
  let vFingerprint = $state("");
  let hostResult = $state<Result | null>(null);

  let kName = $state("");
  let kLine = $state("");
  let kOptions = $state("");
  let kFingerprint = $state("");
  let keyResult = $state<Result | null>(null);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const ssh = getSDKClient().ssh;
      const [hosts, keys] = await Promise.all([ssh.listKnownHosts(scope, owner), ssh.listAuthorizedKeys(scope, owner)]);
      pins = hosts.items;
      entries = keys.items;
    } catch (e) {
      pins = [];
      entries = [];
      error = message(e);
    } finally {
      loading = false;
    }
  }

  async function addHost(): Promise<void> {
    busy = true;
    try {
      const req: SSHAddKnownHostRequest = { scope, owner, host: hHost, fingerprint: hFingerprint };
      if (hAlgorithm !== "") req.algorithm = hAlgorithm;
      await getSDKClient().ssh.addKnownHost(req);
      showToast("success", `Pinned "${hHost}".`);
      hHost = ""; hFingerprint = ""; hAlgorithm = "";
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  async function verifyHost(): Promise<void> {
    hostResult = null;
    try {
      await getSDKClient().ssh.verifyKnownHost(vHost, { scope, owner, fingerprint: vFingerprint });
      hostResult = { ok: true, message: `Fingerprint matches the pin for ${vHost}.` };
    } catch (e) {
      if ((e as { status?: number }).status === 409) {
        hostResult = { ok: false, message: message(e) };
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
      showToast("success", `Authorized key "${kName}" added.`);
      kName = ""; kLine = ""; kOptions = "";
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  async function verifyKey(): Promise<void> {
    keyResult = null;
    try {
      const matched = await getSDKClient().ssh.verifyAuthorizedKey({ scope, owner, fingerprint: kFingerprint });
      keyResult = { ok: true, message: `Fingerprint matches ${matched.name}.` };
    } catch (e) {
      if ((e as { status?: number }).status === 409 || (e as { status?: number }).status === 404) {
        keyResult = { ok: false, message: message(e) };
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
        await getSDKClient().ssh.removeKnownHost(c.host, scope, owner);
        showToast("success", `Pin for "${c.host}" removed.`);
      } else {
        await getSDKClient().ssh.removeAuthorizedKey(scope, owner, c.name);
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

  // Mount-time load with the default scope and owner; later loads are explicit (Load).
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="SSH Trust" subtitle="Known-host pins and authorized_keys entries" />

<div class="flex flex-wrap items-end gap-2 mb-4">
  <input class="input input-bordered input-sm" aria-label="Scope" placeholder="Scope" bind:value={scope} />
  <input class="input input-bordered input-sm" aria-label="Owner" placeholder="Owner" bind:value={owner} />
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
          {#each pins as p (p.host)}
            <tr>
              <td>{p.host}</td>
              <td>{p.algorithm ?? ""}</td>
              <td class="font-mono text-xs">{p.fingerprint}</td>
              <td>{p.added_at}</td>
              <td class="text-right">
                <button class="btn btn-ghost btn-xs text-error" aria-label={`Remove ${p.host}`} onclick={() => (confirm = { kind: "host", host: p.host })}>Remove</button>
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
      <input class="input input-bordered input-sm" aria-label="Host" placeholder="Host" bind:value={hHost} />
      <input class="input input-bordered input-sm" aria-label="Host fingerprint" placeholder="SHA256:..." bind:value={hFingerprint} />
      <input class="input input-bordered input-sm" aria-label="Host algorithm" placeholder="Algorithm (optional)" bind:value={hAlgorithm} />
      <button class="btn btn-primary btn-sm" onclick={addHost} disabled={busy || hHost === "" || hFingerprint === ""}>Add pin</button>
    </div>
    <div class="flex flex-wrap gap-2 mt-3">
      <input class="input input-bordered input-sm" aria-label="Host to verify" placeholder="Host" bind:value={vHost} />
      <input class="input input-bordered input-sm" aria-label="Offered fingerprint" placeholder="SHA256:..." bind:value={vFingerprint} />
      <button class="btn btn-sm" onclick={verifyHost} disabled={vHost === "" || vFingerprint === ""}>Verify host</button>
    </div>
    {#if hostResult}
      {#if hostResult.ok}
        <Alert kind="success" class="mt-3"><span>{hostResult.message}</span></Alert>
      {:else}
        <Alert kind="error" class="mt-3"><strong>Fingerprint mismatch</strong><span>{hostResult.message}</span></Alert>
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
          {#each entries as k (k.name)}
            <tr>
              <td>{k.name}</td>
              <td>{k.comment ?? ""}</td>
              <td>{(k.options ?? []).join(", ")}</td>
              <td class="text-right">
                <button class="btn btn-ghost btn-xs text-error" aria-label={`Remove ${k.name}`} onclick={() => (confirm = { kind: "key", name: k.name })}>Remove</button>
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
      <input class="input input-bordered input-sm" aria-label="Key name" placeholder="Name" bind:value={kName} />
      <input class="input input-bordered input-sm flex-1" aria-label="Authorized key line" placeholder="ssh-ed25519 AAAA... comment" bind:value={kLine} />
      <input class="input input-bordered input-sm" aria-label="Options" placeholder="no-pty, restrict" bind:value={kOptions} />
      <button class="btn btn-primary btn-sm" onclick={addKey} disabled={busy || kName === "" || kLine === ""}>Add key</button>
    </div>
    <div class="flex flex-wrap gap-2 mt-3">
      <input class="input input-bordered input-sm" aria-label="Key fingerprint" placeholder="SHA256:..." bind:value={kFingerprint} />
      <button class="btn btn-sm" onclick={verifyKey} disabled={kFingerprint === ""}>Verify key</button>
    </div>
    {#if keyResult}
      <Alert kind={keyResult.ok ? "success" : "error"} class="mt-3"><span>{keyResult.message}</span></Alert>
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
