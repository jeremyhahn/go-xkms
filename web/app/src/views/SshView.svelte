<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import type { SSHKey } from "@go-xkms/sdk";

  let keys = $state<SSHKey[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let showGen = $state(false);

  let gScope = $state("user");
  let gOwner = $state("");
  let gName = $state("");
  let gAlgorithm = $state("ed25519");
  let gErr = $state<string | null>(null);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().ssh.listKeys();
      keys = resp.items;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function generate(): Promise<void> {
    busy = true;
    gErr = null;
    try {
      await getSDKClient().ssh.generateKey({
        scope: gScope,
        owner: gOwner,
        name: gName,
        algorithm: gAlgorithm,
      });
      showToast("success", `SSH key "${gName}" generated.`);
      showGen = false;
      gName = ""; gOwner = "";
      await load();
    } catch (e) {
      gErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function del(k: SSHKey): Promise<void> {
    try {
      await getSDKClient().ssh.deleteKey(k.scope, k.owner, k.name);
      showToast("success", `SSH key "${k.name}" deleted.`);
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="SSH" subtitle="SSH keys managed by xKMS">
  {#snippet actions()}
    <button class="btn btn-primary btn-sm" onclick={() => (showGen = true)}>+ Generate</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">SSH keys</caption>
      <thead>
        <tr>
          <th scope="col">Scope</th><th scope="col">Owner</th><th scope="col">Name</th>
          <th scope="col">Algorithm</th><th scope="col">Fingerprint</th><th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each keys as k (k.scope + k.owner + k.name)}
          <tr>
            <td>{k.scope}</td>
            <td>{k.owner}</td>
            <td>{k.name}</td>
            <td>{k.algorithm}</td>
            <td class="font-mono text-xs">{k.fingerprint}</td>
            <td class="text-right">
              <button class="btn btn-ghost btn-xs text-error" onclick={() => del(k)}>Delete</button>
            </td>
          </tr>
        {/each}
        {#if keys.length === 0}
          <tr><td colspan="6" class="text-center text-base-content/60 py-6">No SSH keys.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>

  <Alert kind="info" class="mt-6">
    <span>
      Known-hosts and authorized-keys management are available via
      <code class="font-mono">xkmsctl ssh</code>. xKMS stores these keys and
      signs authentication challenges with them; it never opens an SSH session
      itself. Connect with the <strong>xkey</strong> client (or any SSH client
      via the xkey agent) and add this server as a backend — the private key
      stays in the vault.
    </span>
  </Alert>
{/if}

{#if showGen}
  <Modal open={showGen} onClose={() => (showGen = false)} labelledby="generate-ssh-title">
      <h3 id="generate-ssh-title" class="text-lg font-semibold mb-4">Generate SSH key</h3>
      {#if gErr}<Alert kind="error" class="mb-3"><span>{gErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Scope" placeholder="Scope (e.g. user)" bind:value={gScope} />
        <input class="input input-bordered w-full" aria-label="Owner" placeholder="Owner" bind:value={gOwner} />
        <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={gName} />
        <select class="select select-bordered w-full" aria-label="Algorithm" bind:value={gAlgorithm}>
          <option>ed25519</option><option>ecdsa-p256</option><option>ecdsa-p384</option><option>rsa</option>
        </select>
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showGen = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={generate} disabled={busy || gName === "" || gOwner === ""}>Generate</button>
      </div>
  </Modal>
{/if}
