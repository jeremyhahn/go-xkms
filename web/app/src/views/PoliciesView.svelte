<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { PolicyInfo } from "@go-xkms/sdk";

  let policies = $state<PolicyInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let showCreate = $state(false);

  let cName = $state("");
  let cBank = $state("sha256");
  let cPCRs = $state("0,7");
  let cErr = $state<string | null>(null);

  const columns = [
    { key: "name", label: "Name" },
    { key: "bank", label: "Bank" },
    { key: "pcrs", label: "PCRs" },
  ];

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().policies.list();
      policies = resp.policies;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function create(): Promise<void> {
    busy = true;
    cErr = null;
    try {
      const indices = cPCRs.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));
      await getSDKClient().policies.create({ name: cName, bank: cBank, pcr_indices: indices });
      showToast("success", `Policy "${cName}" created.`);
      showCreate = false;
      cName = "";
      await load();
    } catch (e) {
      cErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function verify(name: string): Promise<void> {
    try {
      const resp = await getSDKClient().policies.verify(name);
      showToast(resp.valid ? "success" : "warning", `${name}: ${resp.valid ? "valid" : "INVALID"} — ${resp.message}`);
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function del(name: string): Promise<void> {
    try {
      await getSDKClient().policies.delete(name);
      showToast("success", `Policy "${name}" deleted.`);
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

<PageHeader title="PCR Policies" subtitle="TPM platform configuration register policies">
  {#snippet actions()}
    <button class="btn btn-primary btn-sm" onclick={() => (showCreate = true)}>+ Create</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">PCR policies</caption>
      <thead><tr><th scope="col">Name</th><th scope="col">Bank</th><th scope="col">PCRs</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
      <tbody>
        {#each policies as p (p.name)}
          <tr>
            <td>{p.name}</td>
            <td>{p.bank}</td>
            <td>{(p.pcr_indices ?? []).join(", ")}</td>
            <td class="text-right">
              <button class="btn btn-ghost btn-xs" onclick={() => verify(p.name)}>Verify</button>
              <button class="btn btn-ghost btn-xs text-error" onclick={() => del(p.name)}>Delete</button>
            </td>
          </tr>
        {/each}
        {#if policies.length === 0}
          <tr><td colspan="4" class="text-center text-base-content/60 py-6">No policies.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

{#if showCreate}
  <Modal open={showCreate} onClose={() => (showCreate = false)} labelledby="create-policy-title">
      <h3 id="create-policy-title" class="text-lg font-semibold mb-4">Create PCR policy</h3>
      {#if cErr}<Alert kind="error" class="mb-3"><span>{cErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={cName} />
        <select class="select select-bordered w-full" aria-label="Bank" bind:value={cBank}>
          <option>sha256</option><option>sha384</option><option>sha1</option>
        </select>
        <input class="input input-bordered w-full" aria-label="PCR indices" placeholder="PCR indices (e.g. 0,2,4,7)" bind:value={cPCRs} />
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showCreate = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={create} disabled={busy || cName === ""}>Create</button>
      </div>
  </Modal>
{/if}
