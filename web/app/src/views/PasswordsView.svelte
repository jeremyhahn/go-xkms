<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { PasswordInfo, PasswordStoreStatusResponse } from "@go-xkms/sdk";

  let status = $state<PasswordStoreStatusResponse | null>(null);
  let entries = $state<PasswordInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let unlockPin = $state("");
  let showAdd = $state(false);

  let aName = $state("");
  let aUsername = $state("");
  let aPassword = $state("");
  let aErr = $state<string | null>(null);

  async function refreshStatus(): Promise<void> {
    status = await getSDKClient().passwords.status();
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      await refreshStatus();
      if (status && !status.is_locked) {
        const resp = await getSDKClient().passwords.list();
        entries = resp.passwords;
      } else {
        entries = [];
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function unlock(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().passwords.unlock({ pin: unlockPin });
      unlockPin = "";
      showToast("success", "Vault unlocked.");
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  async function lock(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().passwords.lock();
      showToast("success", "Vault locked.");
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  async function add(): Promise<void> {
    busy = true;
    aErr = null;
    try {
      await getSDKClient().passwords.add({ name: aName, username: aUsername, password: aPassword });
      showToast("success", `Entry "${aName}" added.`);
      showAdd = false;
      aName = ""; aUsername = ""; aPassword = "";
      await load();
    } catch (e) {
      aErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function del(id: string): Promise<void> {
    try {
      await getSDKClient().passwords.delete(id);
      showToast("success", "Entry deleted.");
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

<PageHeader title="Passwords" subtitle="Encrypted credential vault">
  {#snippet actions()}
    {#if status && !status.is_locked}
      <button class="btn btn-primary btn-sm" onclick={() => (showAdd = true)}>+ Add</button>
      <button class="btn btn-sm" onclick={lock} disabled={busy}>Lock</button>
    {/if}
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if status}
  <div class="flex flex-wrap gap-2 mb-4">
    <StatusBadge label={status.is_locked ? "locked" : "unlocked"} ok={!status.is_locked} />
    <StatusBadge label={`${status.password_count} entries`} kind="neutral" />
  </div>

  {#if status.is_locked}
    <div class="card bg-base-200 max-w-sm">
      <div class="card-body">
        <h2 class="card-title text-base">Unlock vault</h2>
        <input type="password" class="input input-bordered" aria-label="PIN" placeholder="PIN" bind:value={unlockPin} />
        <button class="btn btn-primary btn-sm w-fit" onclick={unlock} disabled={busy || unlockPin === ""}>Unlock</button>
      </div>
    </div>
  {:else}
    <div class="overflow-x-auto">
      <table class="table table-sm">
        <caption class="sr-only">Password vault entries</caption>
        <thead><tr><th scope="col">Name</th><th scope="col">Username</th><th scope="col">URL</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {#each entries as e (e.id)}
            <tr>
              <td>{e.name}</td>
              <td>{e.username ?? "—"}</td>
              <td>{e.url ?? "—"}</td>
              <td class="text-right"><button class="btn btn-ghost btn-xs text-error" onclick={() => del(e.id)}>Delete</button></td>
            </tr>
          {/each}
          {#if entries.length === 0}
            <tr><td colspan="4" class="text-center text-base-content/60 py-6">No entries.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

{#if showAdd}
  <Modal open={showAdd} onClose={() => (showAdd = false)} labelledby="add-password-title">
      <h3 id="add-password-title" class="text-lg font-semibold mb-4">Add entry</h3>
      {#if aErr}<Alert kind="error" class="mb-3"><span>{aErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={aName} />
        <input class="input input-bordered w-full" aria-label="Username" placeholder="Username" bind:value={aUsername} />
        <input type="password" class="input input-bordered w-full" aria-label="Password" placeholder="Password" bind:value={aPassword} />
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showAdd = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={add} disabled={busy || aName === "" || aPassword === ""}>Add</button>
      </div>
  </Modal>
{/if}
