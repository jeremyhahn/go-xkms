<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { can } from "$stores/session.svelte.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import type { UserInfo } from "@go-xkms/sdk";

  let users = $state<UserInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let showCreate = $state(false);

  let cUsername = $state("");
  let cDisplay = $state("");
  let cRole = $state("user");
  let cTenant = $state("system");
  let cErr = $state<string | null>(null);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().users.list();
      users = resp.users;
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
      await getSDKClient().users.create({
        username: cUsername,
        display_name: cDisplay,
        role: cRole,
        tenant_id: cTenant,
      });
      showToast("success", `User "${cUsername}" created.`);
      showCreate = false;
      cUsername = ""; cDisplay = "";
      await load();
    } catch (e) {
      cErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function enable(u: UserInfo): Promise<void> {
    try {
      await getSDKClient().users.enable(u.username);
      showToast("success", `User "${u.username}" enabled.`);
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function disable(u: UserInfo): Promise<void> {
    try {
      await getSDKClient().users.disable(u.username);
      showToast("success", `User "${u.username}" disabled.`);
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function del(u: UserInfo): Promise<void> {
    try {
      await getSDKClient().users.delete(u.username);
      showToast("success", `User "${u.username}" deleted.`);
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

<PageHeader title="Users" subtitle="Platform identities">
  {#snippet actions()}
    {#if can("users", "create")}
      <button class="btn btn-primary btn-sm" onclick={() => (showCreate = true)}>+ Create</button>
    {/if}
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">Platform users</caption>
      <thead>
        <tr>
          <th scope="col">Username</th><th scope="col">Display name</th><th scope="col">Role</th>
          <th scope="col">Enabled</th><th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each users as u (u.username)}
          <tr>
            <td>{u.username}</td>
            <td>{u.display_name ?? "—"}</td>
            <td>{u.role ?? "—"}</td>
            <td>{u.enabled ? "yes" : "no"}</td>
            <td class="text-right">
              {#if u.enabled}
                {#if can("users", "disable")}
                  <button class="btn btn-ghost btn-xs" onclick={() => disable(u)}>Disable</button>
                {/if}
              {:else if can("users", "enable")}
                <button class="btn btn-ghost btn-xs" onclick={() => enable(u)}>Enable</button>
              {/if}
              {#if can("users", "delete")}
                <button class="btn btn-ghost btn-xs text-error" onclick={() => del(u)}>Delete</button>
              {/if}
            </td>
          </tr>
        {/each}
        {#if users.length === 0}
          <tr><td colspan="5" class="text-center text-base-content/60 py-6">No users.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

{#if showCreate}
  <Modal open={showCreate} onClose={() => (showCreate = false)} labelledby="create-user-title">
      <h3 id="create-user-title" class="text-lg font-semibold mb-4">Create user</h3>
      {#if cErr}<Alert kind="error" class="mb-3"><span>{cErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Username" placeholder="Username" bind:value={cUsername} />
        <input class="input input-bordered w-full" aria-label="Display name" placeholder="Display name" bind:value={cDisplay} />
        <input class="input input-bordered w-full" aria-label="Role" placeholder="Role" bind:value={cRole} />
        <input class="input input-bordered w-full" aria-label="Tenant ID" placeholder="Tenant ID" bind:value={cTenant} />
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showCreate = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={create} disabled={busy || cUsername === ""}>Create</button>
      </div>
  </Modal>
{/if}
