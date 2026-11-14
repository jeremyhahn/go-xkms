<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { loadUser, isNotFound } from "$lib/userDetail.ts";
  import type { UserInfo } from "@go-xkms/sdk";

  let username = $state("");
  let user = $state<UserInfo | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function lookUp(): Promise<void> {
    const name = username.trim();
    if (name === "" || busy) return;
    busy = true;
    error = null;
    user = null;
    try {
      user = await loadUser(name);
    } catch (e) {
      error = isNotFound(e) ? "User not found" : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  function onKeydown(e: KeyboardEvent): void {
    if (e.key === "Enter") void lookUp();
  }
</script>

<PageHeader title="User Detail" subtitle="Read-only view of one user record, looked up by username" />

<div class="card bg-base-100 shadow-sm mb-4">
  <div class="card-body flex-row flex-wrap items-end gap-2">
    <input
      class="input input-bordered w-full max-w-xs"
      aria-label="Username"
      placeholder="Username"
      bind:value={username}
      onkeydown={onKeydown}
    />
    <button class="btn btn-primary" onclick={lookUp} disabled={busy}>
      {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if}
      Look up
    </button>
  </div>
</div>

{#if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if user}
  <div class="card bg-base-100 shadow-sm">
    <div class="card-body">
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
        <dt class="font-semibold">ID</dt>
        <dd><code class="font-mono">{user.id}</code></dd>
        <dt class="font-semibold">Username</dt>
        <dd>{user.username}</dd>
        <dt class="font-semibold">Display name</dt>
        <dd>{user.display_name ?? ""}</dd>
        <dt class="font-semibold">Roles</dt>
        <dd class="flex flex-wrap gap-1">
          {#each user.roles ?? [] as role (role)}
            <span class="badge badge-outline">{role}</span>
          {/each}
        </dd>
        <dt class="font-semibold">State</dt>
        <dd><StatusBadge label={user.enabled ? "enabled" : "disabled"} ok={user.enabled} /></dd>
        <dt class="font-semibold">Created</dt>
        <dd><time datetime={user.created_at}>{user.created_at}</time></dd>
        <dt class="font-semibold">Last login</dt>
        <dd>
          {#if user.last_login}<time datetime={user.last_login}>{user.last_login}</time>{:else}Never{/if}
        </dd>
      </dl>
    </div>
  </div>
{/if}
