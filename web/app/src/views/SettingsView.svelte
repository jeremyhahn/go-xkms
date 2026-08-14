<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { sessionStore } from "$stores/session.svelte.ts";
  import { themeStore, setTheme } from "$stores/theme.svelte.ts";

  const caps = $derived(Object.entries(sessionStore.capabilities));
</script>

<PageHeader title="Settings" subtitle="Session and appearance" />

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
  <div class="card bg-base-200">
    <div class="card-body">
      <h2 class="card-title text-base">Session</h2>
      <dl class="text-sm space-y-1">
        <div class="flex justify-between"><dt class="text-base-content/60">User</dt><dd>{sessionStore.username}</dd></div>
        <div class="flex justify-between"><dt class="text-base-content/60">Display name</dt><dd>{sessionStore.displayName}</dd></div>
        <div class="flex justify-between"><dt class="text-base-content/60">Roles</dt><dd>{sessionStore.roles.join(", ") || "—"}</dd></div>
      </dl>
    </div>
  </div>

  <div class="card bg-base-200">
    <div class="card-body">
      <h2 class="card-title text-base">Appearance</h2>
      <div class="join">
        <button
          class="btn btn-sm join-item"
          class:btn-active={themeStore.theme === "xkms-dark"}
          onclick={() => setTheme("xkms-dark")}>Dark</button
        >
        <button
          class="btn btn-sm join-item"
          class:btn-active={themeStore.theme === "xkms-light"}
          onclick={() => setTheme("xkms-light")}>Light</button
        >
      </div>
    </div>
  </div>

  <div class="card bg-base-200 lg:col-span-2">
    <div class="card-body">
      <h2 class="card-title text-base">Server capabilities</h2>
      <div class="flex flex-wrap gap-2">
        {#each caps as [name, wired] (name)}
          <StatusBadge label={name} ok={wired} />
        {/each}
        {#if caps.length === 0}
          <span class="text-sm text-base-content/60">No capability information.</span>
        {/if}
      </div>
    </div>
  </div>
</div>
