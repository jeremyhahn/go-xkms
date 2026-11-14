<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { PasswordStoreStatusResponse } from "@go-xkms/sdk";

  type Mode = "pin_per_operation" | "session_based";

  const modes: Array<{ value: Mode; label: string; help: string }> = [
    {
      value: "pin_per_operation",
      label: "PIN per operation",
      help: "Every read or write of a password asks for the PIN again.",
    },
    {
      value: "session_based",
      label: "Session based",
      help: "One unlock opens the store until it is locked or the session ends.",
    },
  ];

  let status = $state<PasswordStoreStatusResponse | null>(null);
  let loadError = $state<string | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let selected = $state<Mode | "">("");
  let confirming = $state(false);
  // The status carries no mode, so the view shows only the mode it set itself.
  let current = $state<string | null>(null);

  const canApply = $derived(status?.available === true && selected !== "" && !busy);

  async function load(): Promise<void> {
    loading = true;
    loadError = null;
    try {
      status = await getSDKClient().passwords.status();
    } catch (e) {
      loadError = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function confirm(): Promise<void> {
    if (selected === "") return;
    busy = true;
    error = null;
    try {
      const res = await getSDKClient().passwords.setAccessMode({ mode: selected });
      current = res.mode;
      showToast("success", res.message);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
      confirming = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Password Access Mode" subtitle="How the password store is unlocked" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  {#if loadError}
    <Alert kind="error" class="mb-3"><span>{loadError}</span></Alert>
  {:else if status}
    <div class="flex flex-wrap gap-2 mb-4">
      <StatusBadge label={status.available ? "available" : "unavailable"} ok={status.available} />
      <StatusBadge label={status.is_locked ? "locked" : "unlocked"} kind="neutral" />
      <StatusBadge label={`${status.password_count} passwords`} kind="neutral" />
    </div>
    {#if !status.available}
      <Alert kind="info" class="mb-3"><span>{status.message || "The password store is not available."}</span></Alert>
    {/if}
  {/if}

  <p class="mb-4" data-testid="current-mode">
    Mode set in this session: <span class="font-mono">{current ?? "not known"}</span>
  </p>

  {#if error}
    <Alert kind="error" class="mb-3"><span>{error}</span></Alert>
  {/if}

  <fieldset class="space-y-3 mb-4">
    <legend class="font-semibold mb-2">Access mode</legend>
    {#each modes as m (m.value)}
      <div class="flex items-start gap-3">
        <input
          type="radio"
          class="radio radio-sm mt-1"
          name="access-mode"
          id={`mode-${m.value}`}
          aria-label={m.label}
          value={m.value}
          bind:group={selected}
          disabled={busy}
        />
        <div>
          <span class="font-medium">{m.label}</span>
          <p class="text-sm text-base-content/70">{m.help}</p>
        </div>
      </div>
    {/each}
  </fieldset>

  {#if confirming}
    <div class="border border-warning rounded p-3 space-y-3">
      <p data-testid="confirm-mode">Switch the password store to <span class="font-mono">{selected}</span>?</p>
      <div class="flex gap-2">
        <button class="btn btn-ghost btn-sm" onclick={() => (confirming = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary btn-sm" onclick={confirm} disabled={busy}>Confirm</button>
      </div>
    </div>
  {:else}
    <button class="btn btn-primary btn-sm" onclick={() => (confirming = true)} disabled={!canApply}>Apply</button>
  {/if}
{/if}
