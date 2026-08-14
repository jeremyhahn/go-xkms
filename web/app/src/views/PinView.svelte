<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatCard from "$components/StatCard.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Alert from "$components/Alert.svelte";
  import type { LockoutStatusResponse } from "@go-xkms/sdk";

  let lockout = $state<LockoutStatusResponse | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);

  // SO PIN change form.
  let soCurrent = $state("");
  let soNew = $state("");
  // User PIN change form.
  let userCurrent = $state("");
  let userNew = $state("");
  // Lockout reset.
  let resetSO = $state("");

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      lockout = await getSDKClient().pin.lockoutStatus();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function changeSO(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().pin.changeSO({ current_so_pin: soCurrent, new_so_pin: soNew });
      showToast("success", "SO PIN changed.");
      soCurrent = ""; soNew = "";
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  async function changeUser(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().pin.changeUser({ current_user_pin: userCurrent, new_user_pin: userNew });
      showToast("success", "User PIN changed.");
      userCurrent = ""; userNew = "";
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  async function resetLockout(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().pin.resetLockout({ so_pin: resetSO });
      showToast("success", "Lockout counter reset.");
      resetSO = "";
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="PIN" subtitle="Security Officer and user PIN management" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if lockout}
  <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
    <StatCard label="Failed attempts" value={lockout.failed_attempts} />
    <StatCard label="Max attempts" value={lockout.max_attempts} />
    <StatCard label="Locked" value={lockout.is_locked ? "yes" : "no"} />
  </div>
{/if}

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
  <div class="card bg-base-200">
    <div class="card-body">
      <h2 class="card-title text-base">Change SO PIN</h2>
      <input type="password" class="input input-bordered" aria-label="Current SO PIN" placeholder="Current SO PIN" bind:value={soCurrent} />
      <input type="password" class="input input-bordered" aria-label="New SO PIN" placeholder="New SO PIN" bind:value={soNew} />
      <button class="btn btn-primary btn-sm w-fit" onclick={changeSO} disabled={busy || soNew === ""}>Change</button>
    </div>
  </div>

  <div class="card bg-base-200">
    <div class="card-body">
      <h2 class="card-title text-base">Change User PIN</h2>
      <input type="password" class="input input-bordered" aria-label="Current user PIN" placeholder="Current user PIN" bind:value={userCurrent} />
      <input type="password" class="input input-bordered" aria-label="New user PIN" placeholder="New user PIN" bind:value={userNew} />
      <button class="btn btn-primary btn-sm w-fit" onclick={changeUser} disabled={busy || userNew === ""}>Change</button>
    </div>
  </div>

  <div class="card bg-base-200">
    <div class="card-body">
      <h2 class="card-title text-base">Reset lockout</h2>
      <input type="password" class="input input-bordered" aria-label="SO PIN" placeholder="SO PIN" bind:value={resetSO} />
      <button class="btn btn-warning btn-sm w-fit" onclick={resetLockout} disabled={busy || resetSO === ""}>Reset counter</button>
    </div>
  </div>
</div>
