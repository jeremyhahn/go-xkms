<script lang="ts">
  /**
   * Copyright (C) 2024 Trusted CA Authors.
   *
   * This Source Code Form is subject to the terms of the Mozilla Public
   * License, v. 2.0, or alternatively, under the terms of the
   * GNU Affero General Public License as published by the Free Software
   * Foundation, either version 3 of the License, or (at your option) any
   * later version. A commercial license is available from the authors.
   *
   * SealManager provides a UI for inspecting and controlling the barrier
   * seal/unseal lifecycle, including Shamir secret sharing support and
   * remote-mode passthrough display.
   */

  import { onMount, onDestroy } from 'svelte';
  import { AlertTriangle, Info } from 'lucide-svelte';
  import { barrierApi } from '@trustedca/shared/api/barrier';
  import { sealStore, updateSealStatus, addShare } from '@trustedca/shared/stores/seal.svelte';
  import {
    notifySuccess,
    notifyError,
    notifyInfo,
  } from '@trustedca/shared/stores/notifications';

  // ---------------------------------------------------------------------------
  // Local state
  // ---------------------------------------------------------------------------

  let loading = false;
  let shareInput = '';
  let secretInput = '';
  let submittingShare = false;
  let sealing = false;

  // Shamir unseal progress from most recent API response
  let shamirRequired = 0;
  let shamirSubmitted = 0;

  let pollInterval: ReturnType<typeof setInterval> | null = null;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  onMount(async () => {
    await fetchStatus();
    startPolling();
  });

  onDestroy(() => {
    stopPolling();
  });

  // ---------------------------------------------------------------------------
  // Polling
  // ---------------------------------------------------------------------------

  function startPolling(): void {
    if (pollInterval !== null) return;
    sealStore.polling = true;
    pollInterval = setInterval(fetchStatus, 10_000);
  }

  function stopPolling(): void {
    if (pollInterval !== null) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    sealStore.polling = false;
  }

  // ---------------------------------------------------------------------------
  // API calls
  // ---------------------------------------------------------------------------

  async function fetchStatus(): Promise<void> {
    try {
      const status = await barrierApi.status();
      updateSealStatus(status);
      shamirRequired = status.shares_required;
      shamirSubmitted = status.shares_provided;
    } catch (err) {
      // Silently suppress polling errors to avoid toast floods.
      if (!sealStore.polling) {
        notifyError('Failed to fetch barrier status.');
      }
    }
  }

  async function handleUnsealWithShare(): Promise<void> {
    const share = shareInput.trim();
    if (!share) return;

    submittingShare = true;
    try {
      const res = await barrierApi.unsealWithShare({ share });
      shareInput = '';
      shamirSubmitted = res.submitted;
      shamirRequired = res.required;
      addShare();
      if (res.complete) {
        notifySuccess('Barrier unsealed successfully.');
        await fetchStatus();
      } else {
        notifyInfo(`Share accepted. ${res.required - res.submitted} more share(s) required.`);
      }
    } catch (err) {
      notifyError(err instanceof Error ? err.message : 'Failed to submit share.');
    } finally {
      submittingShare = false;
    }
  }

  async function handleUnsealSingle(): Promise<void> {
    const secret = secretInput.trim();
    if (!secret) return;

    submittingShare = true;
    try {
      await barrierApi.unseal({ secret });
      secretInput = '';
      notifySuccess('Barrier unsealed successfully.');
      await fetchStatus();
    } catch (err) {
      notifyError(err instanceof Error ? err.message : 'Failed to unseal barrier.');
    } finally {
      submittingShare = false;
    }
  }

  async function handleSeal(): Promise<void> {
    sealing = true;
    try {
      await barrierApi.seal();
      notifySuccess('Barrier sealed.');
      await fetchStatus();
    } catch (err) {
      notifyError(err instanceof Error ? err.message : 'Failed to seal barrier.');
    } finally {
      sealing = false;
    }
  }

  // ---------------------------------------------------------------------------
  // Derived helpers
  // ---------------------------------------------------------------------------

  $: isShamir = sealStore.sharesTotal > 1;
  $: progressPct = shamirRequired > 0
    ? Math.round((shamirSubmitted / shamirRequired) * 100)
    : 0;
  $: isRemote = sealStore.mode === 'remote';
</script>

<div class="p-6">
  <h1 class="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
    Seal Manager
  </h1>

  <!-- Remote mode — barrier is managed externally -->
  {#if isRemote}
    <div class="flex items-start gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-800 dark:bg-blue-900/20">
      <Info class="mt-0.5 h-5 w-5 flex-shrink-0 text-blue-600 dark:text-blue-400" />
      <div>
        <p class="font-medium text-blue-800 dark:text-blue-200">Barrier managed by remote server</p>
        <p class="mt-1 text-sm text-blue-700 dark:text-blue-300">
          This Trusted CA instance delegates barrier operations to an external QRDB server.
          Seal and unseal actions must be performed on that server.
        </p>
      </div>
    </div>

    <!-- Status summary in remote mode (read-only) -->
    <div class="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
      <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
        <p class="text-sm text-slate-500 dark:text-slate-400">Mode</p>
        <p class="mt-1 font-medium capitalize text-slate-900 dark:text-slate-100">{sealStore.mode}</p>
      </div>
      <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
        <p class="text-sm text-slate-500 dark:text-slate-400">Status</p>
        <span class="mt-1 inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium
          {sealStore.sealed
            ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
            : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'}">
          {sealStore.sealed ? 'Sealed' : 'Unsealed'}
        </span>
      </div>
      <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
        <p class="text-sm text-slate-500 dark:text-slate-400">Shares</p>
        <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
          {sealStore.sharesProvided} / {sealStore.sharesRequired}
        </p>
      </div>
    </div>
  {:else}
    <!-- Embedded mode — full seal/unseal controls -->

    <!-- Status cards -->
    <div class="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
        <p class="text-sm text-slate-500 dark:text-slate-400">Status</p>
        <span class="mt-1 inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium
          {sealStore.sealed
            ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
            : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'}">
          {sealStore.sealed ? 'Sealed' : 'Unsealed'}
        </span>
      </div>

      <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
        <p class="text-sm text-slate-500 dark:text-slate-400">Mode</p>
        <p class="mt-1 font-medium capitalize text-slate-900 dark:text-slate-100">{sealStore.mode}</p>
      </div>

      <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
        <p class="text-sm text-slate-500 dark:text-slate-400">Strategy</p>
        <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
          {isShamir ? 'Shamir' : 'Single'}
        </p>
      </div>

      <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
        <p class="text-sm text-slate-500 dark:text-slate-400">Shares</p>
        <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
          {sealStore.sharesTotal > 0
            ? `${sealStore.sharesRequired} of ${sealStore.sharesTotal}`
            : '—'}
        </p>
      </div>
    </div>

    <!-- Unseal section -->
    {#if sealStore.sealed}
      <div class="mb-6 rounded-lg border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-900/20">
        <div class="flex items-start gap-3 border-b border-amber-200 px-4 py-3 dark:border-amber-800">
          <AlertTriangle class="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-600 dark:text-amber-400" />
          <p class="text-sm font-medium text-amber-800 dark:text-amber-200">
            The barrier is sealed. Certificate operations are unavailable until it is unsealed.
          </p>
        </div>

        <div class="p-4">
          {#if isShamir}
            <!-- Shamir unseal -->
            <h2 class="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-200">
              Submit Unseal Share
            </h2>

            <!-- Progress bar -->
            {#if shamirRequired > 0}
              <div class="mb-4">
                <div class="mb-1 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                  <span>{shamirSubmitted} of {shamirRequired} shares submitted</span>
                  <span>{progressPct}%</span>
                </div>
                <div class="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
                  <div
                    class="h-full rounded-full bg-amber-500 transition-all duration-300"
                    style="width: {progressPct}%"
                  ></div>
                </div>
              </div>
            {/if}

            <div class="flex gap-2">
              <input
                class="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900
                       placeholder-slate-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500
                       dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100 dark:placeholder-slate-500"
                type="password"
                placeholder="Paste unseal share..."
                bind:value={shareInput}
                disabled={submittingShare}
                on:keydown={(e) => e.key === 'Enter' && handleUnsealWithShare()}
              />
              <button
                class="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-colors
                       hover:bg-amber-700 disabled:cursor-not-allowed disabled:opacity-50"
                on:click={handleUnsealWithShare}
                disabled={submittingShare || !shareInput.trim()}
              >
                {#if submittingShare}
                  <span class="inline-flex items-center gap-1.5">
                    <svg class="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                    </svg>
                    Submitting…
                  </span>
                {:else}
                  Submit Share
                {/if}
              </button>
            </div>
          {:else}
            <!-- Single-secret unseal -->
            <h2 class="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-200">
              Unseal Barrier
            </h2>
            <div class="flex gap-2">
              <input
                class="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900
                       placeholder-slate-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500
                       dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100 dark:placeholder-slate-500"
                type="password"
                placeholder="Enter unseal secret..."
                bind:value={secretInput}
                disabled={submittingShare}
                on:keydown={(e) => e.key === 'Enter' && handleUnsealSingle()}
              />
              <button
                class="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-colors
                       hover:bg-amber-700 disabled:cursor-not-allowed disabled:opacity-50"
                on:click={handleUnsealSingle}
                disabled={submittingShare || !secretInput.trim()}
              >
                {#if submittingShare}
                  <span class="inline-flex items-center gap-1.5">
                    <svg class="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                    </svg>
                    Unsealing…
                  </span>
                {:else}
                  Unseal
                {/if}
              </button>
            </div>
          {/if}
        </div>
      </div>
    {:else}
      <!-- Unsealed — success state + seal button -->
      <div class="mb-6 flex items-start gap-3 rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800 dark:bg-green-900/20">
        <svg class="mt-0.5 h-5 w-5 flex-shrink-0 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <div class="flex-1">
          <p class="font-medium text-green-800 dark:text-green-200">Barrier is unsealed</p>
          <p class="mt-0.5 text-sm text-green-700 dark:text-green-300">
            Certificate operations are available.
          </p>
        </div>
        <button
          class="rounded-lg bg-slate-700 px-4 py-2 text-sm font-medium text-white transition-colors
                 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50
                 dark:bg-slate-600 dark:hover:bg-slate-500"
          on:click={handleSeal}
          disabled={sealing}
        >
          {#if sealing}
            <span class="inline-flex items-center gap-1.5">
              <svg class="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
              Sealing…
            </span>
          {:else}
            Seal Barrier
          {/if}
        </button>
      </div>
    {/if}

    <!-- Polling indicator -->
    {#if sealStore.polling}
      <div class="flex items-center gap-2 text-xs text-slate-400 dark:text-slate-500">
        <span class="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-slate-400 dark:bg-slate-500"></span>
        Auto-refreshing every 10 seconds
      </div>
    {/if}
  {/if}
</div>
