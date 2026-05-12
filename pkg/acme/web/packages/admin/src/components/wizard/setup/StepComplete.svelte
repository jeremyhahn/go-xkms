<!--
  Copyright (C) 2024 Trusted CA Authors.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0, or alternatively, under the terms of the
  GNU Affero General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any
  later version. A commercial license is available from the authors.
-->
<script lang="ts">
  import { setupWizardStore } from '@trustedca/shared/stores/setup-wizard.svelte';

  let { onDone }: { onDone: () => void } = $props();

  let copiedIndex: number | null = $state(null);

  async function copyShare(share: string, index: number): Promise<void> {
    try {
      await navigator.clipboard.writeText(share);
      copiedIndex = index;
      setTimeout(() => {
        copiedIndex = null;
      }, 2000);
    } catch (_e) {
      // Clipboard unavailable — user can copy manually.
    }
  }

  const hasShamirShares = $derived(setupWizardStore.shamirShares.length > 0);
</script>

<div class="flex flex-col items-center gap-6">
  <!-- Success icon -->
  <svg
    xmlns="http://www.w3.org/2000/svg"
    class="h-16 w-16 text-success"
    fill="none"
    viewBox="0 0 24 24"
    stroke="currentColor"
  >
    <path
      stroke-linecap="round"
      stroke-linejoin="round"
      stroke-width="2"
      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
    />
  </svg>

  <div class="text-center">
    <h2 class="text-2xl font-bold">Setup Complete</h2>
    <p class="text-base-content/70 mt-2">
      Your Trusted CA has been successfully initialized and is ready for use.
    </p>
  </div>

  <!-- Shamir shares -->
  {#if hasShamirShares}
    <div class="w-full max-w-2xl space-y-4">
      <div role="alert" class="alert alert-warning">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-5 w-5 shrink-0"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
          />
        </svg>
        <div class="text-sm">
          <p class="font-semibold">Save these shares now — they will not be shown again.</p>
          <p class="mt-1">
            Distribute each share to a separate, trusted operator. At least
            {setupWizardStore.shamirThreshold} shares are required to unseal the CA.
          </p>
        </div>
      </div>

      <div class="bg-base-200 rounded-lg p-4 space-y-3">
        <h3 class="font-semibold text-sm uppercase tracking-wide text-primary">
          Shamir Key Shares
        </h3>
        {#each setupWizardStore.shamirShares as share, i}
          <div class="flex items-center gap-2">
            <span class="text-base-content/50 w-8 text-sm font-mono shrink-0">
              {i + 1}.
            </span>
            <code
              class="bg-base-300 rounded px-3 py-1.5 text-xs font-mono flex-1 break-all select-all"
            >
              {share}
            </code>
            <button
              class="btn btn-sm btn-ghost"
              title="Copy share {i + 1}"
              onclick={() => copyShare(share, i)}
            >
              {#if copiedIndex === i}
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  class="h-4 w-4 text-success"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              {:else}
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  class="h-4 w-4"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                  />
                </svg>
              {/if}
            </button>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <button class="btn btn-primary btn-lg" onclick={onDone}>
    Continue to Dashboard
  </button>
</div>
