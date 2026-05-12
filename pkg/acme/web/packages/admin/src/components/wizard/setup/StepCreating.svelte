<!--
  Copyright (C) 2024 Trusted CA Authors.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0, or alternatively, under the terms of the
  GNU Affero General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any
  later version. A commercial license is available from the authors.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { setupWizardStore, nextStep } from '@trustedca/shared/stores/setup-wizard.svelte';
  import { setupApi } from '@trustedca/shared/api/setup';

  let { onComplete }: { onComplete: () => void } = $props();

  type PhaseStatus = 'pending' | 'active' | 'done' | 'error';

  interface Phase {
    readonly label: string;
    status: PhaseStatus;
  }

  let phases: Phase[] = $state([
    { label: 'Configuring barrier...', status: 'pending' },
    { label: 'Initializing Certificate Authority...', status: 'pending' },
    { label: 'Completing setup...', status: 'pending' },
  ]);

  let currentPhaseIndex: number = $state(-1);
  let progressPercent: number = $state(0);
  let errorMessage: string = $state('');

  let currentLabel = $derived(
    errorMessage
      ? 'Initialization failed'
      : currentPhaseIndex >= 0 && currentPhaseIndex < phases.length
        ? (phases[currentPhaseIndex]?.label ?? 'Initializing...')
        : 'Preparing...',
  );

  function advancePhase(index: number): void {
    currentPhaseIndex = index;
    if (phases[index] !== undefined) {
      phases[index] = { ...phases[index], status: 'active' };
    }
    progressPercent = Math.round(((index + 1) / phases.length) * 100);
  }

  function completePhase(index: number): void {
    if (phases[index] !== undefined) {
      phases[index] = { ...phases[index], status: 'done' };
    }
  }

  function failPhase(index: number): void {
    if (phases[index] !== undefined) {
      phases[index] = { ...phases[index], status: 'error' };
    }
  }

  async function runSetup(): Promise<void> {
    // Phase 0: Configure barrier
    advancePhase(0);
    const barrierReq =
      setupWizardStore.barrierStrategy === 'shamir'
        ? {
            strategy: setupWizardStore.barrierStrategy,
            secret: '',
            shamir: {
              threshold: setupWizardStore.shamirThreshold,
              total: setupWizardStore.shamirTotal,
            },
          }
        : {
            strategy: setupWizardStore.barrierStrategy,
            secret: setupWizardStore.barrierSecret,
          };

    const barrierResp = await setupApi.configureBarrier(barrierReq);
    if (barrierResp.shares && barrierResp.shares.length > 0) {
      setupWizardStore.shamirShares = barrierResp.shares;
    }
    completePhase(0);

    // Phase 1: Initialize CA
    advancePhase(1);
    await setupApi.configureCA({
      root_ca_name: setupWizardStore.rootCAName,
      intermediate_ca_name: setupWizardStore.intermediateCAName,
      key_algorithm: setupWizardStore.keyAlgorithm,
      validity_years: setupWizardStore.validityYears,
      organization: setupWizardStore.organization,
      organizational_unit: setupWizardStore.organizationalUnit,
      country: setupWizardStore.country,
      state: setupWizardStore.state,
      locality: setupWizardStore.locality,
    });
    completePhase(1);

    // Phase 2: Complete setup
    advancePhase(2);
    await setupApi.complete();
    completePhase(2);

    progressPercent = 100;
    onComplete();
  }

  onMount(() => {
    async function run(): Promise<void> {
      try {
        await runSetup();
      } catch (err: unknown) {
        if (currentPhaseIndex >= 0) {
          failPhase(currentPhaseIndex);
        }
        errorMessage =
          err instanceof Error ? err.message : 'An unknown error occurred.';
      }
    }
    run();
  });
</script>

<div class="flex flex-col items-center gap-8">
  <div class="text-center">
    <h2 class="text-2xl font-bold">Initializing Trusted CA</h2>
    <p class="text-base-content/70 mt-2">
      Please wait while the server is configured...
    </p>
  </div>

  <div class="w-full max-w-md space-y-6">
    <!-- Progress bar -->
    <div class="w-full">
      <progress
        class="progress {errorMessage
          ? 'progress-error'
          : 'progress-primary'} w-full"
        value={progressPercent}
        max="100"
      ></progress>
      <div class="mt-2 flex justify-between text-sm">
        <span class="text-base-content/60">{currentLabel}</span>
        <span class="text-base-content/50">{progressPercent}%</span>
      </div>
    </div>

    <!-- Global spinner -->
    {#if !errorMessage && progressPercent < 100}
      <div class="flex justify-center">
        <span class="loading loading-spinner loading-lg text-primary"></span>
      </div>
    {/if}

    <!-- Phase indicators -->
    <div class="space-y-2">
      {#each phases as phase (phase.label)}
        <div class="flex items-center gap-3">
          {#if phase.status === 'done'}
            <svg
              xmlns="http://www.w3.org/2000/svg"
              class="h-5 w-5 text-success"
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
          {:else if phase.status === 'active'}
            <span class="loading loading-spinner loading-sm text-primary"
            ></span>
          {:else if phase.status === 'error'}
            <svg
              xmlns="http://www.w3.org/2000/svg"
              class="h-5 w-5 text-error"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          {:else}
            <div class="h-5 w-5 rounded-full border-2 border-base-content/20"
            ></div>
          {/if}
          <span
            class="text-sm {phase.status === 'done' || phase.status === 'active'
              ? 'text-base-content'
              : phase.status === 'error'
                ? 'text-error'
                : 'text-base-content/40'}"
          >
            {phase.label}
          </span>
        </div>
      {/each}
    </div>

    <!-- Error alert -->
    {#if errorMessage}
      <div role="alert" class="alert alert-error">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-6 w-6 shrink-0 stroke-current"
          fill="none"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <span>{errorMessage}</span>
      </div>
    {/if}
  </div>
</div>
