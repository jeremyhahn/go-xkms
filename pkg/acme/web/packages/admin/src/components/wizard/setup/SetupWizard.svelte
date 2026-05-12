<!--
  Copyright (C) 2024 Trusted CA Authors.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0, or alternatively, under the terms of the
  GNU Affero General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any
  later version. A commercial license is available from the authors.
-->
<script lang="ts">
  import {
    setupWizardStore,
    nextStep,
    prevStep,
    resetSetupWizard,
  } from '@trustedca/shared/stores/setup-wizard.svelte';
  import type { SetupWizardStep } from '@trustedca/shared/stores/setup-wizard.svelte';
  import StepIndicator from '@trustedca/shared/components/StepIndicator.svelte';
  import StepBarrierConfig from './StepBarrierConfig.svelte';
  import StepCAInit from './StepCAInit.svelte';
  import StepSummary from './StepSummary.svelte';
  import StepCreating from './StepCreating.svelte';
  import StepComplete from './StepComplete.svelte';

  let { onComplete }: { onComplete: () => void } = $props();

  // -------------------------------------------------------------------------
  // Step indicator metadata
  // -------------------------------------------------------------------------

  /** Human-readable labels for each wizard step. */
  const stepLabels: Readonly<Record<SetupWizardStep, string>> = {
    barrier: 'Barrier',
    ca: 'CA',
    summary: 'Review',
    creating: 'Create',
    complete: 'Done',
  } as const;

  /** The fixed step sequence shown in the indicator (excludes 'complete'). */
  const indicatorSteps: readonly SetupWizardStep[] = [
    'barrier',
    'ca',
    'summary',
    'creating',
    'complete',
  ] as const;

  let indicatorLabels = $derived(indicatorSteps.map((s) => stepLabels[s]));

  let currentIndex = $derived(
    indicatorSteps.indexOf(setupWizardStore.currentStep),
  );

  // -------------------------------------------------------------------------
  // Navigation
  // -------------------------------------------------------------------------

  function handleNext(): void {
    nextStep();
  }

  function handleBack(): void {
    prevStep();
  }

  function handleCancel(): void {
    resetSetupWizard();
  }

  function handleCreatingComplete(): void {
    nextStep();
  }

  function handleDone(): void {
    onComplete();
  }
</script>

<div class="flex min-h-screen flex-col items-center justify-center px-4 py-8">
  <div class="w-full max-w-3xl">
    <!-- Header -->
    <div class="mb-8 text-center">
      <h1 class="text-3xl font-bold">Trusted CA Setup</h1>
      <p class="text-base-content/60 mt-1 text-sm">
        First-run initialization wizard
      </p>
    </div>

    <!-- Step indicator (hidden on complete step) -->
    {#if setupWizardStore.currentStep !== 'complete'}
      <div class="mb-8">
        <StepIndicator steps={indicatorLabels} currentIndex={currentIndex} />
      </div>
    {/if}

    <!-- Step content card -->
    <div class="card bg-base-100 shadow-xl">
      <div class="card-body">
        {#if setupWizardStore.currentStep === 'barrier'}
          <StepBarrierConfig onNext={handleNext} onCancel={handleCancel} />
        {:else if setupWizardStore.currentStep === 'ca'}
          <StepCAInit onNext={handleNext} onBack={handleBack} />
        {:else if setupWizardStore.currentStep === 'summary'}
          <StepSummary onNext={handleNext} onBack={handleBack} />
        {:else if setupWizardStore.currentStep === 'creating'}
          <StepCreating onComplete={handleCreatingComplete} />
        {:else if setupWizardStore.currentStep === 'complete'}
          <StepComplete onDone={handleDone} />
        {/if}
      </div>
    </div>
  </div>
</div>
