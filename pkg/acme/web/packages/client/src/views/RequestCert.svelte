<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientApi } from '../lib/api/client-api';

  let specName = '';
  let specs: string[] = [];
  let loading = false;
  let currentStep = '';

  const steps = [
    'Creating order...',
    'Setting up challenge...',
    'Validating...',
    'Finalizing...',
    'Downloading certificate...',
  ];

  $: stepIndex = steps.indexOf(currentStep);

  async function loadSpecs() {
    try {
      const data = await clientApi.listCertificates();
      specs = Object.keys(data).sort();
      if (!specName && specs.length > 0) specName = specs[0];
    } catch (e) {
      notifyError(`Failed to load certificate specs: ${(e as Error).message}`);
    }
  }

  async function handleRequest() {
    if (!specName) return;

    loading = true;
    currentStep = steps[0];
    try {
      const res = await clientApi.requestCertificate({ name: specName });
      currentStep = '';
      notifySuccess(`Certificate issued for "${res.subject || specName}"`);
    } catch (e) {
      currentStep = '';
      notifyError(`Certificate request failed: ${(e as Error).message}`);
    } finally {
      loading = false;
      currentStep = '';
    }
  }

  onMount(loadSpecs);
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Request Certificate
  </h1>

  <div class="max-w-xl">
    <Card
      title="New Certificate Request"
      subtitle="Issue a certificate from a configured certificate spec"
    >
      <form class="space-y-4" on:submit|preventDefault={handleRequest}>
        <fieldset disabled={loading}>
          <div class="space-y-4">
            <FormField
              label="Certificate Spec"
              required
              hint="Specs are defined in the client config or added via POST /api/v1/certificates"
              id="spec-name"
            >
              {#if specs.length === 0}
                <input
                  id="spec-name"
                  class="input"
                  type="text"
                  bind:value={specName}
                  placeholder="web-demo"
                  required
                />
              {:else}
                <select id="spec-name" class="select" bind:value={specName} required>
                  {#each specs as s}
                    <option value={s}>{s}</option>
                  {/each}
                </select>
              {/if}
            </FormField>
          </div>
        </fieldset>

        {#if loading && currentStep}
          <div class="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800/50">
            <div class="space-y-2">
              {#each steps as step, i}
                <div class="flex items-center gap-3 text-sm">
                  {#if i < stepIndex}
                    <svg class="h-4 w-4 text-green-500 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    <span class="text-slate-500 dark:text-slate-400">{step}</span>
                  {:else if i === stepIndex}
                    <svg class="h-4 w-4 animate-spin text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    <span class="font-medium text-blue-700 dark:text-blue-300">{step}</span>
                  {:else}
                    <div class="h-4 w-4 rounded-full border-2 border-slate-300 dark:border-slate-600"></div>
                    <span class="text-slate-400 dark:text-slate-500">{step}</span>
                  {/if}
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <Button type="submit" variant="primary" {loading} disabled={!specName}>
          Request Certificate
        </Button>
      </form>
    </Card>
  </div>
</div>
