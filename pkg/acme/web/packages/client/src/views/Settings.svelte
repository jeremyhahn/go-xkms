<script lang="ts">
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { theme, themeMode, setThemeMode } from '@trustedca/shared/stores/theme';
  import type { ThemeMode } from '@trustedca/shared/stores/theme';
  import { notifySuccess } from '@trustedca/shared/stores/notifications';
  import { getApiBaseUrl } from '@trustedca/shared/api/transport';

  const themeModes: { value: ThemeMode; label: string; icon: string }[] = [
    {
      value: 'light',
      label: 'Light',
      icon: 'M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z',
    },
    {
      value: 'dark',
      label: 'Dark',
      icon: 'M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z',
    },
    {
      value: 'system',
      label: 'System',
      icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
    },
  ];

  function selectTheme(mode: ThemeMode) {
    setThemeMode(mode);
    notifySuccess(`Theme set to ${mode}`);
  }
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Settings
  </h1>

  <div class="max-w-2xl space-y-6">
    <Card title="Appearance">
      <div class="space-y-4">
        <FormField label="Theme" hint="Choose how Trusted CA Client looks to you">
          <div class="flex items-center gap-3">
            {#each themeModes as mode}
              <button
                class="flex items-center gap-2 rounded-lg border-2 px-4 py-2.5 text-sm font-medium transition-colors
                       {$themeMode === mode.value
                         ? 'border-blue-600 bg-blue-50 text-blue-700 dark:border-blue-400 dark:bg-blue-900/20 dark:text-blue-300'
                         : 'border-slate-200 text-slate-600 hover:border-slate-300 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-400 dark:hover:border-slate-500 dark:hover:bg-slate-800'}"
                on:click={() => selectTheme(mode.value)}
              >
                <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d={mode.icon} />
                </svg>
                {mode.label}
              </button>
            {/each}
          </div>
        </FormField>

        <!-- Theme preview -->
        <div class="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">
            Preview
          </p>
          <div class="flex gap-3">
            <div class="flex-1 rounded-lg bg-white p-3 shadow-sm ring-1 ring-slate-200 dark:bg-slate-800 dark:ring-slate-700">
              <div class="h-2 w-16 rounded bg-blue-500 mb-2"></div>
              <div class="h-2 w-24 rounded bg-slate-200 dark:bg-slate-600 mb-1"></div>
              <div class="h-2 w-20 rounded bg-slate-200 dark:bg-slate-600"></div>
            </div>
            <div class="flex-1 rounded-lg bg-white p-3 shadow-sm ring-1 ring-slate-200 dark:bg-slate-800 dark:ring-slate-700">
              <div class="h-2 w-12 rounded bg-green-500 mb-2"></div>
              <div class="h-2 w-20 rounded bg-slate-200 dark:bg-slate-600 mb-1"></div>
              <div class="h-2 w-16 rounded bg-slate-200 dark:bg-slate-600"></div>
            </div>
          </div>
          <p class="mt-3 text-xs text-slate-500 dark:text-slate-400">
            Currently using: <span class="font-medium">{$theme}</span> theme
            {#if $themeMode === 'system'}
              (detected from system)
            {/if}
          </p>
        </div>
      </div>
    </Card>

    <Card title="Connection Info">
      <FormField label="API Base URL">
        <input class="input" type="text" value={getApiBaseUrl()} readonly />
      </FormField>
    </Card>
  </div>
</div>
