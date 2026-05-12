<script lang="ts">
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { getApiBaseUrl } from '@trustedca/shared/api/transport';

  let apiBaseUrl = getApiBaseUrl();
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Connection Settings
  </h1>

  <div class="max-w-2xl space-y-6">
    <Card title="API Connection">
      <div class="space-y-4">
        <FormField label="API Base URL" hint="The base URL used for all API requests">
          <input
            class="input"
            type="text"
            value={apiBaseUrl}
            readonly
          />
        </FormField>

        <FormField label="Connection Status">
          <div class="flex items-center gap-2">
            <span class="h-2.5 w-2.5 rounded-full bg-green-500"></span>
            <span class="text-sm text-slate-700 dark:text-slate-300">Connected</span>
          </div>
        </FormField>
      </div>

      <div slot="footer">
        <Button variant="secondary" size="sm">
          Test Connection
        </Button>
      </div>
    </Card>

    <Card title="TLS Configuration" subtitle="Certificate verification settings for API connections">
      <p class="text-sm text-slate-500 dark:text-slate-400">
        TLS configuration is managed by the server. The admin GUI uses the
        browser's built-in certificate store for TLS verification.
      </p>
    </Card>
  </div>
</div>
