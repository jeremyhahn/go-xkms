<script lang="ts">
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientApi } from '../lib/api/client-api';

  let accountName = '';
  let directoryURL = '';
  let contactEmail = '';
  let keyAlgorithm: 'ECDSA' | 'RSA' = 'ECDSA';
  let eccCurve = 'P-256';
  let rsaBits = 2048;
  let eabKid = '';
  let eabHmacKey = '';
  let termsAgreed = false;
  let loading = false;
  let progressMessage = '';

  function buildRequest() {
    const req: {
      name: string;
      email: string;
      directory: string;
      key?: {
        algorithm: string;
        store: string;
        ecc?: { curve: string };
        rsa?: { bits: number };
      };
      eab?: { kid: string; hmac_key: string };
    } = {
      name: accountName.trim(),
      email: contactEmail.trim(),
      directory: directoryURL.trim(),
      key: {
        algorithm: keyAlgorithm,
        store: 'software',
      },
    };
    if (keyAlgorithm === 'ECDSA') {
      req.key!.ecc = { curve: eccCurve };
    } else {
      req.key!.rsa = { bits: rsaBits };
    }
    if (eabKid && eabHmacKey) {
      req.eab = { kid: eabKid, hmac_key: eabHmacKey };
    }
    return req;
  }

  async function handleRegister() {
    if (!accountName || !directoryURL || !contactEmail || !termsAgreed) return;

    loading = true;
    progressMessage = 'Registering with ACME server...';
    try {
      const res = await clientApi.addAccount(buildRequest());
      progressMessage = '';
      notifySuccess(`Account "${res.name ?? accountName}" registered`);
      accountName = '';
      directoryURL = '';
      contactEmail = '';
      eabKid = '';
      eabHmacKey = '';
      termsAgreed = false;
    } catch (e) {
      progressMessage = '';
      notifyError(`Registration failed: ${(e as Error).message}`);
    } finally {
      loading = false;
      progressMessage = '';
    }
  }
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Register Account
  </h1>

  <div class="max-w-xl">
    <Card title="ACME Account Registration" subtitle="Create a new ACME account with the CA server">
      <form class="space-y-4" on:submit|preventDefault={handleRegister}>
        <fieldset disabled={loading}>
          <div class="space-y-4">
            <FormField label="Account Name" required id="account-name" hint="Local identifier used in certificate configs">
              <input
                id="account-name"
                class="input"
                type="text"
                bind:value={accountName}
                placeholder="prod-ca"
                required
              />
            </FormField>

            <FormField label="ACME Directory URL" required id="directory-url">
              <input
                id="directory-url"
                class="input"
                type="url"
                bind:value={directoryURL}
                placeholder="https://ca.example.com/acme/directory"
                required
              />
            </FormField>

            <FormField label="Contact Email" required id="contact-email">
              <input
                id="contact-email"
                class="input"
                type="email"
                bind:value={contactEmail}
                placeholder="admin@example.com"
                required
              />
            </FormField>

            <div class="grid grid-cols-2 gap-3">
              <FormField label="Key Algorithm" id="key-algo">
                <select id="key-algo" class="select" bind:value={keyAlgorithm}>
                  <option value="ECDSA">ECDSA</option>
                  <option value="RSA">RSA</option>
                </select>
              </FormField>

              {#if keyAlgorithm === 'ECDSA'}
                <FormField label="ECC Curve" id="ecc-curve">
                  <select id="ecc-curve" class="select" bind:value={eccCurve}>
                    <option value="P-256">P-256</option>
                    <option value="P-384">P-384</option>
                    <option value="P-521">P-521</option>
                  </select>
                </FormField>
              {:else}
                <FormField label="RSA Bits" id="rsa-bits">
                  <select id="rsa-bits" class="select" bind:value={rsaBits}>
                    <option value={2048}>2048</option>
                    <option value={3072}>3072</option>
                    <option value={4096}>4096</option>
                  </select>
                </FormField>
              {/if}
            </div>

            <FormField label="EAB Key ID" id="eab-kid" hint="External Account Binding identifier (optional)">
              <input
                id="eab-kid"
                class="input"
                type="text"
                bind:value={eabKid}
                placeholder="Optional"
              />
            </FormField>

            <FormField label="EAB HMAC Key" id="eab-hmac" hint="Base64-encoded HMAC key provided by the CA (optional)">
              <input
                id="eab-hmac"
                class="input"
                type="text"
                bind:value={eabHmacKey}
                placeholder="Optional"
              />
            </FormField>

            <div class="flex items-center gap-2">
              <input
                id="terms"
                type="checkbox"
                bind:checked={termsAgreed}
                class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 dark:border-slate-600 dark:bg-slate-700"
              />
              <label for="terms" class="text-sm text-slate-700 dark:text-slate-300">
                I agree to the Terms of Service
              </label>
            </div>
          </div>
        </fieldset>

        {#if loading && progressMessage}
          <div class="flex items-center gap-3 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm dark:border-blue-800 dark:bg-blue-900/20">
            <svg class="h-4 w-4 animate-spin text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <span class="font-medium text-blue-700 dark:text-blue-300">{progressMessage}</span>
          </div>
        {/if}

        <Button
          type="submit"
          variant="primary"
          {loading}
          disabled={!accountName || !directoryURL || !contactEmail || !termsAgreed}
        >
          Register
        </Button>
      </form>
    </Card>
  </div>
</div>
