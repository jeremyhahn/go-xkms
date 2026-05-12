<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import { formatDateTime, formatDate } from '@trustedca/shared/utils/formatters';
  import { selectedOrder, ordersLoading, fetchOrder } from '../lib/stores/orders';

  export let orderId: string;

  const dispatch = createEventDispatcher<{ back: void }>();

  onMount(() => {
    fetchOrder(orderId);
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center gap-4">
    <Button variant="ghost" size="sm" on:click={() => dispatch('back')}>
      <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15 19l-7-7 7-7" />
      </svg>
      Back to Orders
    </Button>
  </div>

  {#if $ordersLoading}
    <div class="flex items-center justify-center py-20">
      <LoadingSpinner size="lg" />
    </div>
  {:else if $selectedOrder}
    <div class="mb-6 flex items-center gap-4">
      <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">
        Order #{$selectedOrder.id}
      </h1>
      <StatusBadge status={$selectedOrder.status} />
    </div>

    <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
      <!-- Order metadata -->
      <Card title="Order Details">
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Order ID</p>
            <p class="mt-1 font-mono text-sm text-slate-900 dark:text-slate-100">
              {$selectedOrder.id}
            </p>
          </div>

          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Account ID</p>
            <p class="mt-1 font-mono text-sm text-slate-900 dark:text-slate-100">
              {$selectedOrder.account_id}
            </p>
          </div>

          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Status</p>
            <div class="mt-1">
              <StatusBadge status={$selectedOrder.status} />
            </div>
          </div>

          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Created</p>
            <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
              {formatDateTime($selectedOrder.created_at)}
            </p>
          </div>

          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Expires</p>
            <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
              {formatDate($selectedOrder.expires)}
            </p>
          </div>

          {#if $selectedOrder.not_before}
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Not Before</p>
              <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                {formatDate($selectedOrder.not_before)}
              </p>
            </div>
          {/if}

          {#if $selectedOrder.not_after}
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Not After</p>
              <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                {formatDate($selectedOrder.not_after)}
              </p>
            </div>
          {/if}
        </div>
      </Card>

      <!-- Identifiers -->
      <Card title="Identifiers">
        {#if $selectedOrder.identifiers && $selectedOrder.identifiers.length > 0}
          <ul class="space-y-2">
            {#each $selectedOrder.identifiers as identifier}
              <li class="flex items-center gap-2 rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-800/50">
                <svg class="h-4 w-4 flex-shrink-0 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
                </svg>
                <span class="font-mono text-sm text-slate-900 dark:text-slate-100">
                  {identifier}
                </span>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="text-sm text-slate-500 dark:text-slate-400">No identifiers.</p>
        {/if}
      </Card>

      <!-- Certificate URL -->
      {#if $selectedOrder.certificate}
        <Card title="Issued Certificate">
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Certificate URL</p>
            <a
              href={$selectedOrder.certificate}
              target="_blank"
              rel="noopener noreferrer"
              class="mt-1 block break-all font-mono text-sm text-blue-600 hover:underline dark:text-blue-400"
            >
              {$selectedOrder.certificate}
            </a>
          </div>
        </Card>
      {/if}
    </div>
  {:else}
    <div class="flex flex-col items-center justify-center py-20 gap-4">
      <p class="text-sm text-slate-600 dark:text-slate-400">Order not found.</p>
      <Button variant="secondary" size="sm" on:click={() => dispatch('back')}>
        Back to Orders
      </Button>
    </div>
  {/if}
</div>
