<script lang="ts">
  export let status: string = '';

  const colorMap: Record<string, string> = {
    valid: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    active: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    issued: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    ready: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',

    expired: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    revoked: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    deactivated: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    deleted: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    invalid: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',

    pending: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    processing: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',

    'pending-rotation': 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
    expiring: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
    suspended: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
    unused: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
  };

  const defaultColor = 'bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300';

  $: colorClass = colorMap[status.toLowerCase()] ?? defaultColor;
  $: label = status.charAt(0).toUpperCase() + status.slice(1).replace(/-/g, ' ');
</script>

<span
  class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium {colorClass}"
  {...$$restProps}
>
  {label}
</span>
