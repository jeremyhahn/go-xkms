<script lang="ts">
  import LoadingSpinner from './LoadingSpinner.svelte';

  export let variant: 'primary' | 'secondary' | 'danger' | 'ghost' = 'primary';
  export let size: 'sm' | 'md' | 'lg' = 'md';
  export let disabled: boolean = false;
  export let loading: boolean = false;
  export let type: 'button' | 'submit' | 'reset' = 'button';

  const variantClasses: Record<string, string> = {
    primary:
      'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500 disabled:bg-blue-400 dark:bg-blue-500 dark:hover:bg-blue-600 dark:focus:ring-blue-400 dark:disabled:bg-blue-700',
    secondary:
      'bg-slate-200 text-slate-800 hover:bg-slate-300 focus:ring-slate-400 border border-slate-300 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600 dark:border-slate-600',
    danger:
      'bg-red-600 text-white hover:bg-red-700 focus:ring-red-500 disabled:bg-red-400 dark:bg-red-500 dark:hover:bg-red-600 dark:focus:ring-red-400 dark:disabled:bg-red-700',
    ghost:
      'bg-transparent text-slate-700 hover:bg-slate-100 focus:ring-slate-400 dark:text-slate-300 dark:hover:bg-slate-800',
  };

  const sizeClasses: Record<string, string> = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-3 text-base',
  };

  $: classes = [
    'inline-flex items-center justify-center gap-2 font-medium rounded-lg',
    'transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 dark:focus:ring-offset-slate-900',
    'disabled:cursor-not-allowed disabled:opacity-60',
    variantClasses[variant],
    sizeClasses[size],
  ].join(' ');
</script>

<button
  {type}
  class={classes}
  disabled={disabled || loading}
  on:click
  {...$$restProps}
>
  {#if loading}
    <LoadingSpinner size="sm" />
  {/if}
  <slot />
</button>
