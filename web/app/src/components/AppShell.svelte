<script lang="ts">
  import { Sun, Moon, LogOut } from "lucide-svelte";
  import Sidebar from "./Sidebar.svelte";
  import { themeStore, toggleTheme } from "$stores/theme.svelte.ts";
  import { sessionStore, clearSession } from "$stores/session.svelte.ts";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { navigateTo } from "$stores/router.svelte.ts";
  import {
    authStore,
    endSession,
    readRefreshToken,
  } from "@go-xkms/svelte-auth";
  import { showToast } from "$stores/toast.svelte.ts";

  interface Props {
    children: import("svelte").Snippet;
  }
  let { children }: Props = $props();

  async function logout(): Promise<void> {
    try {
      await getSDKClient().auth.logout(readRefreshToken() ?? undefined);
    } catch {
      // Logout is best-effort: the server may already have expired the
      // session. Local teardown proceeds regardless.
    }
    endSession();
    clearSession();
    navigateTo("/login");
    showToast("info", "Signed out.");
    // authStore is read so the shell re-renders on the status change.
    void authStore.status;
  }
</script>

<div class="flex h-screen w-screen overflow-hidden">
  <Sidebar />
  <div class="flex-1 flex flex-col overflow-hidden">
    <header class="h-14 shrink-0 flex items-center justify-end gap-2 px-4 border-b border-base-300 bg-base-100">
      <span class="text-sm text-base-content/70">{sessionStore.displayName}</span>
      <button
        class="btn btn-ghost btn-sm btn-square"
        aria-label="Toggle theme"
        onclick={toggleTheme}
      >
        {#if themeStore.theme === "xkms-dark"}<Sun size={18} />{:else}<Moon size={18} />{/if}
      </button>
      <button class="btn btn-ghost btn-sm" onclick={logout}>
        <LogOut size={16} /> Sign out
      </button>
    </header>
    <main class="flex-1 overflow-y-auto p-6">
      {@render children()}
    </main>
  </div>
</div>
