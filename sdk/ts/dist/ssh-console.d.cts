import { ITheme } from '@xterm/xterm';

/** Connection details for SSHConsoleClient.open. */
interface ConsoleConnection {
    /** Full WebSocket URL including any one-time token query, e.g.
     * `ws://127.0.0.1:54321/console?token=abc`. */
    url: string;
    /**
     * Optional WebSocket subprotocols, for a host whose bridge authenticates
     * that way. Browsers cannot set an Authorization header on a WebSocket
     * upgrade, so such a host reads the credential from here instead. Note that
     * the xkms server serves no console endpoint — it stores SSH keys and signs
     * authentication challenges, and never terminates an SSH session — so this
     * client always connects to a bridge running on the operator's own machine
     * (xkey's loopback server).
     */
    protocols?: string[];
}
/** Construction options. */
interface SSHConsoleOptions {
    fontSize?: number;
    fontFamily?: string;
    theme?: ITheme;
}
/** A server-reported host key awaiting client confirmation or notification. */
interface HostKeyPrompt {
    host: string;
    key_type: string;
    fingerprint: string;
    known: boolean;
    mode: 'confirm' | 'notify';
}
/**
 * SSHConsoleClient is a framework-agnostic embedded SSH terminal: it renders an
 * xterm.js terminal into a DOM element and bridges it to a go-xkms SSH console
 * over a WebSocket. xkey (Svelte) and other web UIs (React, etc.) wrap it.
 */
declare class SSHConsoleClient {
    private readonly opts;
    private term;
    private fitAddon;
    private ws;
    private readonly encoder;
    private pendingHostKeyResponded;
    /** Called when the server reports an error control frame or the socket errors. */
    onError: ((message: string) => void) | undefined;
    /** Called when the session ends (exit control frame or socket close). */
    onClose: (() => void) | undefined;
    /**
     * Called when the server reports a host key control frame. For mode
     * "confirm" the server is paused awaiting a response (subject to a
     * server-side timeout); call respond(accept) exactly once to continue or
     * abort the handshake. For mode "notify" the server already decided under
     * its own accept-new policy and respond() is a no-op — this is informational
     * only. If onHostKey is left unset, a "confirm" prompt is auto-rejected
     * (fail-closed): the client never silently trusts an unverified host key.
     */
    onHostKey: ((prompt: HostKeyPrompt, respond: (accept: boolean) => void) => void) | undefined;
    constructor(opts?: SSHConsoleOptions);
    /** open renders the terminal into element and connects to conn.url. */
    open(element: HTMLElement, conn: ConsoleConnection): void;
    /** fit resizes the terminal to its container and notifies the server. */
    fit(): void;
    /** dispose closes the socket and tears down the terminal. Idempotent. */
    dispose(): void;
    private onMessage;
    private onHostKeyFrame;
    private sendHostKeyResponse;
    private sendResize;
    private sendResizeRC;
    private safeFit;
}

export { type ConsoleConnection, type HostKeyPrompt, SSHConsoleClient, type SSHConsoleOptions };
