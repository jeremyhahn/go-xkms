/**
 * Wails runtime type declarations.
 *
 * These are stubs for development outside the Wails build environment.
 * The actual runtime module is auto-generated during `wails build` or `wails dev`.
 */

export declare function EventsOn(event: string, callback: (...data: unknown[]) => void): void;
export declare function EventsOff(event: string): void;
export declare function EventsEmit(event: string, ...data: unknown[]): void;
export declare function LogDebug(message: string): void;
export declare function LogInfo(message: string): void;
export declare function LogWarning(message: string): void;
export declare function LogError(message: string): void;
export declare function WindowSetTitle(title: string): void;
export declare function WindowMinimise(): void;
export declare function WindowMaximise(): void;
export declare function WindowUnmaximise(): void;
export declare function WindowToggleMaximise(): void;
export declare function WindowFullscreen(): void;
export declare function WindowUnfullscreen(): void;
export declare function WindowCenter(): void;
export declare function WindowReload(): void;
export declare function Quit(): void;
