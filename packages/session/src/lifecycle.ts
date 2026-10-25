import type { Observable } from "@openlv/core";
import type { EventEmitter } from "eventemitter3";

import type { SessionEvents } from "./events.js";
import { log } from "./utils/log.js";

export type SessionLifecycleOptions = {
  emitter: EventEmitter<SessionEvents>;
  lastError: Observable<string | undefined>;
  setLastErrorIfUnset: (reason: string) => void;
  onDisconnected: () => void;
  // Tears down the signaling and transport layers, which hold their own state.
  teardownLayers: () => Promise<void>;
};

export type SessionLifecycle = {
  isStopped: () => boolean;
  invalidatePairing: () => void;
  // Cleanup registered here runs once, before the layers are torn down.
  onTeardown: (cleanup: () => void) => void;
  // Rejects with the session error if the session closes before `work` settles.
  trackConnect: <T>(work: () => Promise<T>) => Promise<T>;
  teardown: () => Promise<void>;
};

/**
 * Owns a session's terminal state: whether it is stopped, whether the pairing
 * was invalidated, and the single teardown that releases everything else.
 */
export const createSessionLifecycle = (
  options: SessionLifecycleOptions,
): SessionLifecycle => {
  const {
    emitter,
    lastError,
    setLastErrorIfUnset,
    onDisconnected,
    teardownLayers,
  } = options;
  const cleanups: (() => void)[] = [];
  let isStopped = false;
  let isPairingInvalidated = false;
  let teardownPromise: Promise<void> | undefined;
  let rejectPendingConnect: ((error: Error) => void) | undefined;

  const teardown = (): Promise<void> => {
    if (teardownPromise) return teardownPromise;

    isStopped = true;
    rejectPendingConnect?.(new Error(lastError.get() ?? "Session closed"));
    rejectPendingConnect = undefined;

    for (const cleanup of cleanups) cleanup();

    cleanups.length = 0;

    teardownPromise = (async () => {
      try {
        await teardownLayers();
      }
      catch (error) {
        log("session teardown failed", error);
        setLastErrorIfUnset(error instanceof Error ? error.message : "Session teardown failed");
      }
    })();
    onDisconnected();
    emitter.emit("close", lastError.get(), isPairingInvalidated);

    return teardownPromise;
  };

  return {
    isStopped: () => isStopped,
    invalidatePairing: () => {
      isPairingInvalidated = true;
    },
    onTeardown: (cleanup) => {
      cleanups.push(cleanup);
    },
    trackConnect: async <T>(work: () => Promise<T>): Promise<T> => {
      // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries target ES2020.
      const ended = new Promise<never>((_resolve, reject) => {
        rejectPendingConnect = reject;
      });

      try {
        return await Promise.race([work(), ended]);
      }
      finally {
        rejectPendingConnect = undefined;
      }
    },
    teardown,
  };
};
