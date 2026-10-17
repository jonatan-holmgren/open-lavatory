import {
  encodeConnectionURL,
  parseSessionConnectionParameters,
  type SessionConnectionParameters,
} from "@openlv/core";
import {
  connectSession,
  createSession,
  type PeerInfo,
  type Session,
  SessionStatus,
} from "@openlv/session";
import { Status as SignalStatus } from "@openlv/signaling";
import { webrtc } from "@openlv/transport/webrtc";
import { useEffect, useMemo, useState } from "react";
import type { EIP1193Provider } from "viem";
import type { Config, Connector } from "wagmi";
import { reconnect } from "wagmi/actions";

import {
  attachTryItSession,
  peerInfoFromConnectionUrl,
  shimWalletOnMessage,
  type TryItSessionActions,
} from "./TryItOutSession.js";

export type WalletSessionLifecycle = {
  active: boolean;
  connecting: boolean;
  connect: (url: string) => Promise<void>;
  end: () => Promise<void>;
};

// The wallet tab is a raw session consumer, so it persists its own pairing.
// Full parameters are stored: a connection URL only carries handshake fields.
// sessionStorage keeps the dApp and wallet tabs of this demo from sharing one.
const WALLET_SESSION_STORAGE_KEY = "@openlv/docs/wallet-session";

const loadWalletSession = (): SessionConnectionParameters | undefined => {
  try {
    return parseSessionConnectionParameters(
      JSON.parse(globalThis.sessionStorage.getItem(WALLET_SESSION_STORAGE_KEY) ?? "null"),
    );
  }
  catch {
    return undefined;
  }
};

const saveWalletSession = (parameters: SessionConnectionParameters) => {
  globalThis.sessionStorage.setItem(
    WALLET_SESSION_STORAGE_KEY,
    JSON.stringify(parameters),
  );
};

const clearWalletSession = () => {
  globalThis.sessionStorage.removeItem(WALLET_SESSION_STORAGE_KEY);
};

const walletInfo = (connector: Connector): PeerInfo => {
  // EIP-6963 icons are data URIs of arbitrary size; anything over the 8 KB
  // wire limit would make the session handshake throw.
  const icon
    = connector.icon && connector.icon.length <= 8192 ? connector.icon : undefined;

  return {
    // eslint-disable-next-line no-restricted-syntax -- Connector.id is wagmi's API.
    identity: `sh.openlv.docs.${connector.id}`,
    name: connector.name,
    ...(icon && { icon }),
  };
};

const pause = (milliseconds: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, milliseconds);

    signal.addEventListener("abort", abort, { once: true });

    if (signal.aborted) abort();
  });

// Discovery and wagmi hydration can finish after the first React render.
// Reconnect only authorized injected connectors; never open an approval prompt.
const readyConnector = async (config: Config, signal: AbortSignal) => {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    signal.throwIfAborted();
    const connection = config.state.connections.get(config.state.current ?? "");
    const connector = connection?.connector;

    if (connector?.type !== "openLv" && typeof connector?.getProvider === "function") {
      try {
        const provider = await connector.getProvider() as EIP1193Provider | undefined;

        if (provider) return { connector, provider };
      }
      catch {
        // Some injected providers are announced before their bridge is ready.
      }
    }

    if (config.state.status === "disconnected") {
      try {
        await reconnect(config, {
          connectors: config.connectors.filter(candidate => candidate.type !== "openLv"),
        });
      }
      catch {
        // Discovery can finish on the next bounded readiness attempt.
      }
    }

    await pause(250, signal);
  }

  throw new Error("Wallet provider is not ready");
};

/** Join or restore a pairing, publishing its handles before connecting so it can be cancelled. */
const connectWalletSession = async (
  parameters: string | SessionConnectionParameters,
  connector: Connector,
  client: EIP1193Provider,
  actions: TryItSessionActions,
  signal: AbortSignal,
  onCreated: (session: Session, detach: () => void) => void,
  onClosed: (reason: string | undefined) => void,
): Promise<void> => {
  signal.throwIfAborted();

  const options = {
    info: walletInfo(connector),
    onConnectionParametersChange: saveWalletSession,
  };
  const onMessage = shimWalletOnMessage(
    "wallet",
    message => client.request(message as never),
    actions,
  );

  // Saved pairings carry key material, so they are rebuilt with createSession;
  // connectSession only decodes a handshake URL.
  const session = await (typeof parameters === "string"
    ? connectSession(parameters, onMessage, [webrtc()], options)
    : createSession(parameters, [webrtc()], onMessage, options));

  if (signal.aborted) {
    await session.close({ notifyPeer: false });
    signal.throwIfAborted();
  }

  let settle!: (status: SessionStatus) => void;
  // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Docs compiler targets ES2022.
  const settled = new Promise<SessionStatus>((resolve) => {
    settle = resolve;
  });
  const abort = () => {
    settle(SessionStatus.DISCONNECTED);
    void session.close({ notifyPeer: false });
  };
  const detachLog = attachTryItSession(session, "wallet", actions, { logRequests: false });
  let hasEnded = false;
  const observe = () => {
    if (hasEnded || signal.aborted) return;

    const status = session.status.get();
    const hasSignalingError = session.signalStatus.get() === SignalStatus.ERROR;

    if (!hasSignalingError && status === SessionStatus.CONNECTED) {
      settle(status);

      return;
    }

    if (!hasSignalingError && (status !== SessionStatus.DISCONNECTED || session._internal.transport)) return;

    hasEnded = true;
    const reason = session.error.get() ?? (hasSignalingError ? "Signaling failed" : undefined);

    if (reason === undefined || session._internal.isPairingInvalidated) clearWalletSession();

    if (reason !== undefined) actions.setPhase("error");

    settle(SessionStatus.DISCONNECTED);
    onClosed(reason);
  };
  const stopStatusWatch = session.status.subscribe(observe);
  const stopSignalWatch = session.signalStatus.subscribe(observe);
  const detach = () => {
    detachLog();
    stopStatusWatch();
    stopSignalWatch();
    signal.removeEventListener("abort", abort);
  };

  signal.addEventListener("abort", abort, { once: true });
  onCreated(session, detach);

  try {
    signal.throwIfAborted();
    await session.connect();

    if (await settled !== SessionStatus.CONNECTED)
      throw new Error(session.error.get() ?? "Session failed to connect");

    signal.throwIfAborted();
    // Fresh sessions do not persist counters before the first handshake.
    saveWalletSession(session.getConnectionParameters());
  }
  catch (error) {
    detach();
    await session.close({ notifyPeer: false });
    throw error;
  }
};

/**
 * Own the raw wallet pairing independently of the injected-wallet UI mount.
 * Every retry reloads the durable high-water counters, never the first snapshot.
 */
export const useWalletSession = (config: Config, actions: TryItSessionActions): WalletSessionLifecycle => {
  const [active, setActive] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const lifecycle = useMemo(() => {
    let current: Session | undefined;
    let detach: (() => void) | undefined;
    let operation: AbortController | undefined;
    let isDisposed = false;

    const release = async (shouldNotifyPeer: boolean) => {
      detach?.();
      detach = undefined;
      operation?.abort();
      const previous = current;

      current = undefined;
      await previous?.close({ notifyPeer: shouldNotifyPeer });
    };
    const end = async () => {
      // Clear before awaiting so an in-flight resume cannot revive this pairing.
      clearWalletSession();
      await release(true);

      if (!isDisposed) {
        setActive(false);
        setConnecting(false);
        actions.resetSession();
      }
    };
    const run = async (parameters?: string) => {
      if (!parameters && !loadWalletSession()) return;

      const cleanup = parameters ? end() : release(false);
      // Register before yielding: StrictMode's cleanup must cancel this exact
      // attempt, even if its replacement mounts before cleanup has resolved.
      const controller = new AbortController();

      operation = controller;
      await cleanup;

      if (isDisposed || controller.signal.aborted) return;

      setConnecting(true);

      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const ready = await readyConnector(config, controller.signal);
          const material = parameters ?? loadWalletSession();

          if (!material) break;

          actions.setPhase("establishing");
          actions.setPeer(peerInfoFromConnectionUrl(
            "wallet",
            typeof material === "string" ? material : encodeConnectionURL(material),
          ));
          await connectWalletSession(
            material, ready.connector, ready.provider, actions, controller.signal,
            (session, stop) => {
              current = session;
              detach = stop;
            },
            (reason) => {
              if (isDisposed) return;

              if (reason === undefined) void end();
              else setActive(false);
            },
          );

          controller.signal.throwIfAborted();
          setActive(true);
          break;
        }
        catch (error) {
          if (controller.signal.aborted) return;

          // Read the flag before dropping the reference: an invalidated pairing
          // must not be retried with keys that can never authenticate again.
          const pairingInvalidated = current?._internal.isPairingInvalidated ?? false;

          current = undefined;

          if (!parameters && !pairingInvalidated && loadWalletSession() && attempt < 2) {
            try {
              await pause(500 * (attempt + 1), controller.signal);
            }
            catch {
              return;
            }

            if (controller.signal.aborted) return;

            continue;
          }

          const reason = error instanceof Error ? error.message : String(error);

          if (parameters || loadWalletSession()) actions.setPhase("error");

          actions.appendEntry({
            role: "wallet",
            direction: "in",
            kind: "info",
            summary: "Connection failed",
            payload: { message: reason },
          });
          break;
        }
      }

      if (!isDisposed && !controller.signal.aborted) setConnecting(false);
    };

    return {
      connect: (url: string) => run(url),
      resume: () => {
        isDisposed = false;

        return run();
      },
      end,
      dispose: () => {
        isDisposed = true;
        void release(false);
      },
    };
  }, [config, actions]);

  useEffect(() => {
    void lifecycle.resume();

    return lifecycle.dispose;
  }, [lifecycle]);

  return { active, connecting, connect: lifecycle.connect, end: lifecycle.end };
};
