import {
  encodeConnectionURL,
  parseSessionConnectionParameters,
  type SessionConnectionParameters,
} from "@openlv/core";
import {
  connectSession,
  createSession,
  InvalidSavedSessionError,
  type PeerInfo,
  type Session,
  SessionStatus,
} from "@openlv/session";
import { webrtc } from "@openlv/transport/webrtc";
import { useEffect, useMemo, useState } from "react";
import type { EIP1193Provider } from "viem";
import type { Config, Connector } from "wagmi";

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

const findWalletConnector = (connections: Config["state"]["connections"]) => {
  for (const { connector, accounts } of connections.values()) {
    if (connector.type !== "openLv" && accounts.length > 0) return connector;
  }

  return undefined;
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
  const stopStatusWatch = session.status.subscribe((status) => {
    if (status === SessionStatus.CONNECTED) settle(status);
  });
  const onSessionClosed = (reason: string | undefined, isPairingInvalidated: boolean) => {
    if (signal.aborted) return;

    if (reason === undefined || isPairingInvalidated) clearWalletSession();

    if (reason !== undefined) actions.setPhase("error");

    settle(SessionStatus.DISCONNECTED);
    onClosed(reason);
  };

  session.emitter.on("close", onSessionClosed);
  const detach = () => {
    detachLog();
    stopStatusWatch();
    session.emitter.off("close", onSessionClosed);
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
    // Persist only after the peer has completed the handshake.
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
 * Each restore attempt reloads the saved pairing credentials.
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
      // Clear before awaiting so an in-flight restore cannot revive this pairing.
      clearWalletSession();
      await release(true);

      if (!isDisposed) {
        setActive(false);
        setConnecting(false);
        actions.resetSession();
      }
    };
    const run = async (parameters?: string, preferredConnector?: Connector) => {
      if (!parameters && !loadWalletSession()) return;

      const cleanup = parameters ? end() : release(false);
      // Register before yielding: StrictMode's cleanup must cancel this exact
      // attempt, even if its replacement mounts before cleanup has resolved.
      const controller = new AbortController();

      operation = controller;
      await cleanup;

      if (isDisposed || controller.signal.aborted) return;

      setConnecting(true);

      try {
        const connector = preferredConnector ?? findWalletConnector(config.state.connections);

        if (!connector) throw new Error("No authorized wallet connector is connected");

        controller.signal.throwIfAborted();
        const client = await connector.getProvider() as EIP1193Provider | undefined;

        if (!client) throw new Error("Wallet provider is not ready");

        const material = parameters ?? loadWalletSession();

        if (!material) {
          if (!isDisposed && !controller.signal.aborted) setConnecting(false);

          return;
        }

        actions.setPhase("establishing");
        actions.setPeer(peerInfoFromConnectionUrl(
          "wallet",
          typeof material === "string" ? material : encodeConnectionURL(material),
        ));
        await connectWalletSession(
          material, connector, client, actions, controller.signal,
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
      }
      catch (error) {
        if (controller.signal.aborted) return;

        if (!parameters && error instanceof InvalidSavedSessionError) clearWalletSession();

        current = undefined;
        const reason = error instanceof Error ? error.message : String(error);

        actions.setPhase("error");

        actions.appendEntry({
          role: "wallet",
          direction: "in",
          kind: "info",
          summary: "Connection failed",
          payload: { message: reason },
        });
      }

      if (!isDisposed && !controller.signal.aborted) setConnecting(false);
    };

    return {
      connect: (url: string) => run(url),
      resume: (connector?: Connector) => {
        isDisposed = false;

        return run(undefined, connector);
      },
      end,
      dispose: () => {
        isDisposed = true;
        void release(false);
      },
    };
  }, [config, actions]);

  useEffect(() => {
    let lastConnectorUid: string | undefined;
    const stopWatching = config.subscribe(
      state => state.connections,
      (connections) => {
        const connector = findWalletConnector(connections);

        if (!connector) {
          lastConnectorUid = undefined;

          return;
        }

        if (connector.uid === lastConnectorUid) return;

        lastConnectorUid = connector.uid;
        void lifecycle.resume(connector);
      },
      { emitImmediately: true },
    );

    return () => {
      stopWatching();
      lifecycle.dispose();
    };
  }, [config, lifecycle]);

  return { active, connecting, connect: lifecycle.connect, end: lifecycle.end };
};
