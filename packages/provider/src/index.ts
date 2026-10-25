/* eslint-disable max-lines -- Provider lifecycle invariants stay beside their state owner. */
import {
  encodeConnectionURL,
  type Observable,
  observable,
  type PeerInfo,
  type SessionLinkParameters,
} from "@openlv/core";
import {
  createSession,
  InvalidSavedSessionError,
  type Session,
  SessionStatus,
} from "@openlv/session";
import type { TransportProtocol } from "@openlv/transport";
import { webrtc, type WebRTCConfig } from "@openlv/transport/webrtc";
import { Provider as OxProvider } from "ox";
import type { EventMap } from "ox/Provider";
import type { ExtractReturnType } from "ox/RpcSchema";
import type { Address, Prettify } from "viem";

import {
  createWalletRpcClient,
  jsonRpcRequest,
  type RpcSchema,
} from "./rpc.js";
import {
  createProviderStorage,
  type ProviderStorageParameters,
  type ProviderStorageR,
} from "./storage/index.js";
import type { SignalingProtocol } from "./storage/version.js";
import { log } from "./utils/log.js";

export type OpenLVProviderConfig = {
  /** Shared with the wallet during the handshake and shown in its UI. */
  info?: PeerInfo;
  signaling?: {
    p?: SignalingProtocol;
    s?: Record<SignalingProtocol, string>;
  };
  transport?: {
    p?: TransportProtocol;
    s?: Record<TransportProtocol, WebRTCConfig>;
  };
};

export type OpenLVProviderParameters = Prettify<
  {
    config?: OpenLVProviderConfig;
    openModal?: (provider: OpenLVProvider) => Promise<void>;
  } & Pick<ProviderStorageParameters, "storage" | "sessionStorage">
>;

export const ProviderStatus = {
  STANDBY: "standby",
  CREATING: "creating",
  CONNECTING: "connecting",
  CONNECTED: "connected",
  ERROR: "error",
} as const;
export type ProviderStatus = (typeof ProviderStatus)[keyof typeof ProviderStatus];

export type ProviderConfig = {
  schema: RpcSchema;
};

export type ProviderBase = {
  storage: ProviderStorageR;
  createSession: (parameters?: SessionLinkParameters) => Promise<Session>;
  restoreSession: () => Promise<Session>;
  closeSession: () => Promise<void>;
  getAccounts: () => Promise<Address[]>;
  status: Observable<ProviderStatus>;
  error: Observable<string | undefined>;
  session: Observable<Session | undefined>;
};

export type OpenLVProvider = OxProvider.Provider<
  { schema: RpcSchema; },
  EventMap
>
& ProviderBase;

/** Whether startup should restore a saved pairing. */
export const hasRestorableSession = (
  storage: Pick<ProviderStorageR, "getSettings" | "getSession">,
): boolean => storage.getSettings().autoReconnect && storage.getSession() !== undefined;

/**
 * OpenLV Provider
 *
 * https://openlv.sh/api/provider
 */
export const createProvider = (
  parameters: OpenLVProviderParameters,
): OpenLVProvider => {
  const oxEmitter = OxProvider.createEmitter<EventMap>();

  const [session, setSession] = observable<Session | undefined>(undefined);
  const [status, setStatus] = observable<ProviderStatus>(ProviderStatus.STANDBY);
  const [error, setError] = observable<string | undefined>(undefined);

  let currentOperation = 0;
  let unsubscribeSession: (() => void) | undefined;
  let restoringSession: Promise<Session> | undefined;
  const storage = createProviderStorage({
    storage: parameters.storage,
    sessionStorage: parameters.sessionStorage,
  });
  const { openModal, config } = parameters;
  const walletRpc = createWalletRpcClient(async (payload) => {
    const current = session.get();

    if (!current) throw new Error("No session");

    return await current.send(payload);
  });

  status.subscribe(current => log("status", current));

  const assertCurrentOperation = (operation: number) => {
    if (operation !== currentOperation) throw new Error("Session operation superseded");
  };

  /**
   * Reset provider state for a finished operation if no subscriber has started
   * or closed another session. Returns whether this operation still owns state.
   */
  const didResetSession = (operation: number, reason?: string): boolean => {
    if (operation !== currentOperation) return false;

    unsubscribeSession?.();
    unsubscribeSession = undefined;
    setSession(undefined);

    if (operation !== currentOperation) return false;

    setError(reason);

    if (operation !== currentOperation) return false;

    setStatus(reason ? ProviderStatus.ERROR : ProviderStatus.STANDBY);

    return operation === currentOperation;
  };

  const clearSavedSession = () => {
    try {
      storage.clearSession();
    }
    catch (error) {
      log("could not delete saved session", error);
    }
  };

  // dApps do not serve wallet RPC; emit inbound requests for observers, then
  // reject unknown methods with a JSON-RPC response.
  const onMessage = async (message: unknown, operation: number): Promise<unknown> => {
    assertCurrentOperation(operation);
    log("onMessage received from remote peer", message);

    session.get()?.emitter.emit("request", message);

    const requestIdentifier = jsonRpcRequest.safeParse(message).data?.["id"] ?? null;

    return {
      jsonrpc: "2.0",
      ["id"]: requestIdentifier,
      error: {
        code: -32_601,
        message: "Method not found",
      },
    };
  };

  /** Derive default link parameters from stored signaling settings. */
  const defaultLinkParameters = (): SessionLinkParameters | undefined => {
    const signaling = storage.getSettings().signaling ?? config?.signaling;
    const p = signaling?.p;
    const s = p ? signaling?.s?.[p] : undefined;

    return p && s ? { p, s } : undefined;
  };

  const start = async (
    parameters?: SessionLinkParameters,
    operation = ++currentOperation,
    isRestoreAttempt = false,
  ) => {
    assertCurrentOperation(operation);
    setError(undefined);
    setStatus(ProviderStatus.CREATING);
    const linkParameters = parameters ?? defaultLinkParameters();

    if (!linkParameters) throw new Error("No link parameters provided and no signaling defaults configured");

    // Keep defaults for an empty ICE list; saved settings override config.
    const stored = storage.getSettings().transport?.s?.webrtc;
    const iceServers = [
      ...stored?.stun?.map(urls => ({ urls })) ?? [],
      ...stored?.turn ?? [],
    ];
    const transportOptions = iceServers.length > 0
      ? { iceServers }
      : config?.transport?.s?.webrtc;
    // A resumed pairing must persist counters even when auto-reconnect is off.
    const shouldPersist = storage.getSettings().autoReconnect
      || "pairingId" in linkParameters;
    let startedSession: Session | undefined;

    try {
      const next = await createSession(
        linkParameters,
        [webrtc(transportOptions)],
        message => onMessage(message, operation),
        {
          info: config?.info,
          onConnectionParametersChange: shouldPersist
            ? (connection) => {
                if (
                  operation === currentOperation
                  && (!startedSession || session.get() === startedSession)
                ) {
                  storage.setSession(connection);
                }
              }
            : undefined,
        },
      );

      startedSession = next;
      assertCurrentOperation(operation);

      setSession(next);
      assertCurrentOperation(operation);
      unsubscribeSession?.();
      const onSessionClosed = (reason: string | undefined, isPairingInvalidated: boolean) => {
        if (operation !== currentOperation || session.get() !== next) return;

        if (!didResetSession(operation, reason)) return;

        if (reason === undefined || isPairingInvalidated) clearSavedSession();

        if (operation !== currentOperation) return;

        const disconnectError = new OxProvider.ProviderRpcError(
          4900,
          reason ?? "Session closed by peer",
        );

        oxEmitter.emit("disconnect", disconnectError);
      };

      next.emitter.on("close", onSessionClosed);
      unsubscribeSession = () => {
        next.emitter.off("close", onSessionClosed);
      };
      setStatus(ProviderStatus.CONNECTING);
      assertCurrentOperation(operation);
      await next.connect();
      assertCurrentOperation(operation);
      log("session connected");
      log("session url", encodeConnectionURL(next.getHandshakeParameters()));

      const settled = await next.status.until(
        state => state === SessionStatus.CONNECTED
          || state === SessionStatus.DISCONNECTED,
      );

      assertCurrentOperation(operation);

      if (settled !== SessionStatus.CONNECTED) {
        throw new Error(next.error.get() ?? "Session failed to connect");
      }

      const accounts = [...await walletRpc.call({ method: "eth_accounts" })];

      assertCurrentOperation(operation);

      const chainId = await walletRpc.call({ method: "eth_chainId" });

      assertCurrentOperation(operation);

      setStatus(ProviderStatus.CONNECTED);
      assertCurrentOperation(operation);

      if (shouldPersist) storage.setSession(next.getConnectionParameters());

      assertCurrentOperation(operation);
      oxEmitter.emit("connect", { chainId });
      assertCurrentOperation(operation);
      oxEmitter.emit("accountsChanged", accounts);
      assertCurrentOperation(operation);

      return next;
    }
    catch (error_) {
      const reason = startedSession?.error.get()
        ?? (error_ instanceof Error ? error_.message : "Connection failed");

      // Retry readiness probes with the latest counters, never a half-ready session.
      if (didResetSession(operation, reason)) {
        currentOperation++;

        if (isRestoreAttempt && error_ instanceof InvalidSavedSessionError) {
          clearSavedSession();
        }
      }

      try {
        await startedSession?.close({ notifyPeer: false });
      }
      catch (error) {
        log("could not tear down failed session", error);
      }

      throw error_;
    }
  };
  const closeSession = async () => {
    const current = session.get();
    const operation = ++currentOperation;

    restoringSession = undefined;

    try {
      if (didResetSession(operation)) storage.clearSession();
    }
    finally {
      await current?.close();
    }
  };

  const restoreSession = async (): Promise<Session> => {
    if (restoringSession) return await restoringSession;

    const current = session.get();

    if (current) return current;

    const saved = storage.getSession();

    if (!saved) throw new Error("No saved session to restore");

    const operation = ++currentOperation;

    const pending = (async () => {
      // Assign restoringSession before start notifies synchronous subscribers.
      await Promise.resolve();

      return await start(saved, operation, true);
    })();

    restoringSession = pending;

    try {
      return await pending;
    }
    finally {
      if (restoringSession === pending) restoringSession = undefined;
    }
  };

  const request: OxProvider.from.Value<ProviderConfig>["request"] = async (
    request,
  ) => {
    log("ox request", request.method, request.params);

    if (request.method === "eth_chainId" && !session.get()) return "0x1";

    if (request.method === "wallet_revokePermissions") return await closeSession();

    if (request.method === "eth_accounts" && restoringSession) await restoringSession;

    if (request.method === "eth_requestAccounts") {
      log("eth_requestAccounts");

      if (restoringSession) {
        await restoringSession;
        return [...await walletRpc.call({ method: "eth_accounts" })];
      }

      if (openModal) {
        await openModal(oxProvider as OpenLVProvider);

        await new Promise<void>((resolve) => {
          const onConnect = () => {
            cleanup();
            resolve();
          };
          const onDisconnect = () => {
            cleanup();
            resolve();
          };
          const cleanup = () => {
            oxProvider.off("connect", onConnect);
            oxProvider.off("disconnect", onDisconnect);
          };

          oxProvider.on("connect", onConnect);
          oxProvider.on("disconnect", onDisconnect);
        });
      }
      else {
        await start();
      }

      return [...await walletRpc.call({ method: "eth_accounts" })];
    }

    if (!session.get()) throw new Error(`Method ${request.method} not supported`);

    log("sending request to session", request);
    const result = await walletRpc.call(request);

    log("result from session", result);

    return result as ExtractReturnType<RpcSchema, typeof request.method>;
  };
  const oxProvider = OxProvider.from<
    ProviderConfig,
    OxProvider.from.Value<ProviderConfig>
    & ProviderBase
    & OxProvider.Emitter<EventMap>
  >({
    ...oxEmitter,
    storage,
    request,
    getAccounts: async () => (
      [...await walletRpc.call({ method: "eth_accounts" })]
    ),
    createSession: start,
    restoreSession,
    closeSession,
    status,
    error,
    session,
  });

  if (hasRestorableSession(storage)) {
    void (async () => {
      try {
        await restoreSession();
      }
      catch (error) {
        log("auto-restore failed", error);
      }
    })();
  }

  return oxProvider as OpenLVProvider;
};
