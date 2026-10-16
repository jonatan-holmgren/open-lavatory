
import {
  encodeConnectionURL,
  type Observable,
  observable,
  type SessionConnectionParameters,
  type SessionLinkParameters,
} from "@openlv/core";
import {
  createSession,
  type Session,
  SessionStatus,
} from "@openlv/session";
import type { PeerInfo } from "@openlv/signaling";
import { Status as SignalStatus } from "@openlv/signaling";
import type { TransportProtocol } from "@openlv/transport";
import { webrtc, type WebRTCConfig } from "@openlv/transport/webrtc";
import { Provider as OxProvider } from "ox";
import type { EventMap } from "ox/Provider";
import type { ExtractReturnType } from "ox/RpcSchema";
import { match } from "ts-pattern";
import type { Address, Prettify } from "viem";

import type { RpcSchema } from "./rpc.js";
import {
  createProviderStorage,
  type ProviderStorageParameters,
  type ProviderStorageR,
} from "./storage/index.js";
import type { SignalingProtocol } from "./storage/version.js";
import { log } from "./utils/log.js";

/** Unwrap `{ result }` / `{ error }` envelopes from wallet session handlers. */
const unwrapSessionResponse = (payload: unknown): unknown => {
  if (typeof payload !== "object" || payload === null) {
    return payload;
  }

  if ("error" in payload && payload.error) {
    const rpcError = payload.error as {
      code: number;
      message: string;
      data?: unknown;
    };

    throw Object.assign(new Error(rpcError.message), { code: rpcError.code });
  }

  if ("result" in payload) {
    return (payload as { result: unknown; }).result;
  }

  return payload;
};

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
  } & Pick<ProviderStorageParameters, "storage">
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

  let accounts: Address[] = [];
  let unsubscribeSessionStatus: (() => void) | undefined;
  let restoringSession: Promise<Session> | undefined;
  const storage = createProviderStorage({
    storage: parameters.storage,
  });
  const { openModal, config } = parameters;

  status.subscribe(current => log("status", current));

  /**
   * Called when the remote peer (wallet) sends a request to the dApp.
   *
   * In the normal EIP-1193 flow the dApp is always the requester, so this
   * path is unusual. We emit a `request` event on the session (once the
   * session is available) so the modal or other UI consumers can react.
   * For any method we have no built-in handler for, we return a JSON-RPC
   * "Method not found" error so the wallet receives a proper response rather
   * than a no-op stub.
   */
  const onMessage = async (message: object): Promise<object> => {
    log("onMessage received from remote peer", message);

    // Emit on the session emitter so observers (e.g. modal) can react.
    session.get()?.emitter.emit("request", message);

    return {
      error: {
        code: -32_601,
        message: "Method not found",
      },
    };
  };

  const getAccounts = async (): Promise<Address[]> => {
    const current = session.get();

    if (current) {
      return unwrapSessionResponse(
        await current.send({ method: "eth_accounts", params: [] }),
      ) as Address[];
    }

    throw new Error("No session");
  };

  /** Derive default link parameters from stored signaling settings. */
  const defaultLinkParameters = (): SessionLinkParameters | undefined => {
    const signaling = storage.getSettings().signaling ?? config?.signaling;
    const p = signaling?.p;
    const s = p ? signaling?.s?.[p] : undefined;

    return p && s ? { p, s } : undefined;
  };

  const persistSession = (connection: SessionConnectionParameters) => {
    if (
      storage.getSettings().autoReconnect
      || storage.getSession()?.pairingId === connection.pairingId
    ) {
      storage.setSession(connection);
    }
  };

  const start = async (parameters?: SessionLinkParameters) => {
    setError(undefined);
    setStatus(ProviderStatus.CREATING);
    const linkParameters = parameters ?? defaultLinkParameters();

    if (!linkParameters) {
      throw new Error("No link parameters provided and no signaling defaults configured");
    }

    // Stored user settings win over constructor config; both fall back to the
    // transport's built-in defaults, so an empty list must stay undefined
    // rather than become an empty iceServers array.
    const stored = storage.getSettings().transport?.s?.webrtc;
    const iceServers = [
      ...stored?.stun?.map(urls => ({ urls })) ?? [],
      ...stored?.turn ?? [],
    ];
    const transportOptions = iceServers.length > 0
      ? { iceServers }
      : config?.transport?.s?.webrtc;

    try {
      const next = await createSession(
        linkParameters,
        [webrtc(transportOptions)],
        onMessage,
        {
          info: config?.info,
          onConnectionParametersChange: persistSession,
        },
      );

      setSession(next);
      unsubscribeSessionStatus?.();
      const onSessionStatusChange = () => {
        if (next.status.get() !== SessionStatus.DISCONNECTED || session.get() !== next) return;

        // Keep the pairing while signaling can recover a dropped transport.
        if (next.signalStatus.get() !== SignalStatus.ERROR && next._internal.transport) return;

        const reason = next.error.get();

        setSession(undefined);
        setError(reason);
        setStatus(reason ? ProviderStatus.ERROR : ProviderStatus.STANDBY);

        try {
          storage.clearSession();
        }
        catch (error) {
          log("could not delete saved session", error);
        }
      };
      const unsubscribeStatus = next.status.subscribe(onSessionStatusChange);
      const unsubscribeSignalStatus = next.signalStatus.subscribe(onSessionStatusChange);

      unsubscribeSessionStatus = () => {
        unsubscribeStatus();
        unsubscribeSignalStatus();
      };
      setStatus(ProviderStatus.CONNECTING);

      log("session created");
      await next.connect();
      log("session connected");
      const handshakeParameters = next.getHandshakeParameters();
      const url = encodeConnectionURL(handshakeParameters);

      log("session url", url);

      const settled = await next.status.until(
        state => state === SessionStatus.CONNECTED
          || state === SessionStatus.DISCONNECTED,
      );

      if (settled !== SessionStatus.CONNECTED) {
        throw new Error(next.error.get() ?? "Session failed to connect");
      }

      log("session linked");

      accounts = await getAccounts();

      const chainIdHex = unwrapSessionResponse(
        await next.send({ method: "eth_chainId", params: [] }),
      ) as string;

      setStatus(ProviderStatus.CONNECTED);

      try {
        persistSession(next.getConnectionParameters());
      }
      catch (error) {
        log("could not persist session", error);
      }

      oxEmitter.emit("connect", { chainId: chainIdHex });
      oxEmitter.emit("accountsChanged", accounts);

      return next;
    }
    catch (error_) {
      // Surface the failure to UI consumers (e.g. the modal) instead of
      // leaving the provider stuck in "connecting".
      setError(
        session.get()?.error.get()
        ?? (error_ instanceof Error ? error_.message : "Connection failed"),
      );
      setStatus(ProviderStatus.ERROR);
      throw error_;
    }
  };
  const closeSession = async () => {
    await session.get()?.close();
    setSession(undefined);
    setError(undefined);
    setStatus(ProviderStatus.STANDBY);
    storage.clearSession();
  };

  const restoreSession = async (): Promise<Session> => {
    if (restoringSession) return await restoringSession;

    const current = session.get();

    if (current) return current;

    const saved = storage.getSession();

    if (!saved) throw new Error("No saved session to restore");

    const pending = (async () => {
      // Assign restoringSession before start notifies synchronous subscribers.
      await Promise.resolve();

      return await start(saved);
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

    return (
      match(request)
        .with({ method: "eth_chainId" }, async () => {
          log("eth_chainId");

          const current = session.get();

          if (current) {
            log("sending eth_chainId to session");
            const result = unwrapSessionResponse(
              await current.send(request),
            );

            log("eth_chainId result from session", result);

            return result;
          }

          return "0x1";
        })
        .with({ method: "wallet_requestPermissions" }, () => {
          throw new Error("Not implemented");
        })
        .with({ method: "wallet_revokePermissions" }, async () => {
          await closeSession();

          return;
        })
        .with({ method: "eth_requestAccounts" }, async () => {
          log("eth_requestAccounts");

          if (restoringSession) {
            await restoringSession;

            return await getAccounts();
          }

          let provider: OpenLVProvider | undefined;

          if (oxProvider) {
            provider = oxProvider as OpenLVProvider;
          }

          if (openModal && provider) {
            await openModal(provider);

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
                provider?.off("connect", onConnect);
                provider?.off("disconnect", onDisconnect);
              };

              provider?.on("connect", onConnect);
              provider?.on("disconnect", onDisconnect);
            });

            return await getAccounts();
          }

          await start();

          return await getAccounts();
        })
        .with({ method: "eth_accounts" }, async () => {
          log("eth_accounts");

          if (restoringSession) await restoringSession;

          return await getAccounts();
        })
        .otherwise(async (v) => {
          const current = session.get();

          if (current) {
            log("sending request to session", request);
            const result = unwrapSessionResponse(
              await current.send(request),
            );

            log("result from session", result);

            return result;
          }

          throw new Error(`Method ${v.method} not supported`);
        }) as unknown as ExtractReturnType<RpcSchema, typeof request.method>
    );
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
    getAccounts,
    createSession: start,
    restoreSession,
    closeSession,
    status,
    error,
    session,
  });

  if (storage.getSettings().autoReconnect && storage.getSession()) {
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
