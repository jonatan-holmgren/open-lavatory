import type { IncomingMessage, TransportLayer, TransportMessage } from "@openlv/transport";
import type { EventEmitter } from "eventemitter3";

import type { SessionEvents } from "../events.js";
import { log } from "../utils/log.js";
import type { CorrelationEvents } from "./correlate.js";
import type {
  SessionMessage,
  SessionMessageAck,
  SessionMessageRequest,
  SessionMessageResponse,
} from "./index.js";

export type SessionMessagingContext = {
  // Wallet-side handler for inbound requests.
  onMessage: (payload: object) => Promise<object | string>;
  emitter: EventEmitter<SessionEvents>;
  // Correlation bus for open send() calls.
  messages: EventEmitter<CorrelationEvents>;
  getTransport: () => TransportLayer | undefined;
  isTransportReady: () => boolean;
  isStopped: () => boolean;
  // Ends the session when the peer sends a close frame.
  close: () => Promise<void>;
};

export type SessionMessaging = {
  handleTransportMessage: (message: IncomingMessage) => Promise<void>;
  handleSignalMessage: (message: object) => Promise<void>;
  flushNegotiation: () => Promise<void>;
  clearNegotiation: () => void;
};

const respondToRequest = async (
  request: SessionMessageRequest,
  transport: TransportLayer,
  context: SessionMessagingContext,
): Promise<void> => {
  // Acknowledge before the handler can wait for user interaction.
  await transport.send({ type: "ack", messageId: request.messageId } satisfies SessionMessage);
  context.emitter.emit("request", request.payload);

  let payload: object | string;

  try {
    payload = await context.onMessage(request.payload as object);
  }
  catch {
    payload = { error: { code: -32_603, message: "Internal error" } };
  }

  await transport.send({
    type: "response",
    messageId: request.messageId,
    payload,
  } satisfies SessionMessage);
};

/**
 * Routes session messages between the transport, the signaling channel, and
 * the correlation bus. Negotiation frames are buffered while the transport is
 * being (re)built so a resumed peer's offer is not lost.
 */
export const createSessionMessaging = (
  context: SessionMessagingContext,
): SessionMessaging => {
  const { messages, getTransport, isTransportReady, isStopped, close } = context;
  const MAX_PENDING_NEGOTIATION = 32;
  let pendingNegotiation: TransportMessage[] = [];

  const handleTransportMessage = async (
    message: IncomingMessage,
  ): Promise<void> => {
    if (isStopped()) return;

    const current = getTransport();

    if (!current) return;

    try {
      if (message.type === "close") {
        await close();

        return;
      }

      if (message.type === "request") {
        await respondToRequest(message as SessionMessageRequest, current, context);
      }
      else if (message.type === "response" || message.type === "ack") {
        messages.emit("message", message as SessionMessageAck | SessionMessageResponse);
      }
    }
    catch (error) {
      log("failed to handle peer message", error);
    }
  };

  const handleSignalMessage = async (message: object): Promise<void> => {
    if (isStopped()) return;

    const sessionMessage = message as SessionMessage;

    if (sessionMessage.type === "response") {
      messages.emit("message", sessionMessage);
    }
    else if (sessionMessage.type === "request") {
      const negotiationMessage = sessionMessage.payload as TransportMessage;

      const current = getTransport();

      if (!current || !isTransportReady()) {
        if (pendingNegotiation.length >= MAX_PENDING_NEGOTIATION) {
          log("dropping oldest buffered negotiation message");
          pendingNegotiation.shift();
        }

        pendingNegotiation.push(negotiationMessage);

        return;
      }

      try {
        await current.handle(negotiationMessage);
      }
      catch (error) {
        log("failed to handle negotiation message", error);
      }
    }
  };

  const flushNegotiation = async (): Promise<void> => {
    const current = getTransport();

    if (!current || !isTransportReady() || pendingNegotiation.length === 0) return;

    const buffered = pendingNegotiation;

    pendingNegotiation = [];

    for (const message of buffered) {
      try {
        await current.handle(message);
      }
      catch (error) {
        log("failed to handle buffered negotiation message", error);
      }
    }
  };

  return {
    handleTransportMessage,
    handleSignalMessage,
    flushNegotiation,
    clearNegotiation: () => {
      pendingNegotiation = [];
    },
  };
};
