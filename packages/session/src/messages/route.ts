import type { TransportLayer, TransportMessage } from "@openlv/transport";
import type { EventEmitter } from "eventemitter3";

import type { SessionEvents } from "../events.js";
import { log } from "../utils/log.js";
import type { CorrelationEvents } from "./correlate.js";
import { isSessionMessage, type SessionMessage, type SessionMessageRequest } from "./index.js";

export type SessionMessagingContext = {
  // Wallet-side handler for inbound requests.
  onMessage: (payload: unknown) => Promise<unknown>;
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
  handleTransportMessage: (message: object) => Promise<void>;
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

  let answer: SessionMessage;

  try {
    answer = {
      type: "response",
      messageId: request.messageId,
      payload: await context.onMessage(request.payload),
    };
  }
  catch (error) {
    log("request handler threw", error);
    answer = { type: "failed", messageId: request.messageId };
  }

  await transport.send(answer);
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
    message: object,
  ): Promise<void> => {
    if (isStopped()) return;

    if (!isSessionMessage(message)) {
      log("dropping invalid session message", message);
      return;
    }

    const current = getTransport();

    if (!current) return;

    try {
      if (message.type === "close") {
        await close();

        return;
      }

      if (message.type === "request") {
        await respondToRequest(message, current, context);
      }
      else {
        messages.emit("message", message);
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
