import type { TransportLayer } from "@openlv/transport";
import type { EventEmitter } from "eventemitter3";

import type { SessionEvents } from "../events.js";

export type SessionMessage
  = | SessionMessageRequest
    | SessionMessageResponse
    | SessionMessageAck
    | SessionMessageClose;

export type SessionMessageRequest = {
  type: "request";
  messageId: string;
  payload: object | string;
};

export type SessionMessageResponse = {
  type: "response";
  messageId: string;
  payload: object | string;
};

export type SessionMessageAck = {
  type: "ack";
  messageId: string;
};

export type SessionMessageClose = {
  type: "close";
};

export const respondToRequest = async (
  request: SessionMessageRequest,
  transport: TransportLayer,
  onMessage: (payload: object) => Promise<object | string>,
  events: EventEmitter<SessionEvents>,
): Promise<void> => {
  // Acknowledge before the handler can wait for user interaction.
  await transport.send({ type: "ack", messageId: request.messageId } satisfies SessionMessage);
  events.emit("request", request.payload);

  let payload: object | string;

  try {
    payload = await onMessage(request.payload as object);
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
