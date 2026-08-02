import type { TransportPayload } from "@openlv/transport";

export type SessionPayload = TransportPayload;

export type SessionMessage
  = | SessionMessageRequest
    | SessionMessageResponse
    | SessionMessageAck
    | SessionMessageClose;

export type SessionMessageRequest = {
  type: "request";
  messageId: string;
  payload: SessionPayload;
};

export type SessionMessageResponse = {
  type: "response";
  messageId: string;
  payload: SessionPayload;
};

export type SessionMessageAck = {
  type: "ack";
  messageId: string;
};

export type SessionMessageClose = {
  type: "close";
};
