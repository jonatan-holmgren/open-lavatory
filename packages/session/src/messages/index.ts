import type { JsonValue } from "@openlv/transport";

export type SessionMessage
  = | SessionMessageRequest
    | SessionMessageResponse
    | SessionMessageAck
    | SessionMessageClose;

export type SessionMessageRequest = {
  type: "request";
  messageId: string;
  payload: JsonValue;
};

export type SessionMessageResponse = {
  type: "response";
  messageId: string;
  payload: JsonValue;
};

export type SessionMessageAck = {
  type: "ack";
  messageId: string;
};

export type SessionMessageClose = {
  type: "close";
};
