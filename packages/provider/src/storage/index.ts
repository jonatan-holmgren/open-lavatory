import {
  parseSessionConnectionParameters,
  type SessionConnectionParameters,
} from "@openlv/core";
import { EventEmitter } from "eventemitter3";

import { DEFAULT_SETTINGS } from "./default.js";
import { parseProviderStorage, type ProviderStorage } from "./version.js";

const DEFAULT_STORAGE_KEY = "@openlv/connector/settings";
const SESSION_STORAGE_KEY = "@openlv/connector/session";
const SESSION_STORAGE_VERSION = 1;

type StoredSession = {
  storageVersion: typeof SESSION_STORAGE_VERSION;
  parameters: SessionConnectionParameters;
};

export type {
  ProviderStorage,
  SignalingProtocol,
  TurnServer,
  UserThemePreference,
  WebRTCSettings,
} from "./version.js";

export type ProviderStorageParameters = {
  // Defaults to localStorage
  storage?: Storage;
  // Saved-session backend; defaults to `storage` so the dApp tab and the
  // wallet tab of the same browser can pass per-tab isolation here.
  sessionStorage?: Storage;
};

const createPassthrough = () => {
  const map = new Map<string, string>();

  return {
    getItem: (key: string) => map.get(key),
    setItem: (key: string, value: string) => {
      map.set(key, value);
    },
    removeItem: (key: string) => {
      map.delete(key);
    },
  };
};

const getStorage = () => {
  if (globalThis.window === undefined) return;

  if (!("localStorage" in globalThis)) return;

  return globalThis.localStorage;
};

export type ProviderStorageR = {
  emitter: EventEmitter<{
    settings_change: (settings: ProviderStorage) => void;
  }>;
  getSettings: () => ProviderStorage;
  setSettings: (update: ProviderStorage) => void;
  getSession: () => SessionConnectionParameters | undefined;
  setSession: (parameters: SessionConnectionParameters) => void;
  clearSession: () => void;
};

const parseStoredSession = (parsed: unknown): SessionConnectionParameters | undefined => {
  if (typeof parsed !== "object" || parsed === null) return undefined;

  const stored = parsed as Record<string, unknown>;

  return stored["storageVersion"] === SESSION_STORAGE_VERSION
    ? parseSessionConnectionParameters(stored["parameters"])
    : undefined;
};

export const createProviderStorage = ({
  storage,
  sessionStorage,
}: ProviderStorageParameters): ProviderStorageR => {
  const io = storage ?? getStorage() ?? createPassthrough();
  // Settings and sessions may live in different backends (per-tab sessions).
  const sessionIo = sessionStorage ?? io;
  const initialSettings = io.getItem(DEFAULT_STORAGE_KEY);

  let settings: ProviderStorage = initialSettings
    ? parseProviderStorage(initialSettings)
    : DEFAULT_SETTINGS;

  const emitter = new EventEmitter<{
    settings_change: (settings: ProviderStorage) => void;
  }>();

  const readSession = (): SessionConnectionParameters | undefined => {
    const raw = sessionIo.getItem(SESSION_STORAGE_KEY);

    if (!raw) return undefined;

    try {
      const parsed: unknown = JSON.parse(raw);
      const parameters = parseStoredSession(parsed);

      if (!parameters) sessionIo.removeItem(SESSION_STORAGE_KEY);

      return parameters;
    }
    catch {
      sessionIo.removeItem(SESSION_STORAGE_KEY);

      return undefined;
    }
  };

  return {
    emitter,
    getSettings: () => settings,
    setSettings: (update: ProviderStorage) => {
      settings = update;
      io.setItem(DEFAULT_STORAGE_KEY, JSON.stringify(update));
      emitter.emit("settings_change", update);
    },
    getSession: readSession,
    setSession: (parameters: SessionConnectionParameters) => {
      const stored: StoredSession = {
        storageVersion: SESSION_STORAGE_VERSION,
        parameters,
      };

      sessionIo.setItem(SESSION_STORAGE_KEY, JSON.stringify(stored));
    },
    clearSession: () => {
      sessionIo.removeItem(SESSION_STORAGE_KEY);
    },
  };
};
