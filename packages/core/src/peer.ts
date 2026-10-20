/** Optional self-description shown in the other peer's UI. */
export type PeerInfo = {
  /** Reverse-DNS application identifier, e.g. "com.example.wallet". */
  identity: string;
  name: string;
  /**
   * A data URI or an image URL. Only size is enforced on the wire -- anyone
   * rendering or fetching it is responsible for sanity-checking it first.
   */
  icon?: string;
};

export type PeerCapabilities = {
  /** Supported transport identifiers, in preference order. */
  transports: string[];
  info?: PeerInfo;
};

export const MAX_PEER_TEXT_LENGTH = 128;
export const MAX_PEER_ICON_LENGTH = 8192;
export const MAX_PEER_TRANSPORTS = 8;
export const MAX_TRANSPORT_ID_LENGTH = 32;

const isBoundedString = (value: unknown, maxLength: number): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= maxLength;

export const validatePeerInfo = (info: PeerInfo): string | undefined => {
  if (!isBoundedString(info.identity, MAX_PEER_TEXT_LENGTH)) {
    return `info.identity must be 1-${MAX_PEER_TEXT_LENGTH} characters`;
  }

  if (!isBoundedString(info.name, MAX_PEER_TEXT_LENGTH)) {
    return `info.name must be 1-${MAX_PEER_TEXT_LENGTH} characters`;
  }

  if (info.icon !== undefined && !isBoundedString(info.icon, MAX_PEER_ICON_LENGTH)) {
    return `info.icon must be 1-${MAX_PEER_ICON_LENGTH} characters -- use a smaller image or an image URL`;
  }

  return undefined;
};

export const parsePeerCapabilities = (
  value: unknown,
): PeerCapabilities | undefined => {
  if (typeof value !== "object" || value === null) return undefined;

  const payload = value as Record<string, unknown>;
  const transports = payload["transports"];

  if (
    !Array.isArray(transports)
    || transports.length === 0
    || transports.length > MAX_PEER_TRANSPORTS
    || transports.some(transportId => !isBoundedString(transportId, MAX_TRANSPORT_ID_LENGTH))
  ) {
    return undefined;
  }

  if (payload["info"] === undefined) return { transports };

  const rawInfo = payload["info"];

  if (typeof rawInfo !== "object" || rawInfo === null) return undefined;

  const info = rawInfo as Record<string, unknown>;

  if (!isBoundedString(info["identity"], MAX_PEER_TEXT_LENGTH)) return undefined;

  if (!isBoundedString(info["name"], MAX_PEER_TEXT_LENGTH)) return undefined;

  if (
    info["icon"] !== undefined
    && !isBoundedString(info["icon"], MAX_PEER_ICON_LENGTH)
  ) {
    return undefined;
  }

  return {
    transports,
    info: {
      identity: info["identity"],
      name: info["name"],
      ...(info["icon"] !== undefined && { icon: info["icon"] }),
    },
  };
};
