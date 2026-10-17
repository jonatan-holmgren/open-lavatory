import { createRequire } from "node:module";

import type { BrowserContext, Page } from "@playwright/test";

declare global {
  interface Window {
    openlvE2eSign: (walletName: string, data: string) => Promise<string>;
    openlvE2eWalletReady: () => Promise<void>;
  }
}

// Resolve through the docs dependency graph rather than adding a second viem version.
const requireDocumentation = createRequire(new URL("../../../docs/package.json", import.meta.url));
const { privateKeyToAccount } = requireDocumentation("viem/accounts") as {
  privateKeyToAccount: (key: `0x${string}`) => {
    address: `0x${string}`;
    signMessage: (arguments_: { message: { raw: `0x${string}`; }; }) => Promise<`0x${string}`>;
  };
};
// Public, deterministic test account only. Never fund it.
const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
const secondAccount = privateKeyToAccount(`0x${"22".repeat(32)}`);

export const WALLET_NAME = "OpenLV E2E Wallet";
export const SECOND_WALLET_NAME = "OpenLV E2E Wallet B";
export const WALLET_ADDRESS = account.address;
export const SECOND_WALLET_ADDRESS = secondAccount.address;
export const WALLET_SESSION_KEY = "@openlv/docs/wallet-session";
export const HOST_SESSION_KEY = "@openlv/connector/session";

export const installWallet = async (context: BrowserContext, options: { secondWallet?: boolean; } = {}) => {
  const signatures = new Map<string, number>();
  let isOfflineOnReconnect = false;
  let offlineStarts = 0;

  await context.exposeBinding("openlvE2eWalletReady", async (source) => {
    if (!isOfflineOnReconnect) {
      return;
    }

    isOfflineOnReconnect = false;
    // Production streams the document; dropping the network before load can
    // replace it with a browser error page rather than exercising resumption.
    await source.page.waitForLoadState("load");
    await context.setOffline(true);
    offlineStarts += 1;
  });

  await context.exposeBinding("openlvE2eSign", async (_source, walletName: string, message: `0x${string}`) => {
    const signer = walletName === SECOND_WALLET_NAME ? secondAccount : account;
    const signature = await signer.signMessage({ message: { raw: message } });

    signatures.set(walletName, (signatures.get(walletName) ?? 0) + 1);

    return signature;
  });
  const wallets = [
    { address: account.address, name: WALLET_NAME, suffix: "1" },
    ...(options.secondWallet ? [{ address: secondAccount.address, name: SECOND_WALLET_NAME, suffix: "2" }] : []),
  ];

  await context.addInitScript((injectedWallets) => {
    type Listener = (...arguments_: unknown[]) => void;

    for (const { address, name, suffix } of injectedWallets) {
      const listeners = new Map<string, Set<Listener>>();
      let chainId = "0x1";
      const approvalKey = suffix === "1"
        ? "@openlv/e2e/injected-wallet-approved"
        : `@openlv/e2e/injected-wallet-approved-${suffix}`;
      const provider = {
        isConnected: () => true,
        request: async ({ method, params }: { method: string; params?: unknown[]; }) => {
          switch (method) {
            case "eth_accounts": {
              await globalThis.openlvE2eWalletReady();

              return localStorage.getItem(approvalKey) === "true" ? [address] : [];
            }
            case "eth_requestAccounts": {
              localStorage.setItem(approvalKey, "true");

              return [address];
            }
            case "eth_chainId": {
              return chainId;
            }
            case "net_version": {
              return String(Number(chainId));
            }
            case "wallet_requestPermissions": {
              localStorage.setItem(approvalKey, "true");

              return [{ parentCapability: "eth_accounts" }];
            }
            case "wallet_getPermissions": {
              return localStorage.getItem(approvalKey) === "true" ? [{ parentCapability: "eth_accounts" }] : [];
            }
            case "wallet_switchEthereumChain": {
              const chain = params?.[0];

              if (!chain || typeof chain !== "object" || !("chainId" in chain) || typeof chain.chainId !== "string") {
                throw new Error("Expected chainId for wallet_switchEthereumChain");
              }

              chainId = chain.chainId;
              listeners.get("chainChanged")?.forEach(listener => listener(chainId));

              return null;
            }
            case "personal_sign": {
              const data = params?.[0];

              if (typeof data !== "string" || !/^0x[0-9a-f]*$/i.test(data)) {
                throw new Error("Expected hex personal_sign message");
              }

              return globalThis.openlvE2eSign(name, data);
            }
            default: {
              throw Object.assign(new Error(`Unsupported injected method: ${method}`), { code: 4200 });
            }
          }
        },
        on: (event: string, listener: Listener) => {
          const handlers = listeners.get(event) ?? new Set<Listener>();

          handlers.add(listener);
          listeners.set(event, handlers);
        },
        removeListener: (event: string, listener: Listener) => {
          listeners.get(event)?.delete(listener);
        },
      };

      if (suffix === "1") Object.defineProperty(globalThis, "ethereum", { value: provider, configurable: true });

      const announce = () => globalThis.dispatchEvent(new CustomEvent("eip6963:announceProvider", {
        detail: Object.freeze({
          info: {
            uuid: `b5ef40b7-9eba-4b1b-b416-af94f2c7100${suffix}`,
            name,
            icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>",
            rdns: suffix === "1" ? "sh.openlv.e2e" : `sh.openlv.e2e.wallet${suffix}`,
          },
          provider,
        }),
      }));

      globalThis.addEventListener("eip6963:requestProvider", announce);
      announce();
    }
  }, wallets);

  return {
    signatureCount: (walletName?: string) => (walletName
      ? signatures.get(walletName) ?? 0
      : signatures.values().reduce((sum, count) => sum + count, 0)),
    takeOfflineOnReconnect: () => { isOfflineOnReconnect = true; },
    offlineStarts: () => offlineStarts,
  };
};

/** Keep only known state tokens; raw debug logs can contain pairing secrets. */
export const captureStates = (page: Page, role: string, lines: string[]) => {
  page.on("console", (message) => {
    const match = message.text().match(
      /(?:signal state change|updateStatus|provider status|onConnectionStateChange|iceGatheringState|webrtc handle)\s+(connected|disconnected|encrypted|connecting|linking|resuming|error|failed|closed|open|new|checking|completed|complete|gathering|stable|offer|answer|candidate)\b/i,
    );

    if (match) lines.push(`${role}: ${match[0]}`);

    const failure = message.text().match(/(?:Resume-confirm proof is invalid|Resume-ack (?:challenge mismatch|counter did not advance)|Resume counter did not advance|resume replaced in-flight responder|resume-confirm proof mismatch|session teardown|webrtc teardown|Authenticated resume timed out|Session closed by peer|transport error|Data channel closed)/);

    if (failure) lines.push(`${role}: ${failure[0]}`);

    if (lines.length > 200) lines.shift();
  });
  page.on("pageerror", () => {
    lines.push(`${role}: pageerror (details omitted)`);
  });
};

export const hasMaterial = (page: Page, key: string) => page.evaluate(
  storageKey => globalThis.sessionStorage.getItem(storageKey) !== null,
  key,
);
