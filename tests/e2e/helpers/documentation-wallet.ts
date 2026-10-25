import { createRequire } from "node:module";

import type { BrowserContext } from "@playwright/test";

// Resolve through the docs dependency graph rather than adding a second viem version.
const requireDocumentation = createRequire(new URL("../../../docs/package.json", import.meta.url));
const { privateKeyToAccount } = requireDocumentation("viem/accounts") as {
  privateKeyToAccount: (key: `0x${string}`) => {
    address: `0x${string}`;
    signMessage: (arguments_: { message: { raw: `0x${string}`; }; }) => Promise<`0x${string}`>;
  };
};
const account = privateKeyToAccount(`0x${"11".repeat(32)}`);

export const WALLET_NAME = "OpenLV E2E Wallet";
export const WALLET_ADDRESS = account.address;
export const WALLET_SESSION_KEY = "@openlv/docs/wallet-session";
export const HOST_SESSION_KEY = "@openlv/connector/session";

export const installWallet = async (context: BrowserContext) => {
  let signatures = 0;

  await context.exposeBinding("openlvE2eWalletReady", async () => {});
  await context.exposeBinding("openlvE2eSign", async (_source, data: `0x${string}`) => {
    signatures += 1;

    return await account.signMessage({ message: { raw: data } });
  });
  await context.addInitScript(({ address, name }) => {
    const listeners = new Map<string, Set<(...arguments_: unknown[]) => void>>();
    const provider = {
      isConnected: () => true,
      request: async ({ method, params }: { method: string; params?: unknown[]; }) => {
        switch (method) {
          case "eth_accounts": {
            await globalThis.openlvE2eWalletReady();

            return localStorage.getItem("@openlv/e2e/injected-wallet-approved") === "true" ? [address] : [];
          }
          case "eth_requestAccounts": {
            localStorage.setItem("@openlv/e2e/injected-wallet-approved", "true");

            return [address];
          }
          case "eth_chainId": {
            return "0x1";
          }
          case "net_version": {
            return "1";
          }
          case "wallet_requestPermissions": {
            localStorage.setItem("@openlv/e2e/injected-wallet-approved", "true");

            return [{ parentCapability: "eth_accounts" }];
          }
          case "wallet_getPermissions": {
            return localStorage.getItem("@openlv/e2e/injected-wallet-approved") === "true"
              ? [{ parentCapability: "eth_accounts" }]
              : [];
          }
          case "personal_sign": {
            const data = params?.[0];

            if (typeof data !== "string" || !/^0x[0-9a-f]*$/i.test(data)) {
              throw new Error("Expected hex personal_sign message");
            }

            return await globalThis.openlvE2eSign(data);
          }
          default: {
            throw Object.assign(new Error(`Unsupported injected method: ${method}`), { code: 4200 });
          }
        }
      },
      on: (event: string, listener: (...arguments_: unknown[]) => void) => {
        const handlers = listeners.get(event) ?? new Set();

        handlers.add(listener);
        listeners.set(event, handlers);
      },
      removeListener: (event: string, listener: (...arguments_: unknown[]) => void) => {
        listeners.get(event)?.delete(listener);
      },
    };

    Object.defineProperty(globalThis, "ethereum", { value: provider, configurable: true });
    const announce = () => globalThis.dispatchEvent(new CustomEvent("eip6963:announceProvider", {
      detail: Object.freeze({
        info: {
          uuid: "b5ef40b7-9eba-4b1b-b416-af94f2c71001",
          name,
          icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>",
          rdns: "sh.openlv.e2e",
        },
        provider,
      }),
    }));

    globalThis.addEventListener("eip6963:requestProvider", announce);
    announce();
  }, { address: account.address, name: WALLET_NAME });

  return { signatureCount: () => signatures };
};
