import { createRequire } from "node:module";

import { expect, test } from "@playwright/test";

import { expectConnected, pairThroughUi } from "./helpers/documentation-session.js";
import {
  captureStates,
  hasMaterial,
  installWallet,
  WALLET_NAME,
  WALLET_SESSION_KEY,
} from "./helpers/documentation-wallet.js";

const requireDocumentation = createRequire(new URL("../../docs/package.json", import.meta.url));

type SavedPairing = {
  sessionId: string;
  pairingId: string;
  encryptionKey: string;
  relyingPublicKey: string;
  lastSeenCounter: number;
};
const { parseSessionConnectionParameters } = requireDocumentation("@openlv/core") as {
  parseSessionConnectionParameters: (value: unknown) => SavedPairing | undefined;
};
const { parseEncryptionKey } = requireDocumentation("@openlv/core/encryption") as {
  parseEncryptionKey: (value: string) => Promise<{ encrypt: (value: string) => Promise<string>; }>;
};
const { connectAsync } = requireDocumentation("mqtt") as {
  connectAsync: (url: string) => Promise<{
    publishAsync: (topic: string, message: string) => Promise<void>;
    endAsync: () => Promise<void>;
  }>;
};

declare global {
  interface Window {
    openlvTerminalChannels: RTCDataChannel[];
  }
}

const DOCS_URL = process.env["OPENLV_E2E_DOCS_URL"] ?? "http://127.0.0.1:5198/try";
const RELAY = process.env["OPENLV_E2E_RELAY"] ?? "ws://test.mosquitto.org:8080/mqtt";

test.use({ trace: "off", screenshot: "off", video: "off" });

test("wallet invalidates a rejected pairing after transport loss without a second disconnected event", async ({ browser }, testInfo) => {
  const hostContext = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"] });
  const walletContext = await browser.newContext();
  const states: string[] = [];

  await installWallet(walletContext);
  await hostContext.addInitScript((relay) => {
    localStorage.setItem("@openlv/connector/settings", JSON.stringify({
      version: 3, autoReconnect: true, retainHistory: false,
      signaling: { p: "mqtt", s: { mqtt: relay } },
      transport: { p: "webrtc" }, theme: "system",
    }));
  }, RELAY);
  // Observe and close the real data channel, not a replacement transport.
  await walletContext.addInitScript(() => {
    Object.assign(globalThis, { openlvTerminalChannels: [] });
    const Original = globalThis.RTCPeerConnection;

    Object.assign(globalThis, {
      RTCPeerConnection: new Proxy(Original, {
        construct(target, arguments_) {
          const connection = Reflect.construct(target, arguments_) as RTCPeerConnection;

          connection.addEventListener("datachannel", (event) => {
            globalThis.openlvTerminalChannels.push(event.channel);
          });

          return connection;
        },
      }),
    });
  });
  const host = await hostContext.newPage();
  const wallet = await walletContext.newPage();
  const publisher = await connectAsync(RELAY);

  captureStates(host, "host", states);
  captureStates(wallet, "wallet", states);

  try {
    await Promise.all([host.goto(DOCS_URL), wallet.goto(DOCS_URL)]);
    await wallet.getByRole("button", { name: WALLET_NAME, exact: true }).first()
      .click();
    await pairThroughUi(host, wallet);
    await expectConnected(wallet);
    const raw = await wallet.evaluate(key => globalThis.sessionStorage.getItem(key), WALLET_SESSION_KEY);
    const saved = parseSessionConnectionParameters(JSON.parse(raw ?? "null"));

    if (!saved) throw new Error("Wallet did not save its pairing");

    const key = await parseEncryptionKey(saved.encryptionKey);
    const frame = `xc${await key.encrypt(JSON.stringify({
      type: "resume",
      payload: {
        version: 1,
        pairingId: `${saved.pairingId}x`,
        publicKey: saved.relyingPublicKey,
        challenge: "abcdefghijklmnop",
        counter: saved.lastSeenCounter + 1,
      },
      timestamp: Date.now(),
    }))}`;

    await wallet.evaluate(async () => {
      const channel = globalThis.openlvTerminalChannels.find(candidate => candidate.readyState === "open");

      if (!channel) throw new Error("Wallet data channel was not open");

      const { promise, resolve } = Promise.withResolvers<void>();

      channel.addEventListener("close", () => resolve(), { once: true });
      channel.close();
      await promise;
    });
    expect(await hasMaterial(wallet, WALLET_SESSION_KEY)).toBe(true);
    await publisher.publishAsync(saved.sessionId, frame);
    await expect.poll(() => hasMaterial(wallet, WALLET_SESSION_KEY), { timeout: 10_000 }).toBe(false);
    await expect(wallet.getByText("Failed", { exact: true })).toBeVisible();
    await expect(wallet.getByRole("button", { name: "End", exact: true })).toHaveCount(0);
    await expect(wallet.getByPlaceholder("openlv://...")).toBeEnabled();
  }
  finally {
    await testInfo.attach("redacted-session-states", { body: states.join("\n"), contentType: "text/plain" });
    await publisher.endAsync();
    await Promise.all([hostContext.close(), walletContext.close()]);
  }
});
