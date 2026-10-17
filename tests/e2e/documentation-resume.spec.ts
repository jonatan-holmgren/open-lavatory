import { setTimeout as delay } from "node:timers/promises";

import { expect, test } from "@playwright/test";

import { expectConnected, pairThroughUi } from "./helpers/documentation-session.js";
import {
  captureStates,
  hasMaterial,
  HOST_SESSION_KEY,
  installWallet,
  SECOND_WALLET_ADDRESS,
  SECOND_WALLET_NAME,
  WALLET_ADDRESS,
  WALLET_NAME,
  WALLET_SESSION_KEY,
} from "./helpers/documentation-wallet.js";

const DOCS_URL = process.env["OPENLV_E2E_DOCS_URL"] ?? "http://127.0.0.1:5198/try";
// Override with a local broker's WebSocket listener when available.
const RELAY = process.env["OPENLV_E2E_RELAY"] ?? "ws://test.mosquitto.org:8080/mqtt";

// Traces, screenshots and videos contain connection URLs and pairing material.
test.use({ trace: "off", screenshot: "off", video: "off" });

test("docs pairing survives either reload and an offline resume, and clean teardown unpairs", async ({ browser }, testInfo) => {
  test.setTimeout(180_000);
  const hostContext = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"] });
  const walletContext = await browser.newContext();
  const states: string[] = [];
  const signed = await installWallet(walletContext);

  // Seed settings once per origin. Reloads must keep the real persisted session.
  await hostContext.addInitScript(({ relay }) => {
    if (!localStorage.getItem("@openlv/connector/settings")) {
      localStorage.setItem("@openlv/connector/settings", JSON.stringify({
        version: 3,
        retainHistory: false,
        autoReconnect: true,
        signaling: { p: "mqtt", s: { mqtt: relay } },
        transport: { p: "webrtc" },
        language: "en",
        theme: "system",
      }));
    }
  }, { relay: RELAY });
  const host = await hostContext.newPage();
  const wallet = await walletContext.newPage();

  captureStates(host, "host", states);
  captureStates(wallet, "wallet", states);

  const signThroughHost = async () => {
    const previous = signed.signatureCount();

    await host.getByRole("button", { name: "Sign", exact: true }).click();
    await expect.poll(signed.signatureCount, { timeout: 10_000 }).toBe(previous + 1);
    await expect(host.getByText("Valid signature", { exact: true })).toBeVisible({ timeout: 15_000 });
  };

  try {
    await Promise.all([host.goto(DOCS_URL), wallet.goto(DOCS_URL)]);
    await wallet.getByRole("button", { name: WALLET_NAME, exact: true }).first()
      .click();
    await pairThroughUi(host, wallet);
    await expect.poll(() => hasMaterial(host, HOST_SESSION_KEY)).toBe(true);
    await expect.poll(() => hasMaterial(wallet, WALLET_SESSION_KEY)).toBe(true);
    await signThroughHost();

    // Leave the host untouched: injected-wallet hydration and raw-session resume
    // must happen automatically, with no reconnect click or URI re-paste.
    await wallet.reload();
    await expectConnected(wallet, 10_000);
    await expectConnected(host, 10_000);
    await signThroughHost();

    await host.reload();
    await Promise.all([expectConnected(host, 10_000), expectConnected(wallet, 10_000)]);
    await signThroughHost();

    // Load the real docs assets online, then take the context offline exactly
    // when injected-wallet hydration answers eth_accounts, before raw resume.
    signed.takeOfflineOnReconnect();
    await wallet.reload({ waitUntil: "domcontentloaded" });
    await expect.poll(signed.offlineStarts, { timeout: 10_000 }).toBe(1);
    const offlineUntil = Date.now() + 20_000;

    while (Date.now() < offlineUntil) {
      expect(await hasMaterial(wallet, WALLET_SESSION_KEY), "offline resume retains wallet material").toBe(true);
      expect(await hasMaterial(host, HOST_SESSION_KEY), "offline resume retains host material").toBe(true);
      await delay(500);
    }

    await walletContext.setOffline(false);
    await wallet.reload();
    await Promise.all([expectConnected(wallet, 10_000), expectConnected(host, 10_000)]);
    await signThroughHost();

    await host.getByRole("button", { name: "Disconnect", exact: true }).click();
    await expect(wallet.getByRole("button", { name: /^Wire log/ })).toHaveCount(0, { timeout: 10_000 });
    await expect(wallet.getByRole("button", { name: "End", exact: true })).toHaveCount(0);
    await expect(wallet.getByPlaceholder("openlv://...")).toBeEnabled();
    await expect(wallet.getByText("Failed", { exact: true })).toHaveCount(0);
    await expect.poll(() => hasMaterial(host, HOST_SESSION_KEY)).toBe(false);
    await expect.poll(() => hasMaterial(wallet, WALLET_SESSION_KEY)).toBe(false);

    // Re-pair through the UI to exercise the other explicit terminal action.
    await pairThroughUi(host, wallet);
    await wallet.getByRole("button", { name: "End", exact: true }).click();
    await expect.poll(() => hasMaterial(wallet, WALLET_SESSION_KEY)).toBe(false);
    await expect.poll(() => hasMaterial(host, HOST_SESSION_KEY)).toBe(false);
    await expect(host.getByText("Failed", { exact: true })).toHaveCount(0);
  }
  finally {
    states.push(`wallet: completed personal_sign requests ${signed.signatureCount()}`);
    await testInfo.attach("redacted-session-states", {
      body: states.join("\n"),
      contentType: "text/plain",
    });
    await Promise.all([hostContext.close(), walletContext.close()]);
  }
});

test("same-context tabs retain the chosen authorized wallet after the host connects and the wallet reloads", async ({ browser }, testInfo) => {
  test.setTimeout(90_000);
  const context = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"] });
  const signed = await installWallet(context, { secondWallet: true });
  const states: string[] = [];

  await context.addInitScript(({ relay }) => {
    if (!localStorage.getItem("@openlv/connector/settings")) {
      localStorage.setItem("@openlv/connector/settings", JSON.stringify({
        version: 3,
        retainHistory: false,
        autoReconnect: true,
        signaling: { p: "mqtt", s: { mqtt: relay } },
        transport: { p: "webrtc" },
        language: "en",
        theme: "system",
      }));
    }
  }, { relay: RELAY });
  const host = await context.newPage();
  const wallet = await context.newPage();
  const selectedAddress = `${SECOND_WALLET_ADDRESS.slice(0, 5)}...${SECOND_WALLET_ADDRESS.slice(-4)}`;

  captureStates(host, "host", states);
  captureStates(wallet, "wallet", states);

  try {
    await Promise.all([host.goto(DOCS_URL), wallet.goto(DOCS_URL)]);
    await wallet.getByRole("button", { name: SECOND_WALLET_NAME, exact: true }).click();
    await expect(wallet.getByText(selectedAddress, { exact: true }).first()).toBeVisible();

    // Authorize A without switching wagmi away from B. A is announced first and
    // is also window.ethereum, so losing B's persisted selection cannot pass by
    // falling back to the only authorized injected provider.
    const authorizedAccounts = await wallet.evaluate(async () => {
      const provider = Reflect.get(globalThis, "ethereum") as {
        request: (request: { method: string; }) => Promise<string[]>;
      };

      await provider.request({ method: "eth_requestAccounts" });

      return provider.request({ method: "eth_accounts" });
    });

    expect(authorizedAccounts).toEqual([WALLET_ADDRESS]);
    await pairThroughUi(host, wallet);
    await wallet.reload();
    await expect(wallet.getByText(selectedAddress, { exact: true }).first()).toBeVisible({ timeout: 10_000 });
    await Promise.all([expectConnected(host, 10_000), expectConnected(wallet, 10_000)]);
    await expect(host.getByText(selectedAddress, { exact: true }).first()).toBeVisible();
    await host.getByRole("button", { name: "Sign", exact: true }).click();
    await expect.poll(() => signed.signatureCount(SECOND_WALLET_NAME), { timeout: 10_000 }).toBe(1);
    expect(signed.signatureCount(WALLET_NAME)).toBe(0);
    await expect(host.getByText("Valid signature", { exact: true })).toBeVisible({ timeout: 15_000 });
  }
  finally {
    await testInfo.attach("redacted-session-states", {
      body: states.join("\n"),
      contentType: "text/plain",
    });
    await context.close();
  }
});
