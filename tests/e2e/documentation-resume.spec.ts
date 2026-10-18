import { expect, test } from "@playwright/test";

import { expectConnected, pairThroughUi } from "./helpers/documentation-session.js";
import {
  HOST_SESSION_KEY,
  installWallet,
  WALLET_NAME,
  WALLET_SESSION_KEY,
} from "./helpers/documentation-wallet.js";

const DOCS_URL = process.env["OPENLV_E2E_DOCS_URL"] ?? "http://127.0.0.1:5198/try";
const RELAY = process.env["OPENLV_E2E_RELAY"] ?? "ws://test.mosquitto.org:8080/mqtt";

test.use({ trace: "off", screenshot: "off", video: "off" });

test("client and host refresh restore the pairing", async ({ browser }) => {
  test.setTimeout(120_000);
  const context = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"] });
  const signed = await installWallet(context);

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

  try {
    await Promise.all([host.goto(DOCS_URL), wallet.goto(DOCS_URL)]);
    await wallet.getByRole("button", { name: WALLET_NAME, exact: true }).first()
      .click();
    await pairThroughUi(host, wallet);

    await expect.poll(() => host.evaluate(key => sessionStorage.getItem(key) !== null, HOST_SESSION_KEY)).toBe(true);
    await expect.poll(() => wallet.evaluate(key => sessionStorage.getItem(key) !== null, WALLET_SESSION_KEY)).toBe(true);

    const signThroughHost = async () => {
      const previous = signed.signatureCount();

      await host.getByRole("button", { name: "Sign", exact: true }).click();
      await expect.poll(signed.signatureCount, { timeout: 10_000 }).toBe(previous + 1);
      await expect(host.getByText("Valid signature", { exact: true })).toBeVisible({ timeout: 15_000 });
    };

    await signThroughHost();
    await wallet.reload();
    await Promise.all([expectConnected(wallet, 20_000), expectConnected(host, 20_000)]);
    await signThroughHost();

    await host.reload();
    await Promise.all([expectConnected(host, 20_000), expectConnected(wallet, 20_000)]);
    await signThroughHost();

    await Promise.all([host.reload(), wallet.reload()]);
    await Promise.all([expectConnected(host, 20_000), expectConnected(wallet, 20_000)]);
    await signThroughHost();
    await expect(host.getByRole("button", { name: /^Wire log/ })).toBeVisible();
  }
  finally {
    await context.close();
  }
});
