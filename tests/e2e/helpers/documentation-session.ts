import { expect, type Page } from "@playwright/test";

export const expectConnected = async (page: Page, timeout = 30_000) => {
  await expect(page.getByText("Connected", { exact: true })).toBeVisible({ timeout });
  await expect(page.getByText("Failed", { exact: true })).toHaveCount(0);
};

export const pairThroughUi = async (host: Page, wallet: Page) => {
  await host.getByRole("button", { name: "Open Lavatory", exact: true }).first()
    .click();
  const modal = host.getByRole("dialog");

  await expect(modal).toBeVisible();
  await modal.getByRole("button", { name: "Generate QR", exact: true }).click();
  await modal.getByRole("button", { name: "Copy Connection URL", exact: true }).click();
  const uri = await host.evaluate(() => navigator.clipboard.readText());

  if (!uri.startsWith("openlv://")) throw new Error("Modal did not copy a connection URL");

  await wallet.getByPlaceholder("openlv://...").evaluate((element, value) => {
    if (!(element instanceof HTMLInputElement)) throw new Error("Expected connection URL input");

    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;

    if (!setter) throw new Error("Input value setter unavailable");

    setter.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true }));
  }, uri);
  await wallet.getByRole("button", { name: "Connect", exact: true }).click();
  await Promise.all([expectConnected(host), expectConnected(wallet)]);

  if (await modal.isVisible()) {
    await modal.getByRole("button", { name: "Close", exact: true }).click();
  }
};
