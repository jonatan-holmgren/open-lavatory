import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    // @ts-expect-error: Dumb
    document.querySelector("#webpack-dev-server-client-overlay")?.remove();
  });
});

test("OpenLV wallet appears in the wallet list", async ({ page }) => {
  await expect(page.getByText("Other Wallets")).toBeVisible();
});

test("clicking OpenLV wallet opens the OpenLV modal", async ({ page }) => {
  await page.getByText("Other Wallets").click();

  await expect(page.locator("openlv-modal")).toBeAttached();
  await expect(page.locator("openlv-modal >> text=Generate QR")).toBeVisible();
});
