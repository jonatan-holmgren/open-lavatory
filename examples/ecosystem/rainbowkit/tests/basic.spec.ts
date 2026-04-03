import { expect, test } from "@playwright/test";

test("OpenLV wallet appears in the wallet list", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: /connect wallet/i }).click();

  await expect(page.getByText("Other Wallets")).toBeVisible();
});

test("clicking OpenLV wallet opens the OpenLV modal", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: /connect wallet/i }).click();

  await page.getByText("Other Wallets").click();

  const modal = page.locator("openlv-modal");

  await expect(modal).toBeVisible();
  await expect(modal.getByText("Connect Wallet")).toBeVisible();
  await expect(modal.getByText("Generate QR")).toBeVisible();
});
