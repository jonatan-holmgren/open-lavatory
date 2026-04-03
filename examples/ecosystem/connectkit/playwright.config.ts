import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  use: {
    baseURL: "http://localhost:3000",
  },
  webServer: {
    command: "BROWSER=none yarn dev",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    cwd: ".repo/examples/cra",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
