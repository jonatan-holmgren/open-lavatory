import { observable } from "@openlv/core";
import { afterEach, describe, expect, it, vi } from "vitest";

const { createProviderMock } = vi.hoisted(() => ({ createProviderMock: vi.fn() }));

vi.mock("@openlv/provider", () => ({
  createProvider: createProviderMock,
  hasRestorableSession: (storage: {
    getSettings: () => { autoReconnect: boolean; };
    getSession: () => unknown;
  }) => storage.getSettings().autoReconnect && storage.getSession() !== undefined,
  ProviderStatus: {
    STANDBY: "standby",
    CREATING: "creating",
    CONNECTING: "connecting",
    CONNECTED: "connected",
    ERROR: "error",
  },
}));

import { ProviderStatus } from "@openlv/provider";

import { openlv } from "./index.js";

afterEach(() => createProviderMock.mockReset());

describe("OpenLV connector authorization", () => {
  it("waits for saved-session restoration before reporting authorized accounts", async () => {
    const [status, setStatus] = observable<ProviderStatus>(ProviderStatus.CONNECTING);
    const provider = {
      status,
      storage: {
        getSettings: () => ({ autoReconnect: true }),
        getSession: () => ({ resumptionSecret: "saved-secret" }),
      },
      session: observable({})[0],
      getAccounts: async () => ["0x0000000000000000000000000000000000000001"],
    };

    createProviderMock.mockReturnValue(provider);

    const connector = openlv()({ chains: [] } as never);
    const authorization = connector.isAuthorized();
    let isSettled = false;

    void authorization.then(() => {
      isSettled = true;
    });
    await Promise.resolve();
    expect(isSettled).toBe(false);

    setStatus(ProviderStatus.CONNECTED);

    await expect(authorization).resolves.toBe(true);
  });
});
