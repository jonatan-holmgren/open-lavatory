import { type Observable, observable } from "@openlv/core";
import type * as ProviderModule from "@openlv/provider";
import type { OpenLVProvider } from "@openlv/provider";
import { createProvider, ProviderStatus } from "@openlv/provider";
import type { ConnectorEventMap } from "@wagmi/core";
import { createEmitter } from "@wagmi/core/internal";
import { EventEmitter } from "eventemitter3";
import { mainnet } from "viem/chains";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { openlv } from "./index.js";

vi.mock("@openlv/provider", async (importOriginal) => {
  const actual = await importOriginal<typeof ProviderModule>();

  return { ...actual, createProvider: vi.fn() };
});

vi.mock("./modal.js", () => ({
  // eslint-disable-next-line unicorn/consistent-function-scoping
  getTriggerModal: async () => () => undefined,
}));

const createConnectedProvider = (
  status: Observable<ProviderStatus> = observable(ProviderStatus.CONNECTED)[0],
  isRestoring = false,
): OpenLVProvider => {
  const [error] = observable<string | undefined>(undefined);
  const [session] = observable<object | undefined>({});

  return Object.assign(new EventEmitter(), {
    status,
    error,
    session,
    storage: {
      getSettings: () => ({ autoReconnect: isRestoring }),
      getSession: () => (isRestoring ? {} : undefined),
    },
    getAccounts: vi.fn(async () => ["0x0000000000000000000000000000000000000001"]),
    request: async () => "0x1",
    closeSession: vi.fn(async () => undefined),
  }) as unknown as OpenLVProvider;
};

describe("openlv connector", () => {
  beforeEach(() => {
    vi.mocked(createProvider).mockReset();
  });

  test("forwards a provider disconnect after connecting", async () => {
    const provider = createConnectedProvider();

    vi.mocked(createProvider).mockReturnValue(provider);
    const emitter = createEmitter<ConnectorEventMap>("openlv-test");
    const onDisconnect = vi.fn();

    emitter.on("disconnect", onDisconnect);
    const connector = openlv()({
      chains: [mainnet],
      emitter,
      providers: [],
    });

    await connector.connect({});
    provider.emit(
      "disconnect",
      Object.assign(new Error("Session closed by peer"), {
        code: 4900,
        details: "Session closed by peer",
      }),
    );

    expect(onDisconnect).toHaveBeenCalledOnce();
  });

  test("waits for provider restoration before checking authorization", async () => {
    const [status, setStatus] = observable<ProviderStatus>(ProviderStatus.STANDBY);
    const provider = createConnectedProvider(status, true);

    vi.mocked(createProvider).mockReturnValue(provider);
    const connector = openlv()({
      chains: [mainnet],
      emitter: createEmitter<ConnectorEventMap>("openlv-restore-test"),
      providers: [],
    });

    const authorized = connector.isAuthorized();

    await Promise.resolve();
    expect(provider.getAccounts).not.toHaveBeenCalled();
    setStatus(ProviderStatus.CONNECTED);
    await expect(authorized).resolves.toBe(true);
    expect(provider.getAccounts).toHaveBeenCalledOnce();
  });
});
