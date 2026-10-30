import { describe, expect, it } from "vitest";

import { createEncryptionKey } from "./asymmetric.js";
import { hashPublicKey } from "./hash.js";

describe("public-key hash", () => {
  it("hashes the raw 32-byte X25519 key, not its base64 serialization", async () => {
    const rawPublicKey = Uint8Array.from({ length: 32 }, (_, index) => index);
    const publicKey = await createEncryptionKey(rawPublicKey);

    await expect(hashPublicKey(publicKey)).resolves.toBe("630dcd2966c43366");
  });
});
