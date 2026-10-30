import { inspect } from "node:util";

import { describe, expect, test } from "vitest";

import { decodeConnectionURL, encodeConnectionURL } from "./index.js";

const testCases = [
  {
    url: "openlv://k7n8m9x2w5q1p3r6@1?h=a1b2c3d4e5f60708&k=0123456789abcdef0123456789abcdef&p=mqtt&s=wss%3A%2F%2Ftest.mosquitto.org%3A8081%2Fmqtt",
    expected: {
      version: 1,
      sessionId: "k7n8m9x2w5q1p3r6",
      h: "a1b2c3d4e5f60708",
      k: "0123456789abcdef0123456789abcdef",
      p: "mqtt",
      s: "wss://test.mosquitto.org:8081/mqtt",
    } as const,
  },
];

describe("URL Utilities", () => {
  test("should decode connection URL", () => {
    for (const testCase of testCases) {
      const result = decodeConnectionURL(testCase.url);

      expect(result).toEqual(testCase.expected);
    }
  });

  test("should encode connection URL", () => {
    for (const testCase of testCases) {
      const result = encodeConnectionURL(testCase.expected);

      expect(result).toEqual(testCase.url);
    }
  });

  test("rejects public key hashes that are not 16 lowercase hex characters", () => {
    for (const invalid of ["a1b2c3d4e5f6070", "a1b2c3d4e5f607080", "A1b2c3d4e5f60708"]) {
      expect(() => decodeConnectionURL(testCases[0]!.url.replace(testCases[0]!.expected.h, invalid)))
        .toThrow("16 lowercase hex characters");
    }
  });

  test("keeps bootstrap secrets out of inspected URL parsing errors", () => {
    const secret = "0123456789abcdef0123456789abcdef";
    let failure: unknown;

    try {
      decodeConnectionURL(`openlv://[?k=${secret}`);
    }
    catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(Error);
    expect(inspect(failure, { depth: null })).not.toContain(secret);
  });

  test("does not expose a secret when the URL has the wrong scheme", () => {
    const secret = "0123456789abcdef0123456789abcdef";
    let failure: unknown;

    try {
      decodeConnectionURL(`https://example.test/?k=${secret}`);
    }
    catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(Error);
    expect(inspect(failure, { depth: null })).not.toContain(secret);
  });
});
