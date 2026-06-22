import { describe, expect, test } from "vitest";
import {
  base32Decode,
  hexDecode,
  secretToBytes,
  counterToBuffer,
  computeHmac,
  truncatedValue,
  generateTOTP,
  generateSteam,
  getUnixTime,
  plugin,
} from "./index";

// RFC 4226 test vector: secret = "12345678901234567890" (ASCII)
const RFC_SECRET_HEX = "3132333435363738393031323334353637383930";
const RFC_SECRET_BUF = Buffer.from(RFC_SECRET_HEX, "hex");
const RFC_SECRET_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

// RFC 4226 expected TOTP values for counters 0..9 with SHA1
const RFC_EXPECTED = [
  "755224",
  "287082",
  "359152",
  "969429",
  "338314",
  "254676",
  "287922",
  "162583",
  "399871",
  "520489",
];

describe("base32Decode", () => {
  test("decodes RFC 4226 Base32 secret correctly", () => {
    const buf = base32Decode(RFC_SECRET_BASE32);
    expect(buf.toString("hex")).toBe(RFC_SECRET_HEX);
  });

  test("handles lowercase input", () => {
    const buf = base32Decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq");
    expect(buf.toString("hex")).toBe(RFC_SECRET_HEX);
  });

  test("ignores non-alphanumeric characters", () => {
    const buf = base32Decode("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ");
    expect(buf.toString("hex")).toBe(RFC_SECRET_HEX);
  });

  test("returns empty buffer for empty string", () => {
    const buf = base32Decode("");
    expect(buf.length).toBe(0);
  });
});

describe("hexDecode", () => {
  test("decodes hex string correctly", () => {
    const buf = hexDecode(RFC_SECRET_HEX);
    expect(buf.toString("hex")).toBe(RFC_SECRET_HEX);
  });

  test("decodes hex with colon separators", () => {
    const withColons = "31:32:33:34:35:36:37:38:39:30:31:32:33:34:35:36:37:38:39:30";
    const buf = hexDecode(withColons);
    expect(buf.toString("hex")).toBe(RFC_SECRET_HEX);
  });

  test("decodes hex with dash separators", () => {
    const withDashes = "31-32-33-34-35-36-37-38-39-30-31-32-33-34-35-36-37-38-39-30";
    const buf = hexDecode(withDashes);
    expect(buf.toString("hex")).toBe(RFC_SECRET_HEX);
  });

  test("decodes hex with space separators", () => {
    const withSpaces = "31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30";
    const buf = hexDecode(withSpaces);
    expect(buf.toString("hex")).toBe(RFC_SECRET_HEX);
  });

  test("throws on odd hex character count", () => {
    expect(() => hexDecode("313")).toThrow("even number of characters");
  });

  test("returns empty buffer for empty string", () => {
    const buf = hexDecode("");
    expect(buf.length).toBe(0);
  });
});

describe("secretToBytes", () => {
  const raw = "Hello";

  test("decodes Base32", () => {
    const buf = secretToBytes("JBSWY3DP", "Base32");
    expect(buf.toString()).toBe(raw);
  });

  test("decodes Hex", () => {
    const buf = secretToBytes("48656c6c6f", "Hex");
    expect(buf.toString()).toBe(raw);
  });

  test("decodes Text", () => {
    const buf = secretToBytes(raw, "Text");
    expect(buf.toString()).toBe(raw);
  });

  test("throws on invalid format", () => {
    expect(() => secretToBytes("test", "Invalid")).toThrow("Invalid input format");
  });
});

describe("counterToBuffer", () => {
  test("counter 0 produces 8 zero bytes", () => {
    expect(counterToBuffer(0).toString("hex")).toBe("0000000000000000");
  });

  test("counter 1 produces big-endian 1", () => {
    expect(counterToBuffer(1).toString("hex")).toBe("0000000000000001");
  });

  test("counter 42 produces correct big-endian value", () => {
    expect(counterToBuffer(42).toString("hex")).toBe("000000000000002a");
  });

  test("counter 0xdeadbeef produces correct big-endian value", () => {
    expect(counterToBuffer(0xdeadbeef).toString("hex")).toBe("00000000deadbeef");
  });

  test("counter larger than 32-bit produces correct big-endian value", () => {
    expect(counterToBuffer(0x1a2b3c4d5).toString("hex")).toBe("00000001a2b3c4d5");
  });
});

describe("computeHmac", () => {
  const key = RFC_SECRET_BUF;

  test("SHA1 produces a 20-byte hash", () => {
    const hash = computeHmac("SHA1", key, counterToBuffer(0));
    expect(hash.length).toBe(20);
  });

  test("SHA256 produces a 32-byte hash", () => {
    const hash = computeHmac("SHA256", key, counterToBuffer(0));
    expect(hash.length).toBe(32);
  });

  test("SHA512 produces a 64-byte hash", () => {
    const hash = computeHmac("SHA512", key, counterToBuffer(0));
    expect(hash.length).toBe(64);
  });

  test("produces deterministic output", () => {
    const data = counterToBuffer(0);
    const h1 = computeHmac("SHA1", key, data);
    const h2 = computeHmac("SHA1", key, data);
    expect(h1.equals(h2)).toBe(true);
  });
});

describe("truncatedValue", () => {
  test("returns a 31-bit number", () => {
    const hash = computeHmac("SHA1", RFC_SECRET_BUF, counterToBuffer(0));
    const val = truncatedValue(hash);
    expect(val).toBeGreaterThanOrEqual(0);
    expect(val).toBeLessThan(0x80000000);
  });
});

describe("generateTOTP (RFC 4226 test vectors)", () => {
  test.each([
    [0, RFC_EXPECTED[0]],
    [1, RFC_EXPECTED[1]],
    [2, RFC_EXPECTED[2]],
    [3, RFC_EXPECTED[3]],
    [4, RFC_EXPECTED[4]],
    [5, RFC_EXPECTED[5]],
    [6, RFC_EXPECTED[6]],
    [7, RFC_EXPECTED[7]],
    [8, RFC_EXPECTED[8]],
    [9, RFC_EXPECTED[9]],
  ])("counter %i produces %s", (counter, expected) => {
    const otp = generateTOTP(RFC_SECRET_BUF, counter, 6, "SHA1");
    expect(otp).toBe(expected);
  });

  test("produces 7-digit code", () => {
    const otp = generateTOTP(RFC_SECRET_BUF, 0, 7, "SHA1");
    expect(otp.length).toBe(7);
  });

  test("produces 8-digit code", () => {
    const otp = generateTOTP(RFC_SECRET_BUF, 0, 8, "SHA1");
    expect(otp.length).toBe(8);
  });

  test("produces different output with SHA256", () => {
    const sha1 = generateTOTP(RFC_SECRET_BUF, 1, 6, "SHA1");
    const sha256 = generateTOTP(RFC_SECRET_BUF, 1, 6, "SHA256");
    expect(sha256).not.toBe(sha1);
    expect(sha256.length).toBe(6);
  });

  test("produces different output with SHA512", () => {
    const sha1 = generateTOTP(RFC_SECRET_BUF, 1, 6, "SHA1");
    const sha512 = generateTOTP(RFC_SECRET_BUF, 1, 6, "SHA512");
    expect(sha512).not.toBe(sha1);
    expect(sha512.length).toBe(6);
  });
});

describe("generateSteam", () => {
  test("produces a 5-character code", () => {
    const code = generateSteam(RFC_SECRET_BUF, 0, "SHA1");
    expect(code.length).toBe(5);
  });

  test("only uses valid Steam characters", () => {
    const valid = "23456789BCDFGHJKMNPQRTVWXY";
    for (let i = 0; i < 20; i++) {
      const code = generateSteam(RFC_SECRET_BUF, i, "SHA1");
      for (const ch of code) {
        expect(valid).toContain(ch);
      }
    }
  });

  test("produces deterministic output", () => {
    const a = generateSteam(RFC_SECRET_BUF, 42, "SHA1");
    const b = generateSteam(RFC_SECRET_BUF, 42, "SHA1");
    expect(a).toBe(b);
  });
});

describe("getUnixTime", () => {
  test("returns current time when no custom timestamp", () => {
    const now = Math.floor(Date.now() / 1000);
    const result = getUnixTime(undefined);
    expect(Math.abs(result - now)).toBeLessThan(2);
  });

  test("parses custom Unix millisecond timestamp", () => {
    const ms = "1700000000000";
    const result = getUnixTime(ms);
    expect(result).toBe(1700000000);
  });
});

describe("plugin structure", () => {
  test("exports a plugin object", () => {
    expect(plugin).toBeTypeOf("object");
  });

  test("has templateFunctions array with 2 items", () => {
    expect(Array.isArray(plugin.templateFunctions)).toBe(true);
    expect(plugin.templateFunctions).toHaveLength(2);
  });

  test("first function is otp.generate", () => {
    const fn = plugin.templateFunctions[0];
    expect(fn?.name).toBe("otp.generate");
  });

  test("second function is otp.verify", () => {
    const fn = plugin.templateFunctions[1];
    expect(fn?.name).toBe("otp.verify");
  });
});
