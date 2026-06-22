import { createHmac } from "node:crypto";
import type { CallTemplateFunctionArgs, Context, PluginDefinition } from "@yaakapp/api";

const STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY";

const periods = [15, 30, 60] as const;
const digitsList = [6, 7, 8] as const;
const algorithms = ["SHA1", "SHA256", "SHA512"] as const;
const inputFormats = ["Base32", "Hex", "Text"] as const;

export function base32Decode(encoded: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = encoded.replace(/[^A-Za-z2-7]/g, "").toUpperCase();
  const bits: string[] = [];
  for (const ch of cleaned) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) continue;
    bits.push(idx.toString(2).padStart(5, "0"));
  }
  const bytes: number[] = [];
  const bitString = bits.join("");
  for (let i = 0; i + 7 < bitString.length; i += 8) {
    bytes.push(parseInt(bitString.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

export function hexDecode(hex: string): Buffer {
  const cleaned = hex.replace(/[-: ]/g, "");
  if (cleaned.length % 2 !== 0) {
    throw new Error("Hex string must have an even number of characters");
  }
  const bytes: number[] = [];
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes.push(parseInt(cleaned.substring(i, i + 2), 16));
  }
  return Buffer.from(bytes);
}

export function secretToBytes(secret: string, format: string): Buffer {
  switch (format) {
    case "Base32":
      return base32Decode(secret);
    case "Hex":
      return hexDecode(secret);
    case "Text":
      return Buffer.from(secret, "utf-8");
    default:
      throw new Error(`Invalid input format: ${format}`);
  }
}

export function counterToBuffer(timeCounter: number): Buffer {
  const buf = Buffer.alloc(8);
  let tc = BigInt(Math.floor(timeCounter));
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(tc & 0xffn);
    tc >>= 8n;
  }
  return buf;
}

export function computeHmac(algorithm: string, key: Buffer, data: Buffer): Buffer {
  const hmac = createHmac(algorithm.toLowerCase(), key);
  hmac.update(data);
  return hmac.digest();
}

export function truncatedValue(hash: Buffer): number {
  const offset = hash[hash.length - 1] & 0xf;
  return (
    ((hash[offset] & 0x7f) << 24) |
    (hash[offset + 1] << 16) |
    (hash[offset + 2] << 8) |
    hash[offset + 3]
  );
}

export function generateTOTP(secret: Buffer, timeCounter: number, digits: number, algorithm: string): string {
  const counterBuf = counterToBuffer(timeCounter);
  const hash = computeHmac(algorithm, secret, counterBuf);
  const code = truncatedValue(hash);
  const otp = code % Math.pow(10, digits);
  return otp.toString().padStart(digits, "0");
}

export function generateSteam(secret: Buffer, timeCounter: number, algorithm: string): string {
  const counterBuf = counterToBuffer(timeCounter);
  const hash = computeHmac(algorithm, secret, counterBuf);

  let code = "";
  let offset = hash[hash.length - 1] & 0xf;
  for (let i = 0; i < 5; i++) {
    const idx = ((hash[offset] & 0x7f) << 8 | hash[offset + 1]) % STEAM_CHARS.length;
    code += STEAM_CHARS[idx];
    offset = (offset + 2) % hash.length;
  }
  return code;
}

export function getUnixTime(customMs: string | undefined): number {
  if (customMs) {
    return Math.floor(parseInt(String(customMs), 10) / 1000);
  }
  return Math.floor(Date.now() / 1000);
}

export const plugin: PluginDefinition = {
  templateFunctions: [
    {
      name: "otp.generate",
      description: "Generate a TOTP or Steam code",
      args: [
        {
          type: "text",
          name: "secret",
          label: "Secret Key",
          password: true,
          placeholder: "JBSWY3DPEHPK3PXP",
        },
        {
          type: "select",
          name: "inputFormat",
          label: "Input Format",
          defaultValue: "Base32",
          options: inputFormats.map((f) => ({ label: f, value: f })),
        },
        {
          type: "select",
          name: "type",
          label: "Code Type",
          defaultValue: "totp",
          options: [
            { label: "TOTP", value: "totp" },
            { label: "Steam", value: "steam" },
          ],
        },
        {
          type: "select",
          name: "algorithm",
          label: "Algorithm",
          defaultValue: "SHA1",
          options: algorithms.map((a) => ({ label: a, value: a })),
        },
        {
          type: "h_stack",
          dynamic: (_ctx, args) => ({ hidden: String(args.values.type ?? "totp") !== "totp" }),
          inputs: [
            {
              type: "select",
              name: "digits",
              label: "Digits",
              defaultValue: "6",
              options: digitsList.map((d) => ({ label: String(d), value: String(d) })),
            },
            {
              type: "select",
              name: "period",
              label: "Period (s)",
              defaultValue: "30",
              options: periods.map((p) => ({ label: `${p}s`, value: String(p) })),
            },
          ],
        },
        {
          type: "accordion",
          label: "Advanced",
          inputs: [
            {
              type: "text",
              name: "timestamp",
              label: "Custom Timestamp (Unix ms)",
              placeholder: "Leave empty for current time",
              optional: true,
            },
            {
              type: "select",
              name: "window",
              label: "Verification Window",
              defaultValue: "1",
              options: [
                { label: "1 (current)", value: "1" },
                { label: "2 (current ± 1)", value: "2" },
                { label: "3 (current ± 2)", value: "3" },
              ],
            },
          ],
        },
      ],
      async onRender(
        _ctx: Context,
        args: CallTemplateFunctionArgs,
      ): Promise<string | null> {
        const secretRaw = String(args.values.secret ?? "");
        if (!secretRaw) {
          throw new Error("Secret key is required");
        }

        const inputFormat = String(args.values.inputFormat ?? "Base32");
        const codeType = String(args.values.type ?? "totp");
        const algorithm = String(args.values.algorithm ?? "SHA1");
        const digits = parseInt(String(args.values.digits || "6"), 10);
        const period = parseInt(String(args.values.period || "30"), 10);
        const windowSize = parseInt(String(args.values.window || "1"), 10);

        const unixTime = getUnixTime(String(args.values.timestamp ?? ""));
        const counter = Math.floor(unixTime / period);

        const secret = secretToBytes(secretRaw, inputFormat);

        if (codeType === "steam") {
          return generateSteam(secret, counter, algorithm);
        }

        if (windowSize <= 1) {
          return generateTOTP(secret, counter, digits, algorithm);
        }

        const results: string[] = [];
        for (let i = -(windowSize - 1); i < windowSize; i++) {
          results.push(generateTOTP(secret, counter + i, digits, algorithm));
        }
        return results.join(", ");
      },
    },
    {
      name: "otp.verify",
      description: "Verify a TOTP code against a secret",
      args: [
        {
          type: "text",
          name: "secret",
          label: "Secret Key",
          password: true,
          placeholder: "JBSWY3DPEHPK3PXP",
        },
        {
          type: "text",
          name: "code",
          label: "Code to Verify",
          placeholder: "123456",
        },
        {
          type: "select",
          name: "inputFormat",
          label: "Input Format",
          defaultValue: "Base32",
          options: inputFormats.map((f) => ({ label: f, value: f })),
        },
        {
          type: "h_stack",
          inputs: [
            {
              type: "select",
              name: "digits",
              label: "Digits",
              defaultValue: "6",
              options: digitsList.map((d) => ({ label: String(d), value: String(d) })),
            },
            {
              type: "select",
              name: "period",
              label: "Period (s)",
              defaultValue: "30",
              options: periods.map((p) => ({ label: `${p}s`, value: String(p) })),
            },
          ],
        },
        {
          type: "select",
          name: "algorithm",
          label: "Algorithm",
          defaultValue: "SHA1",
          options: algorithms.map((a) => ({ label: a, value: a })),
        },
        {
          type: "select",
          name: "window",
          label: "Verification Window",
          defaultValue: "1",
          options: [
            { label: "1 (current only)", value: "1" },
            { label: "2 (current ± 1)", value: "2" },
            { label: "3 (current ± 2)", value: "3" },
          ],
        },
      ],
      async onRender(
        _ctx: Context,
        args: CallTemplateFunctionArgs,
      ): Promise<string | null> {
        const secretRaw = String(args.values.secret ?? "");
        const code = String(args.values.code ?? "");

        if (!secretRaw || !code) {
          return "false";
        }

        const inputFormat = String(args.values.inputFormat ?? "Base32");
        const algorithm = String(args.values.algorithm ?? "SHA1");
        const digits = parseInt(String(args.values.digits || "6"), 10);
        const period = parseInt(String(args.values.period || "30"), 10);
        const windowSize = parseInt(String(args.values.window || "1"), 10);

        if (code.length !== digits) {
          return "false";
        }

        const unixTime = Math.floor(Date.now() / 1000);
        const counter = Math.floor(unixTime / period);
        const secret = secretToBytes(secretRaw, inputFormat);

        for (let i = -(windowSize - 1); i < windowSize; i++) {
          const otp = generateTOTP(secret, counter + i, digits, algorithm);
          if (otp === code) {
            return "true";
          }
        }

        return "false";
      },
    },
  ],
};
