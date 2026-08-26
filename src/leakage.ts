import { AgentExchangeError } from "./errors";

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const base64 = (bytes: Uint8Array): string => {
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1] ?? 0;
    const third = bytes[index + 2] ?? 0;
    const combined = (first << 16) | (second << 8) | third;
    output += BASE64_ALPHABET[(combined >> 18) & 63];
    output += BASE64_ALPHABET[(combined >> 12) & 63];
    output +=
      index + 1 < bytes.length ? BASE64_ALPHABET[(combined >> 6) & 63] : "=";
    output += index + 2 < bytes.length ? BASE64_ALPHABET[combined & 63] : "=";
  }
  return output;
};

const printableUtf8 = (bytes: Uint8Array): string | undefined => {
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return decoded.length >= 3 && /^[\x20-\x7e]+$/u.test(decoded)
      ? decoded
      : undefined;
  } catch {
    return undefined;
  }
};

const representations = (bytes: Uint8Array): readonly string[] => {
  const encoded = base64(bytes);
  const utf8 = printableUtf8(bytes);
  return [
    ...(utf8 === undefined ? [] : [utf8]),
    [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
    encoded,
    encoded.replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, ""),
  ].filter(
    (value, index, values) =>
      value.length >= 3 && values.indexOf(value) === index,
  );
};

const stringsIn = (
  value: unknown,
  output: string[],
  seen: Set<object>,
): void => {
  if (typeof value === "string") {
    output.push(value);
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return;
  for (const [key, child] of Object.entries(value)) {
    output.push(key);
    stringsIn(child, output, seen);
  }
};

export const containsSensitiveValue = (
  value: unknown,
  secret: Uint8Array,
): boolean => {
  const strings: string[] = [];
  stringsIn(value, strings, new Set());
  return representations(secret).some((candidate) =>
    strings.some((entry) => entry.includes(candidate)),
  );
};

export const assertNoSensitiveValue = (
  value: unknown,
  secret: Uint8Array,
): void => {
  if (containsSensitiveValue(value, secret)) {
    throw new AgentExchangeError("secret_leak_detected");
  }
};
