import { describe, expect, test } from "bun:test";
import {
  AgentExchangeError,
  containsSensitiveValue,
  validateAgentExchangeInput,
} from "../src";
import { CODE, requestInput } from "./fixture";

describe("request validation", () => {
  test("requires HTTPS origins and tool-confined processing by default", () => {
    const now = Date.now();
    expect(() =>
      validateAgentExchangeInput(
        requestInput({
          expiresAt: now + 60_000,
          resource: {
            ...requestInput().resource,
            origin: "http://accounts.example.com",
          },
        }),
        {
          allowInsecureLocalhost: false,
          allowedProcessingModes: ["tool-confined"],
          maxTtlMs: 300_000,
          now,
        },
      ),
    ).toThrow(AgentExchangeError);

    expect(() =>
      validateAgentExchangeInput(
        requestInput({
          expiresAt: now + 60_000,
          processingMode: "model-visible",
        }),
        {
          allowInsecureLocalhost: false,
          allowedProcessingModes: ["tool-confined"],
          maxTtlMs: 300_000,
          now,
        },
      ),
    ).toThrow(AgentExchangeError);
  });

  test("rejects expired and excessively long requests", () => {
    const now = Date.now();
    for (const expiresAt of [now, now + 300_001]) {
      expect(() =>
        validateAgentExchangeInput(requestInput({ expiresAt }), {
          allowInsecureLocalhost: false,
          allowedProcessingModes: ["tool-confined"],
          maxTtlMs: 300_000,
          now,
        }),
      ).toThrow(AgentExchangeError);
    }
  });
});

describe("leak canary", () => {
  test("finds UTF-8, hexadecimal, base64, and base64url representations", () => {
    const secret = new TextEncoder().encode(CODE);
    for (const value of [
      `value=${CODE}`,
      "343832313933",
      "NDgyMTkz",
      { nested: ["NDgyMTkz"] },
    ]) {
      expect(containsSensitiveValue(value, secret)).toBe(true);
    }
    expect(containsSensitiveValue({ status: "submitted" }, secret)).toBe(false);
  });
});
