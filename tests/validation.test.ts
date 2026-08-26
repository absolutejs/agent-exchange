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

  test("cannot label bearer or general execution as WebAuthn phishing-resistant", () => {
    const now = Date.now();
    for (const assurance of [
      {
        approval: "webauthn-verifier-bound",
        credential: "bearer",
        execution: "purpose-bound",
      },
      {
        approval: "webauthn-verifier-bound",
        credential: "sender-constrained",
        execution: "general",
      },
    ]) {
      expect(() =>
        validateAgentExchangeInput(
          requestInput({
            assurance: assurance as never,
            expiresAt: now + 60_000,
          }),
          {
            allowInsecureLocalhost: false,
            allowedProcessingModes: ["tool-confined"],
            maxTtlMs: 300_000,
            now,
          },
        ),
      ).toThrow(AgentExchangeError);
    }
  });

  test("represents a passkey-approved token-confined broker explicitly", () => {
    const now = Date.now();
    expect(() =>
      validateAgentExchangeInput(
        requestInput({
          assurance: {
            approval: "webauthn-verifier-bound",
            credential: "token-confined-broker",
            execution: "purpose-bound",
          },
          expiresAt: now + 60_000,
        }),
        {
          allowInsecureLocalhost: false,
          allowedProcessingModes: ["tool-confined"],
          maxTtlMs: 300_000,
          now,
        },
      ),
    ).not.toThrow();
  });

  test("requires HTTPS requester and recipient authorities", () => {
    const now = Date.now();
    expect(() =>
      validateAgentExchangeInput(
        requestInput({
          expiresAt: now + 60_000,
          requester: {
            ...requestInput().requester,
            authority: "https://auth.requester.example/path",
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
