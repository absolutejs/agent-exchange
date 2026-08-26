import type { SecretProcessingMode } from "@absolutejs/e2ee";
import { AgentExchangeError } from "./errors";
import type {
  AgentExchangeRequest,
  AgentExchangeRequestInput,
  ExchangeRiskClass,
  SensitiveValue,
} from "./types";

export const DEFAULT_EXCHANGE_MAX_TTL_MS = 5 * 60_000;
export const DEFAULT_MAX_SECRET_BYTES = 256;

export const DEFAULT_BLOCKED_RISKS: ReadonlySet<ExchangeRiskClass> = new Set([
  "account-recovery",
  "administrative",
  "data-export",
  "money-movement",
  "security-settings",
]);

const nonEmpty = (value: string): boolean => value.trim().length > 0;

const validOrigin = (
  value: string,
  allowInsecureLocalhost: boolean,
): boolean => {
  try {
    const parsed = new URL(value);
    if (parsed.origin !== value) return false;
    if (parsed.protocol === "https:") return true;
    return (
      allowInsecureLocalhost &&
      parsed.protocol === "http:" &&
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1")
    );
  } catch {
    return false;
  }
};

const validIdentity = (identity: {
  readonly agentId: string;
  readonly authority: string;
  readonly subject: string;
}): boolean =>
  nonEmpty(identity.agentId) &&
  nonEmpty(identity.authority) &&
  nonEmpty(identity.subject);

export const validateAgentExchangeInput = (
  input: AgentExchangeRequestInput,
  options: {
    readonly allowInsecureLocalhost: boolean;
    readonly allowedProcessingModes: readonly SecretProcessingMode[];
    readonly maxTtlMs: number;
    readonly now: number;
  },
): void => {
  const processingMode = input.processingMode ?? "tool-confined";
  if (
    !validIdentity(input.requester) ||
    !validIdentity(input.recipient) ||
    !nonEmpty(input.purpose) ||
    !nonEmpty(input.secretKind) ||
    !nonEmpty(input.resource.accountRef) ||
    !nonEmpty(input.resource.operation) ||
    !nonEmpty(input.resource.provider) ||
    !validOrigin(input.resource.origin, options.allowInsecureLocalhost) ||
    !Number.isSafeInteger(input.expiresAt) ||
    input.expiresAt <= options.now ||
    input.expiresAt > options.now + options.maxTtlMs ||
    !options.allowedProcessingModes.includes(processingMode) ||
    (input.idempotencyKey !== undefined && !nonEmpty(input.idempotencyKey))
  ) {
    throw new AgentExchangeError("invalid_request");
  }
};

export const validateAgentExchangeRequest = (
  request: AgentExchangeRequest,
  options: {
    readonly allowInsecureLocalhost: boolean;
    readonly maxTtlMs: number;
    readonly now: number;
  },
): void => {
  validateAgentExchangeInput(request, {
    ...options,
    allowedProcessingModes: ["tool-confined"],
  });
  if (
    !nonEmpty(request.actionId) ||
    !nonEmpty(request.exchangeId) ||
    !nonEmpty(request.nonce) ||
    request.maximumUses !== 1 ||
    request.processingMode !== "tool-confined" ||
    !Number.isSafeInteger(request.createdAt) ||
    request.createdAt > options.now
  ) {
    throw new AgentExchangeError("invalid_request");
  }
};

export const validateSensitiveValue = (
  value: SensitiveValue,
  request: AgentExchangeRequest,
  maxSecretBytes: number,
): void => {
  if (
    !(value.bytes instanceof Uint8Array) ||
    value.bytes.length === 0 ||
    value.bytes.length > maxSecretBytes
  ) {
    throw new AgentExchangeError("source_failed");
  }

  if (request.secretKind === "email-one-time-code") {
    let decoded: string;
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(value.bytes);
    } catch {
      throw new AgentExchangeError("source_failed");
    }
    if (!/^\d{6}$/u.test(decoded)) {
      throw new AgentExchangeError("source_failed");
    }
  }
};

export const validatePositiveLimit = (value: number): void => {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new AgentExchangeError("invalid_request");
  }
};
