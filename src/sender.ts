import { digest, type ActionRequestInput } from "@absolutejs/agency";
import { AgentExchangeError } from "./errors";
import { assertNoSensitiveValue } from "./leakage";
import { agentExchangeContext } from "./context";
import type {
  AgentExchangeReceipt,
  AgentExchangeRequest,
  AgentExchangeRequestInput,
  AgentExchangeSender,
  AgentExchangeSenderOptions,
} from "./types";
import {
  DEFAULT_BLOCKED_RISKS,
  DEFAULT_EXCHANGE_MAX_TTL_MS,
  DEFAULT_MAX_SECRET_BYTES,
  validateAgentExchangeInput,
  validatePositiveLimit,
  validateSensitiveValue,
} from "./validation";

const safeRequestInput = (input: AgentExchangeRequestInput, nonce: string) => ({
  expiresAt: input.expiresAt,
  maximumUses: 1 as const,
  nonce,
  processingMode: input.processingMode ?? "tool-confined",
  purpose: input.purpose,
  recipient: input.recipient,
  requester: input.requester,
  resource: input.resource,
  risk: input.risk,
  secretKind: input.secretKind,
});

const agencyAction = (
  input: AgentExchangeRequestInput,
  nonce: string,
): ActionRequestInput => ({
  action: "agent_exchange.deliver",
  actor: {
    agentId: input.requester.agentId,
    delegationId: input.requester.delegationId,
    scopes: ["agent-exchange:request"],
    userId: input.requester.subject,
  },
  authorizationDetails: [
    {
      account_ref: input.resource.accountRef,
      actions: [input.resource.operation],
      locations: [input.resource.origin],
      purpose: input.purpose,
      type: "agent_exchange",
    },
  ],
  effects: ["read", "send", "external-network"],
  expiresAt: input.expiresAt,
  idempotencyKey: input.idempotencyKey,
  input: safeRequestInput(input, nonce),
  resource: {
    id: `${input.recipient.authority}#${input.recipient.subject}:${input.recipient.agentId}`,
    properties: {
      operation: input.resource.operation,
      origin: input.resource.origin,
      purpose: input.purpose,
      risk: input.risk,
    },
    type: "agent_exchange_recipient",
  },
});

const requestNonce = async (input: AgentExchangeRequestInput) =>
  input.idempotencyKey === undefined
    ? `nonce_${crypto.randomUUID()}`
    : `nonce_${await digest({
        agentId: input.requester.agentId,
        authority: input.requester.authority,
        idempotencyKey: input.idempotencyKey,
        subject: input.requester.subject,
      })}`;

const validReceipt = (
  receipt: AgentExchangeReceipt,
  request: AgentExchangeRequest,
): boolean =>
  receipt.exchangeId === request.exchangeId &&
  receipt.maximumUses === 1 &&
  receipt.modelObservedSecret === false &&
  receipt.processingMode === "tool-confined" &&
  receipt.status === "submitted" &&
  Number.isSafeInteger(receipt.completedAt) &&
  receipt.completedAt >= request.createdAt &&
  receipt.consentId.trim().length > 0 &&
  (receipt.reference === undefined || receipt.reference.trim().length > 0);

export const createAgentExchangeSender = (
  options: AgentExchangeSenderOptions,
): AgentExchangeSender => {
  const now = options.now ?? Date.now;
  const maxTtlMs = options.maxTtlMs ?? DEFAULT_EXCHANGE_MAX_TTL_MS;
  const maxSecretBytes = options.maxSecretBytes ?? DEFAULT_MAX_SECRET_BYTES;
  const allowedProcessingModes = options.allowedProcessingModes ?? [
    "tool-confined",
  ];
  validatePositiveLimit(maxTtlMs);
  validatePositiveLimit(maxSecretBytes);

  const request = async (input: AgentExchangeRequestInput) => {
    const currentTime = now();
    validateAgentExchangeInput(input, {
      allowInsecureLocalhost: options.allowInsecureLocalhost ?? false,
      allowedProcessingModes,
      maxTtlMs,
      now: currentTime,
    });
    if (
      DEFAULT_BLOCKED_RISKS.has(input.risk) &&
      !(await options.allowHighRisk?.(input))
    ) {
      throw new AgentExchangeError("high_risk_denied");
    }

    const nonce = await requestNonce(input);
    const requested = await options.agency.request(agencyAction(input, nonce));
    const existing = await options.store.getByActionId(
      requested.action.actionId,
    );
    if (existing !== undefined) {
      return Object.freeze({
        decision: requested.decision,
        exchange: existing,
      });
    }

    const exchange: AgentExchangeRequest = Object.freeze({
      ...input,
      actionId: requested.action.actionId,
      createdAt: requested.action.createdAt,
      exchangeId: `xchg_${requested.action.actionId.slice(4)}`,
      maximumUses: 1,
      nonce,
      processingMode: input.processingMode ?? "tool-confined",
    });
    if (!(await options.store.save(exchange))) {
      const concurrent = await options.store.getByActionId(exchange.actionId);
      if (concurrent === undefined) {
        throw new AgentExchangeError("invalid_request");
      }
      return Object.freeze({
        decision: requested.decision,
        exchange: concurrent,
      });
    }

    return Object.freeze({ decision: requested.decision, exchange });
  };

  const issueLease = async (exchangeId: string) => {
    const exchange = await options.store.get(exchangeId);
    if (exchange === undefined) {
      throw new AgentExchangeError("exchange_not_found");
    }
    return options.agency.issueLease(exchange.actionId);
  };

  const execute: AgentExchangeSender["execute"] = async ({
    exchangeId,
    leaseId,
  }) => {
    const exchange = await options.store.get(exchangeId);
    if (exchange === undefined) {
      throw new AgentExchangeError("exchange_not_found");
    }

    const executed = await options.agency.execute({
      executor: "agent-exchange:sender",
      leaseId,
      run: async () => {
        let sensitive:
          Awaited<ReturnType<typeof options.source.read>> | undefined;
        try {
          try {
            sensitive = await options.source.read(exchange);
            validateSensitiveValue(sensitive, exchange, maxSecretBytes);
          } catch (error) {
            if (
              error instanceof AgentExchangeError &&
              error.code === "source_failed"
            ) {
              throw error;
            }
            throw new AgentExchangeError("source_failed");
          }

          let recipientKey;
          try {
            recipientKey = await options.keyDirectory.resolve(exchange);
            if (
              recipientKey.keyId.trim().length === 0 ||
              !(recipientKey.publicKey instanceof Uint8Array) ||
              recipientKey.publicKey.length === 0
            ) {
              throw new Error("invalid key");
            }
          } catch {
            throw new AgentExchangeError("key_resolution_failed");
          }

          const authenticatedContext = await agentExchangeContext(exchange);
          let envelope: Uint8Array;
          try {
            envelope = await options.e2ee.seal({
              authenticatedContext,
              plaintext: sensitive.bytes,
              recipientPublicKey: recipientKey.publicKey,
            });
          } catch {
            throw new AgentExchangeError("protection_failed");
          }

          let receipt: AgentExchangeReceipt;
          try {
            receipt = await options.transport.deliver({
              authenticatedContext,
              envelope,
              recipientKeyId: recipientKey.keyId,
              request: exchange,
            });
          } catch (error) {
            if (error instanceof AgentExchangeError) throw error;
            throw new AgentExchangeError("transport_failed");
          }
          assertNoSensitiveValue(receipt, sensitive.bytes);
          if (!validReceipt(receipt, exchange)) {
            throw new AgentExchangeError("transport_failed");
          }
          if (!(await options.store.saveReceipt(receipt))) {
            const existing = await options.store.getReceipt(
              exchange.exchangeId,
            );
            if (existing === undefined) {
              throw new AgentExchangeError("transport_failed");
            }
            return existing;
          }
          return receipt;
        } finally {
          sensitive?.bytes.fill(0);
        }
      },
    });

    return Object.freeze({
      agencyReceipt: executed.receipt,
      receipt: executed.result,
    });
  };

  return Object.freeze({ execute, issueLease, request });
};
