import { canonicalJson } from "@absolutejs/agency";
import { agentExchangeContext } from "./context";
import { AgentExchangeError } from "./errors";
import { assertNoSensitiveValue } from "./leakage";
import type {
  AgentExchangeReceiver,
  AgentExchangeReceiverOptions,
  AgentExchangeReceipt,
} from "./types";
import {
  DEFAULT_EXCHANGE_MAX_TTL_MS,
  DEFAULT_MAX_SECRET_BYTES,
  validateAgentExchangeRequest,
  validatePositiveLimit,
  validateSensitiveValue,
} from "./validation";

export const createAgentExchangeReceiver = (
  options: AgentExchangeReceiverOptions,
): AgentExchangeReceiver => {
  const now = options.now ?? Date.now;
  const maxTtlMs = options.maxTtlMs ?? DEFAULT_EXCHANGE_MAX_TTL_MS;
  const maxSecretBytes = options.maxSecretBytes ?? DEFAULT_MAX_SECRET_BYTES;
  validatePositiveLimit(maxTtlMs);
  validatePositiveLimit(maxSecretBytes);

  return Object.freeze({
    receive: async (delivery) => {
      const currentTime = now();
      validateAgentExchangeRequest(delivery.request, {
        allowInsecureLocalhost: options.allowInsecureLocalhost ?? false,
        maxTtlMs,
        now: currentTime,
      });

      const expectedContext = await agentExchangeContext(delivery.request);
      if (
        canonicalJson(delivery.authenticatedContext) !==
        canonicalJson(expectedContext)
      ) {
        throw new AgentExchangeError("invalid_request");
      }

      let consent;
      try {
        consent = await options.consent.assertAllows(delivery.request);
        if (
          consent.consentId.trim().length === 0 ||
          !Number.isSafeInteger(consent.expiresAt) ||
          consent.expiresAt <= currentTime
        ) {
          throw new Error("invalid consent");
        }
      } catch {
        throw new AgentExchangeError("consent_failed");
      }

      let plaintext: Uint8Array | undefined;
      try {
        try {
          plaintext = await options.e2ee.open({
            envelope: delivery.envelope,
            expectedContext,
            recipientKeyHandle: delivery.recipientKeyId,
          });
          validateSensitiveValue(
            { bytes: plaintext },
            delivery.request,
            maxSecretBytes,
          );
        } catch {
          throw new AgentExchangeError("open_failed");
        }

        let consumed: boolean;
        try {
          consumed = await options.replay.consume({
            exchangeId: delivery.request.exchangeId,
            expiresAt: delivery.request.expiresAt,
            nonce: delivery.request.nonce,
            now: currentTime,
          });
        } catch {
          throw new AgentExchangeError("replay_check_failed");
        }
        if (!consumed) throw new AgentExchangeError("replay_detected");
        if (now() >= delivery.request.expiresAt) {
          throw new AgentExchangeError("invalid_request");
        }

        let result;
        try {
          result = await options.sink.submit({
            plaintext,
            request: delivery.request,
          });
        } catch {
          throw new AgentExchangeError("sink_failed");
        }
        assertNoSensitiveValue(result, plaintext);
        if (
          result.status !== "submitted" ||
          (result.reference !== undefined &&
            result.reference.trim().length === 0)
        ) {
          throw new AgentExchangeError("sink_failed");
        }

        const receipt: AgentExchangeReceipt = Object.freeze({
          assurance: delivery.request.assurance,
          completedAt: now(),
          consentId: consent.consentId,
          exchangeId: delivery.request.exchangeId,
          maximumUses: 1,
          modelObservedSecret: false,
          processingMode: "tool-confined",
          reference: result.reference,
          status: "submitted",
        });
        assertNoSensitiveValue(receipt, plaintext);
        return receipt;
      } finally {
        plaintext?.fill(0);
      }
    },
  });
};
