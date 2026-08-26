import type { A2aAgentCard, A2aMessage } from "@absolutejs/a2a";
import { AgentExchangeError } from "./errors";
import type { AgentExchangeRequest } from "./types";

export const ABSOLUTE_AGENT_EXCHANGE_EXTENSION =
  "https://github.com/absolutejs/agent-exchange/extensions/a2a/v1" as const;
export const AGENT_EXCHANGE_REQUEST_MEDIA_TYPE =
  "application/vnd.absolutejs.agent-exchange-reference+json" as const;

export type A2aAgentExchangeReference = {
  readonly actionId: string;
  readonly exchangeId: string;
  readonly expiresAt: number;
  readonly operation: string;
  readonly origin: string;
  readonly processingMode: "tool-confined";
  readonly provider: string;
  readonly purpose: string;
  readonly recipientAgentId: string;
};

export const withAgentExchangeExtension = (
  card: A2aAgentCard,
): A2aAgentCard => ({
  ...card,
  capabilities: {
    ...card.capabilities,
    extensions: [
      ...(card.capabilities.extensions ?? []).filter(
        (extension) => extension.uri !== ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
      ),
      {
        description:
          "Carries opaque, purpose-bound Agent Exchange references; protected values and envelopes remain outside ordinary A2A task history.",
        required: true,
        uri: ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
      },
    ],
  },
});

export const toA2aAgentExchangeReference = (
  request: AgentExchangeRequest,
): A2aAgentExchangeReference =>
  Object.freeze({
    actionId: request.actionId,
    exchangeId: request.exchangeId,
    expiresAt: request.expiresAt,
    operation: request.resource.operation,
    origin: request.resource.origin,
    processingMode: "tool-confined",
    provider: request.resource.provider,
    purpose: request.purpose,
    recipientAgentId: request.recipient.agentId,
  });

export const toA2aAgentExchangeMessage = (
  request: AgentExchangeRequest,
): A2aMessage => ({
  contextId: request.exchangeId,
  extensions: [ABSOLUTE_AGENT_EXCHANGE_EXTENSION],
  messageId: `msg_${crypto.randomUUID()}`,
  metadata: {
    [ABSOLUTE_AGENT_EXCHANGE_EXTENSION]: {
      exchangeId: request.exchangeId,
    },
  },
  parts: [
    {
      data: toA2aAgentExchangeReference(request),
      mediaType: AGENT_EXCHANGE_REQUEST_MEDIA_TYPE,
    },
  ],
  role: "ROLE_USER",
});

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

export const parseA2aAgentExchangeReference = (
  message: A2aMessage,
): A2aAgentExchangeReference => {
  const part = message.parts.find(
    (candidate) =>
      "data" in candidate &&
      candidate.mediaType === AGENT_EXCHANGE_REQUEST_MEDIA_TYPE,
  );
  const data = part !== undefined && "data" in part ? part.data : undefined;
  const allowedKeys = new Set([
    "actionId",
    "exchangeId",
    "expiresAt",
    "operation",
    "origin",
    "processingMode",
    "provider",
    "purpose",
    "recipientAgentId",
  ]);
  if (
    !isRecord(data) ||
    Object.keys(data).some((key) => !allowedKeys.has(key)) ||
    typeof data.actionId !== "string" ||
    typeof data.exchangeId !== "string" ||
    typeof data.expiresAt !== "number" ||
    typeof data.operation !== "string" ||
    typeof data.origin !== "string" ||
    data.processingMode !== "tool-confined" ||
    typeof data.provider !== "string" ||
    typeof data.purpose !== "string" ||
    typeof data.recipientAgentId !== "string"
  ) {
    throw new AgentExchangeError("invalid_request");
  }
  return data as A2aAgentExchangeReference;
};
