import type { A2aAgentCard, A2aMessage } from "@absolutejs/a2a";
import { AgentExchangeError } from "./errors";
import type { AgentExchangeAssurance, AgentExchangeRequest } from "./types";
import { isAgentExchangeAssurance } from "./validation";

export const ABSOLUTE_AGENT_EXCHANGE_EXTENSION =
  "https://github.com/absolutejs/agent-exchange/extensions/a2a/v1" as const;
export const AGENT_EXCHANGE_REQUEST_MEDIA_TYPE =
  "application/vnd.absolutejs.agent-exchange-reference+json" as const;

const MAX_A2A_IDENTIFIER_BYTES = 512;
const MAX_A2A_PURPOSE_BYTES = 2_048;
const encoder = new TextEncoder();

export type A2aAgentExchangeReference = {
  readonly actionId: string;
  readonly assurance: AgentExchangeAssurance;
  readonly exchangeId: string;
  readonly expiresAt: number;
  readonly mandateId?: string;
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
    assurance: request.assurance,
    exchangeId: request.exchangeId,
    expiresAt: request.expiresAt,
    ...(request.mandateId === undefined
      ? {}
      : { mandateId: request.mandateId }),
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

const bounded = (value: unknown, maximumBytes: number): value is string =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  encoder.encode(value).byteLength <= maximumBytes;

const secureOrigin = (value: unknown): value is string => {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    const local =
      parsed.protocol === "http:" &&
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1");
    return (
      parsed.origin === value &&
      parsed.username === "" &&
      parsed.password === "" &&
      (parsed.protocol === "https:" || local)
    );
  } catch {
    return false;
  }
};

export const parseA2aAgentExchangeReference = (
  message: A2aMessage,
): A2aAgentExchangeReference => {
  const part = message.parts.find(
    (candidate) =>
      "data" in candidate &&
      candidate.mediaType === AGENT_EXCHANGE_REQUEST_MEDIA_TYPE,
  );
  const data = part !== undefined && "data" in part ? part.data : undefined;
  const extensionMetadata =
    message.metadata?.[ABSOLUTE_AGENT_EXCHANGE_EXTENSION];
  const allowedKeys = new Set([
    "actionId",
    "assurance",
    "exchangeId",
    "expiresAt",
    "mandateId",
    "operation",
    "origin",
    "processingMode",
    "provider",
    "purpose",
    "recipientAgentId",
  ]);
  if (
    message.role !== "ROLE_USER" ||
    message.extensions?.includes(ABSOLUTE_AGENT_EXCHANGE_EXTENSION) !== true ||
    !isRecord(extensionMetadata) ||
    Object.keys(extensionMetadata).some((key) => key !== "exchangeId") ||
    !isRecord(data) ||
    Object.keys(data).some((key) => !allowedKeys.has(key)) ||
    !bounded(data.actionId, MAX_A2A_IDENTIFIER_BYTES) ||
    !isAgentExchangeAssurance(data.assurance) ||
    !bounded(data.exchangeId, MAX_A2A_IDENTIFIER_BYTES) ||
    extensionMetadata.exchangeId !== data.exchangeId ||
    message.contextId !== data.exchangeId ||
    !Number.isSafeInteger(data.expiresAt) ||
    (data.expiresAt as number) <= 0 ||
    (data.assurance.approval === "standing-mandate"
      ? !bounded(data.mandateId, MAX_A2A_IDENTIFIER_BYTES)
      : data.mandateId !== undefined) ||
    !bounded(data.operation, MAX_A2A_IDENTIFIER_BYTES) ||
    !secureOrigin(data.origin) ||
    data.processingMode !== "tool-confined" ||
    !bounded(data.provider, MAX_A2A_IDENTIFIER_BYTES) ||
    !bounded(data.purpose, MAX_A2A_PURPOSE_BYTES) ||
    !bounded(data.recipientAgentId, MAX_A2A_IDENTIFIER_BYTES)
  ) {
    throw new AgentExchangeError("invalid_request");
  }
  return data as A2aAgentExchangeReference;
};
