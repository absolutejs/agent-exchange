import { digest } from "@absolutejs/agency";
import type { AuthenticatedContext } from "@absolutejs/e2ee";
import type { AgentExchangeRequest } from "./types";

export const agentExchangeBinding = (request: AgentExchangeRequest) => ({
  actionId: request.actionId,
  exchangeId: request.exchangeId,
  expiresAt: request.expiresAt,
  maximumUses: request.maximumUses,
  nonce: request.nonce,
  processingMode: request.processingMode,
  purpose: request.purpose,
  recipient: request.recipient,
  requester: request.requester,
  resource: request.resource,
  risk: request.risk,
  secretKind: request.secretKind,
});

export const agentExchangeContext = async (
  request: AgentExchangeRequest,
): Promise<AuthenticatedContext> => ({
  conversationId: request.exchangeId,
  expiresAt: request.expiresAt,
  purpose: `agent-exchange:${await digest(agentExchangeBinding(request))}`,
  securityEpoch: 0,
  senderId: `${request.requester.authority}#${request.requester.subject}:${request.requester.agentId}`,
});
