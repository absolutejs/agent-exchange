import type { AgentExchangeErrorCode } from "./errors";
import type {
  AgentExchangeReceipt,
  AgentExchangeRequest,
  AgentExchangeTelemetry,
} from "./types";

export const agentExchangeReceiptToTelemetry = (
  request: AgentExchangeRequest,
  receipt: AgentExchangeReceipt,
): AgentExchangeTelemetry => ({
  attributes: Object.freeze({
    "agent.exchange.duration_ms": Math.max(
      0,
      receipt.completedAt - request.createdAt,
    ),
    "agent.exchange.id": request.exchangeId,
    "agent.exchange.maximum_uses": 1,
    "agent.exchange.processing_mode": request.processingMode,
    "agent.exchange.purpose": request.purpose,
    "agent.exchange.risk": request.risk,
    "agent.exchange.status": receipt.status,
  }),
  name: "agent_exchange.completed",
});

export const agentExchangeErrorToTelemetry = (
  request: AgentExchangeRequest,
  code: AgentExchangeErrorCode,
): AgentExchangeTelemetry => ({
  attributes: Object.freeze({
    "agent.exchange.error_code": code,
    "agent.exchange.id": request.exchangeId,
    "agent.exchange.processing_mode": request.processingMode,
    "agent.exchange.purpose": request.purpose,
    "agent.exchange.risk": request.risk,
  }),
  name: "agent_exchange.failed",
});
