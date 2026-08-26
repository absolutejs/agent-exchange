export type AgentExchangeErrorCode =
  | "consent_failed"
  | "exchange_not_found"
  | "high_risk_denied"
  | "invalid_request"
  | "key_resolution_failed"
  | "mandate_exhausted"
  | "mandate_invalid"
  | "mandate_revoked"
  | "open_failed"
  | "protection_failed"
  | "replay_check_failed"
  | "replay_detected"
  | "secret_leak_detected"
  | "sink_failed"
  | "source_failed"
  | "transport_failed";

const messages: Readonly<Record<AgentExchangeErrorCode, string>> = {
  consent_failed: "Recipient consent did not authorize this exchange.",
  exchange_not_found: "Agent exchange was not found.",
  high_risk_denied: "This high-risk exchange is denied by default.",
  invalid_request: "Agent exchange request is invalid.",
  key_resolution_failed: "Recipient key resolution failed.",
  mandate_exhausted: "Standing mandate has no remaining authorized uses.",
  mandate_invalid:
    "Standing mandate is invalid or does not authorize this exchange.",
  mandate_revoked: "Standing mandate has been revoked.",
  open_failed: "Protected exchange could not be opened.",
  protection_failed: "Sensitive value protection failed.",
  replay_check_failed: "Agent exchange replay validation failed.",
  replay_detected: "Agent exchange was already consumed.",
  secret_leak_detected: "A protected value reached a forbidden result surface.",
  sink_failed: "Recipient sink rejected the protected operation.",
  source_failed: "Sensitive value retrieval failed.",
  transport_failed: "Protected exchange delivery failed.",
};

export class AgentExchangeError extends Error {
  override readonly name = "AgentExchangeError";

  constructor(readonly code: AgentExchangeErrorCode) {
    super(messages[code]);
  }
}

export const safeAgentExchangeError = (
  error: unknown,
  fallback: AgentExchangeErrorCode,
): AgentExchangeError =>
  error instanceof AgentExchangeError
    ? error
    : new AgentExchangeError(fallback);
