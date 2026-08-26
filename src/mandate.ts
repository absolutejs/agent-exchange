import { AgentExchangeError } from "./errors";
import type {
  AgentExchangeMandateActor,
  AgentExchangeMandateGrant,
  AgentExchangeMandateJwsSigner,
  AgentExchangeMandateJwsVerifier,
  AgentExchangeMandatePrincipal,
  AgentExchangeMandateStore,
  AgentExchangeStandingMandate,
  AgentExchangeStandingMandateAuthority,
  AgentExchangeStandingMandateInput,
  ExchangeIdentity,
} from "./types";
import {
  DEFAULT_EXCHANGE_MAX_TTL_MS,
  validateAgentExchangeRequest,
  validatePositiveLimit,
} from "./validation";

export const AGENT_EXCHANGE_MANDATE_JWS_TYPE =
  "absolute-agent-exchange-mandate+jws" as const;
export const DEFAULT_MANDATE_MAX_TTL_MS = 30 * 24 * 60 * 60_000;
export const DEFAULT_MANDATE_MAX_USES = 100;
export const DEFAULT_MANDATE_MAX_GRANTS = 20;
export const DEFAULT_MANDATE_APPROVAL_MAX_AGE_MS = 5 * 60_000;
export const DEFAULT_MANDATE_MAX_PAYLOAD_BYTES = 32_768;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const nonEmpty = (value: string): boolean => value.trim().length > 0;
const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const hasOnlyKeys = (
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean => {
  const allowed = new Set(keys);
  return Object.keys(value).every((key) => allowed.has(key));
};

const validOrigin = (
  value: string,
  allowInsecureLocalhost: boolean,
): boolean => {
  try {
    const parsed = new URL(value);
    if (
      parsed.origin !== value ||
      parsed.username !== "" ||
      parsed.password !== ""
    ) {
      return false;
    }
    return (
      parsed.protocol === "https:" ||
      (allowInsecureLocalhost &&
        parsed.protocol === "http:" &&
        (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1"))
    );
  } catch {
    return false;
  }
};

const validPrincipal = (
  value: unknown,
  allowInsecureLocalhost: boolean,
): value is AgentExchangeMandatePrincipal =>
  isRecord(value) &&
  hasOnlyKeys(value, ["authority", "subject"]) &&
  typeof value.authority === "string" &&
  validOrigin(value.authority, allowInsecureLocalhost) &&
  typeof value.subject === "string" &&
  nonEmpty(value.subject);

const validActor = (
  value: unknown,
  allowInsecureLocalhost: boolean,
): value is AgentExchangeMandateActor =>
  isRecord(value) &&
  hasOnlyKeys(value, ["agentId", "authority", "deviceId", "subject"]) &&
  typeof value.agentId === "string" &&
  nonEmpty(value.agentId) &&
  typeof value.authority === "string" &&
  validOrigin(value.authority, allowInsecureLocalhost) &&
  (value.deviceId === undefined ||
    (typeof value.deviceId === "string" && nonEmpty(value.deviceId))) &&
  typeof value.subject === "string" &&
  nonEmpty(value.subject);

const validGrant = (
  value: unknown,
  allowInsecureLocalhost: boolean,
): value is AgentExchangeMandateGrant =>
  isRecord(value) &&
  hasOnlyKeys(value, [
    "accountRef",
    "operation",
    "origin",
    "provider",
    "purpose",
    "risk",
    "secretKind",
  ]) &&
  typeof value.accountRef === "string" &&
  nonEmpty(value.accountRef) &&
  typeof value.operation === "string" &&
  nonEmpty(value.operation) &&
  typeof value.origin === "string" &&
  validOrigin(value.origin, allowInsecureLocalhost) &&
  typeof value.provider === "string" &&
  nonEmpty(value.provider) &&
  typeof value.purpose === "string" &&
  nonEmpty(value.purpose) &&
  typeof value.risk === "string" &&
  nonEmpty(value.risk) &&
  typeof value.secretKind === "string" &&
  nonEmpty(value.secretKind);

const validRpId = (rpId: string, verifierOrigin: string): boolean => {
  try {
    const hostname = new URL(verifierOrigin).hostname;
    return hostname === rpId || hostname.endsWith(`.${rpId}`);
  } catch {
    return false;
  }
};

const validateMandate = (
  value: unknown,
  options: {
    readonly allowInsecureLocalhost: boolean;
    readonly maxApprovalAgeMs: number;
    readonly maxGrants: number;
    readonly maxTtlMs: number;
    readonly maxUses: number;
    readonly now: number;
  },
): AgentExchangeStandingMandate => {
  if (!isRecord(value)) throw new AgentExchangeError("mandate_invalid");
  const approval = value.approval;
  if (
    !hasOnlyKeys(value, [
      "approval",
      "audience",
      "expiresAt",
      "grants",
      "issuedAt",
      "issuer",
      "mandateId",
      "maximumUses",
      "notBefore",
      "requester",
      "version",
    ]) ||
    value.version !== 1 ||
    typeof value.mandateId !== "string" ||
    !nonEmpty(value.mandateId) ||
    !validPrincipal(value.issuer, options.allowInsecureLocalhost) ||
    !validActor(value.requester, options.allowInsecureLocalhost) ||
    !validActor(value.audience, options.allowInsecureLocalhost) ||
    !Array.isArray(value.grants) ||
    value.grants.length < 1 ||
    value.grants.length > options.maxGrants ||
    !value.grants.every((grant) =>
      validGrant(grant, options.allowInsecureLocalhost),
    ) ||
    !Number.isSafeInteger(value.issuedAt) ||
    !Number.isSafeInteger(value.notBefore) ||
    !Number.isSafeInteger(value.expiresAt) ||
    !Number.isSafeInteger(value.maximumUses) ||
    (value.maximumUses as number) < 1 ||
    (value.maximumUses as number) > options.maxUses ||
    (value.issuedAt as number) > options.now ||
    (value.notBefore as number) < (value.issuedAt as number) ||
    (value.expiresAt as number) <= (value.notBefore as number) ||
    (value.expiresAt as number) >
      (value.issuedAt as number) + options.maxTtlMs ||
    !isRecord(approval) ||
    !hasOnlyKeys(approval, [
      "credentialIdHash",
      "method",
      "rpId",
      "userVerified",
      "verifiedAt",
      "verifierOrigin",
    ]) ||
    approval.method !== "webauthn-verifier-bound" ||
    typeof approval.credentialIdHash !== "string" ||
    !nonEmpty(approval.credentialIdHash) ||
    typeof approval.rpId !== "string" ||
    !nonEmpty(approval.rpId) ||
    approval.userVerified !== true ||
    typeof approval.verifiedAt !== "number" ||
    !Number.isSafeInteger(approval.verifiedAt) ||
    approval.verifiedAt > (value.issuedAt as number) ||
    approval.verifiedAt <
      (value.issuedAt as number) - options.maxApprovalAgeMs ||
    typeof approval.verifierOrigin !== "string" ||
    !validOrigin(approval.verifierOrigin, options.allowInsecureLocalhost) ||
    approval.verifierOrigin !== value.issuer.authority ||
    !validRpId(approval.rpId, approval.verifierOrigin)
  ) {
    throw new AgentExchangeError("mandate_invalid");
  }
  return value as AgentExchangeStandingMandate;
};

const canonicalize = (value: unknown): string => {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new AgentExchangeError("mandate_invalid");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (!isRecord(value)) throw new AgentExchangeError("mandate_invalid");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
};

const samePrincipal = (
  left: AgentExchangeMandatePrincipal,
  right: AgentExchangeMandatePrincipal,
): boolean =>
  left.authority === right.authority && left.subject === right.subject;

const sameActor = (
  actor: AgentExchangeMandateActor,
  identity: ExchangeIdentity,
): boolean =>
  actor.agentId === identity.agentId &&
  actor.authority === identity.authority &&
  actor.subject === identity.subject &&
  actor.deviceId === identity.deviceId;

const grantAllows = (
  grant: AgentExchangeMandateGrant,
  request: Parameters<
    AgentExchangeStandingMandateAuthority["authorize"]
  >[0]["request"],
): boolean =>
  grant.accountRef === request.resource.accountRef &&
  grant.operation === request.resource.operation &&
  grant.origin === request.resource.origin &&
  grant.provider === request.resource.provider &&
  grant.purpose === request.purpose &&
  grant.risk === request.risk &&
  grant.secretKind === request.secretKind;

export const createAgentExchangeStandingMandateAuthority = (options: {
  readonly allowInsecureLocalhost?: boolean;
  readonly allowedAlgorithms?: readonly string[];
  readonly maxApprovalAgeMs?: number;
  readonly maxGrants?: number;
  readonly maxPayloadBytes?: number;
  readonly requestMaxTtlMs?: number;
  readonly maxTtlMs?: number;
  readonly maxUses?: number;
  readonly now?: () => number;
  readonly signer: AgentExchangeMandateJwsSigner;
  readonly store: AgentExchangeMandateStore;
  readonly verifier: AgentExchangeMandateJwsVerifier;
}): AgentExchangeStandingMandateAuthority => {
  const allowInsecureLocalhost = options.allowInsecureLocalhost ?? false;
  const allowedAlgorithms = options.allowedAlgorithms ?? ["ES256", "EdDSA"];
  const maxApprovalAgeMs =
    options.maxApprovalAgeMs ?? DEFAULT_MANDATE_APPROVAL_MAX_AGE_MS;
  const maxGrants = options.maxGrants ?? DEFAULT_MANDATE_MAX_GRANTS;
  const maxPayloadBytes =
    options.maxPayloadBytes ?? DEFAULT_MANDATE_MAX_PAYLOAD_BYTES;
  const requestMaxTtlMs =
    options.requestMaxTtlMs ?? DEFAULT_EXCHANGE_MAX_TTL_MS;
  const maxTtlMs = options.maxTtlMs ?? DEFAULT_MANDATE_MAX_TTL_MS;
  const maxUses = options.maxUses ?? DEFAULT_MANDATE_MAX_USES;
  validatePositiveLimit(maxApprovalAgeMs);
  validatePositiveLimit(maxGrants);
  validatePositiveLimit(maxPayloadBytes);
  validatePositiveLimit(requestMaxTtlMs);
  validatePositiveLimit(maxTtlMs);
  validatePositiveLimit(maxUses);

  const validate = (value: unknown, now: number) =>
    validateMandate(value, {
      allowInsecureLocalhost,
      maxApprovalAgeMs,
      maxGrants,
      maxTtlMs,
      maxUses,
      now,
    });

  return Object.freeze({
    authorize: async ({ expectedIssuer, request, signedMandate }) => {
      const now = options.now?.() ?? Date.now();
      validateAgentExchangeRequest(request, {
        allowInsecureLocalhost,
        maxTtlMs: requestMaxTtlMs,
        now,
      });
      let verified;
      let decoded: string;
      let parsed: unknown;
      try {
        verified = await options.verifier.verify({
          compactJws: signedMandate.compactJws,
          expectedIssuer,
          type: AGENT_EXCHANGE_MANDATE_JWS_TYPE,
        });
        if (verified.payload.byteLength > maxPayloadBytes) {
          throw new Error("oversized mandate");
        }
        decoded = decoder.decode(verified.payload);
        parsed = JSON.parse(decoded) as unknown;
      } catch {
        throw new AgentExchangeError("mandate_invalid");
      }
      if (canonicalize(parsed) !== decoded) {
        throw new AgentExchangeError("mandate_invalid");
      }
      const mandate = validate(parsed, now);
      if (
        !samePrincipal(mandate.issuer, expectedIssuer) ||
        now < mandate.notBefore ||
        now >= mandate.expiresAt ||
        request.createdAt < mandate.notBefore ||
        request.expiresAt > mandate.expiresAt ||
        request.mandateId !== mandate.mandateId ||
        request.assurance.approval !== "standing-mandate" ||
        request.assurance.credential !== "token-confined-broker" ||
        !sameActor(mandate.requester, request.requester) ||
        !sameActor(mandate.audience, request.recipient) ||
        !mandate.grants.some((grant) => grantAllows(grant, request)) ||
        !allowedAlgorithms.includes(verified.algorithm) ||
        !nonEmpty(verified.keyId)
      ) {
        throw new AgentExchangeError("mandate_invalid");
      }
      const result = await options.store.consume({
        exchangeId: request.exchangeId,
        mandateId: mandate.mandateId,
        now,
      });
      if (result === "revoked") throw new AgentExchangeError("mandate_revoked");
      if (result === "exhausted")
        throw new AgentExchangeError("mandate_exhausted");
      if (result === "replay") throw new AgentExchangeError("replay_detected");
      if (result !== "consumed")
        throw new AgentExchangeError("mandate_invalid");
      return {
        algorithm: verified.algorithm,
        keyId: verified.keyId,
        mandateId: mandate.mandateId,
        status: "authorized",
      };
    },
    issue: async (input: AgentExchangeStandingMandateInput) => {
      const now = options.now?.() ?? Date.now();
      const mandate = validate({ ...input, issuedAt: now, version: 1 }, now);
      const compactJws = await options.signer.sign({
        payload: encoder.encode(canonicalize(mandate)),
        type: AGENT_EXCHANGE_MANDATE_JWS_TYPE,
      });
      if (!nonEmpty(compactJws))
        throw new AgentExchangeError("mandate_invalid");
      const registered = await options.store.register({
        expiresAt: mandate.expiresAt,
        issuer: mandate.issuer,
        mandateId: mandate.mandateId,
        maximumUses: mandate.maximumUses,
      });
      if (!registered) throw new AgentExchangeError("mandate_invalid");
      return { mandate, signedMandate: { compactJws } };
    },
    revoke: async ({ issuer, mandateId }) =>
      options.store.revoke({
        issuer,
        mandateId,
        now: options.now?.() ?? Date.now(),
      }),
  });
};
