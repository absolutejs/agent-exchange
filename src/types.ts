import type {
  ActionDecision,
  ActionReceipt,
  Agency,
  ExecutionLease,
} from "@absolutejs/agency";
import type {
  AuthenticatedContext,
  EnvelopeProvider,
  SecretProcessingMode,
} from "@absolutejs/e2ee";

export type ExchangeIdentity = {
  readonly agentId: string;
  readonly authority: string;
  readonly delegationId?: string;
  readonly deviceId?: string;
  readonly subject: string;
};

export type ExchangeRiskClass =
  | "account-recovery"
  | "administrative"
  | "authentication"
  | "data-export"
  | "money-movement"
  | "routine"
  | "security-settings"
  | (string & {});

export type AgentExchangeAssurance =
  | {
      readonly approval: "policy";
      readonly credential: "bearer" | "origin-bound" | "sender-constrained";
      readonly execution: "general" | "purpose-bound";
    }
  | {
      readonly approval: "webauthn-verifier-bound";
      readonly credential:
        "origin-bound" | "sender-constrained" | "token-confined-broker";
      readonly execution: "purpose-bound";
    }
  | {
      readonly approval: "standing-mandate";
      readonly credential: "token-confined-broker";
      readonly execution: "purpose-bound";
    };

export type AgentExchangeMandatePrincipal = {
  readonly authority: string;
  readonly subject: string;
};

export type AgentExchangeMandateActor = AgentExchangeMandatePrincipal & {
  readonly agentId: string;
  readonly deviceId?: string;
};

export type AgentExchangeMandateGrant = {
  readonly accountRef: string;
  readonly operation: string;
  readonly origin: string;
  readonly provider: string;
  readonly purpose: string;
  readonly risk: ExchangeRiskClass;
  readonly secretKind: string;
};

export type AgentExchangeStandingMandate = {
  readonly approval: {
    readonly credentialIdHash: string;
    readonly method: "webauthn-verifier-bound";
    readonly rpId: string;
    readonly userVerified: true;
    readonly verifiedAt: number;
    readonly verifierOrigin: string;
  };
  readonly audience: AgentExchangeMandateActor;
  readonly expiresAt: number;
  readonly grants: readonly AgentExchangeMandateGrant[];
  readonly issuedAt: number;
  readonly issuer: AgentExchangeMandatePrincipal;
  readonly mandateId: string;
  readonly maximumUses: number;
  readonly notBefore: number;
  readonly requester: AgentExchangeMandateActor;
  readonly version: 1;
};

export type AgentExchangeStandingMandateInput = Omit<
  AgentExchangeStandingMandate,
  "issuedAt" | "version"
>;

export type AgentExchangeStandingMandateDraft = Omit<
  AgentExchangeStandingMandateInput,
  "approval"
>;

export type SignedAgentExchangeStandingMandate = {
  readonly compactJws: string;
};

export type AgentExchangeMandateJwsSigner = {
  readonly sign: (input: {
    readonly payload: Uint8Array;
    readonly type: "absolute-agent-exchange-mandate+jws";
  }) => Promise<string> | string;
};

export type AgentExchangeMandateJwsVerifier = {
  readonly verify: (input: {
    readonly compactJws: string;
    readonly expectedIssuer: AgentExchangeMandatePrincipal;
    readonly type: "absolute-agent-exchange-mandate+jws";
  }) =>
    | Promise<{
        readonly algorithm: string;
        readonly keyId: string;
        readonly payload: Uint8Array;
      }>
    | {
        readonly algorithm: string;
        readonly keyId: string;
        readonly payload: Uint8Array;
      };
};

export type AgentExchangeMandateRegistration = {
  readonly expiresAt: number;
  readonly issuer: AgentExchangeMandatePrincipal;
  readonly mandateId: string;
  readonly maximumUses: number;
};

export type AgentExchangeMandateConsumeResult =
  "consumed" | "exhausted" | "replay" | "revoked" | "unknown";

export type AgentExchangeMandateStore = {
  readonly consume: (input: {
    readonly exchangeId: string;
    readonly mandateId: string;
    readonly now: number;
  }) => Promise<AgentExchangeMandateConsumeResult>;
  readonly register: (
    registration: AgentExchangeMandateRegistration,
  ) => Promise<boolean>;
  readonly revoke: (input: {
    readonly issuer: AgentExchangeMandatePrincipal;
    readonly mandateId: string;
    readonly now: number;
  }) => Promise<boolean>;
};

export type AgentExchangeMandateAuthorization = {
  readonly algorithm: string;
  readonly keyId: string;
  readonly mandateId: string;
  readonly remainingUses?: number;
  readonly status: "authorized";
};

export type AgentExchangeStandingMandateAuthority = {
  readonly authorize: (input: {
    readonly expectedIssuer: AgentExchangeMandatePrincipal;
    readonly request: AgentExchangeRequest;
    readonly signedMandate: SignedAgentExchangeStandingMandate;
  }) => Promise<AgentExchangeMandateAuthorization>;
  readonly issue: (input: AgentExchangeStandingMandateInput) => Promise<{
    readonly mandate: AgentExchangeStandingMandate;
    readonly signedMandate: SignedAgentExchangeStandingMandate;
  }>;
  readonly revoke: (input: {
    readonly issuer: AgentExchangeMandatePrincipal;
    readonly mandateId: string;
  }) => Promise<boolean>;
};

export type ExchangeResource = {
  readonly accountRef: string;
  readonly challengeId?: string;
  readonly operation: string;
  readonly origin: string;
  readonly provider: string;
};

export type AgentExchangeRequestInput = {
  readonly assurance: AgentExchangeAssurance;
  readonly expiresAt: number;
  readonly idempotencyKey?: string;
  readonly processingMode?: SecretProcessingMode;
  readonly purpose: string;
  readonly recipient: ExchangeIdentity;
  readonly requester: ExchangeIdentity;
  readonly resource: ExchangeResource;
  readonly risk: ExchangeRiskClass;
  readonly secretKind: string;
};

export type AgentExchangeRequest = Omit<
  AgentExchangeRequestInput,
  "processingMode"
> & {
  readonly actionId: string;
  readonly createdAt: number;
  readonly exchangeId: string;
  readonly maximumUses: 1;
  readonly nonce: string;
  readonly processingMode: SecretProcessingMode;
};

export type RequestedAgentExchange = {
  readonly decision: ActionDecision;
  readonly exchange: AgentExchangeRequest;
};

export type SensitiveValue = {
  readonly bytes: Uint8Array;
  readonly evidence?: {
    readonly matchedAt: number;
    readonly messageId: string;
    readonly parserId: string;
    readonly provider: string;
  };
};

export type SensitiveValueSource = {
  readonly read: (
    request: AgentExchangeRequest,
  ) => Promise<SensitiveValue> | SensitiveValue;
};

export type SensitiveValueSinkResult = {
  readonly reference?: string;
  readonly status: "submitted";
};

export type SensitiveValueSink = {
  readonly submit: (input: {
    readonly plaintext: Uint8Array;
    readonly request: AgentExchangeRequest;
  }) => Promise<SensitiveValueSinkResult> | SensitiveValueSinkResult;
};

export type RecipientKey = {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
};

export type RecipientKeyDirectory = {
  readonly resolve: (
    request: AgentExchangeRequest,
  ) => Promise<RecipientKey> | RecipientKey;
};

export type AgentExchangeDelivery = {
  readonly authenticatedContext: AuthenticatedContext;
  readonly envelope: Uint8Array;
  readonly recipientKeyId: string;
  readonly request: AgentExchangeRequest;
};

export type AgentExchangeReceipt = {
  readonly assurance: AgentExchangeAssurance;
  readonly completedAt: number;
  readonly consentId: string;
  readonly exchangeId: string;
  readonly maximumUses: 1;
  readonly modelObservedSecret: false;
  readonly processingMode: "tool-confined";
  readonly reference?: string;
  readonly status: "submitted";
};

export type AgentExchangeWebAuthnApprovalEvidence = {
  readonly challenge: string;
  readonly credentialIdHash: string;
  readonly requestDigest: string;
  readonly rpId: string;
  readonly subject: string;
  readonly userVerified: true;
  readonly verifiedAt: number;
  readonly verifierOrigin: string;
};

export type AgentExchangeApprovalProvider = {
  readonly begin: (input: {
    readonly challenge: string;
    readonly request: AgentExchangeRequest;
    readonly subject: string;
    readonly verifierOrigin: string;
  }) =>
    | Promise<{ readonly challenge: string; readonly options: unknown }>
    | { readonly challenge: string; readonly options: unknown };
  readonly verify: (input: {
    readonly challenge: string;
    readonly request: AgentExchangeRequest;
    readonly response: unknown;
    readonly subject: string;
    readonly verifierOrigin: string;
  }) =>
    | Promise<{
        readonly credentialId: string;
        readonly rpId: string;
        readonly subject: string;
        readonly userVerified: true;
        readonly verifierOrigin: string;
      }>
    | {
        readonly credentialId: string;
        readonly rpId: string;
        readonly subject: string;
        readonly userVerified: true;
        readonly verifierOrigin: string;
      };
};

export type AgentExchangeTransport = {
  readonly deliver: (
    delivery: AgentExchangeDelivery,
  ) => Promise<AgentExchangeReceipt>;
};

export type RecipientConsent = {
  readonly consentId: string;
  readonly expiresAt: number;
};

export type RecipientConsentVerifier = {
  readonly assertAllows: (
    request: AgentExchangeRequest,
  ) => Promise<RecipientConsent> | RecipientConsent;
};

export type AgentExchangeReplayStore = {
  readonly consume: (input: {
    readonly exchangeId: string;
    readonly expiresAt: number;
    readonly nonce: string;
    readonly now: number;
  }) => Promise<boolean>;
};

export type AgentExchangeStore = {
  readonly get: (
    exchangeId: string,
  ) => Promise<AgentExchangeRequest | undefined>;
  readonly getByActionId: (
    actionId: string,
  ) => Promise<AgentExchangeRequest | undefined>;
  readonly getReceipt: (
    exchangeId: string,
  ) => Promise<AgentExchangeReceipt | undefined>;
  readonly save: (request: AgentExchangeRequest) => Promise<boolean>;
  readonly saveReceipt: (receipt: AgentExchangeReceipt) => Promise<boolean>;
};

export type AgentExchangeSenderOptions = {
  readonly approvalProvider?: AgentExchangeApprovalProvider;
  readonly agency: Agency;
  readonly allowHighRisk?: (
    input: AgentExchangeRequestInput,
  ) => Promise<boolean> | boolean;
  readonly allowInsecureLocalhost?: boolean;
  readonly allowedProcessingModes?: readonly SecretProcessingMode[];
  readonly e2ee: EnvelopeProvider;
  readonly keyDirectory: RecipientKeyDirectory;
  readonly maxSecretBytes?: number;
  readonly maxTtlMs?: number;
  readonly now?: () => number;
  readonly source: SensitiveValueSource;
  readonly store: AgentExchangeStore;
  readonly transport: AgentExchangeTransport;
};

export type AgentExchangeReceiverOptions = {
  readonly allowInsecureLocalhost?: boolean;
  readonly consent: RecipientConsentVerifier;
  readonly e2ee: EnvelopeProvider;
  readonly maxSecretBytes?: number;
  readonly maxTtlMs?: number;
  readonly now?: () => number;
  readonly replay: AgentExchangeReplayStore;
  readonly sink: SensitiveValueSink;
};

export type AgentExchangeSender = {
  readonly approve: (input: {
    readonly exchangeId: string;
    readonly response: unknown;
  }) => Promise<AgentExchangeWebAuthnApprovalEvidence>;
  readonly beginApproval: (exchangeId: string) => Promise<{
    readonly challenge: string;
    readonly options: unknown;
  }>;
  readonly execute: (input: {
    readonly exchangeId: string;
    readonly leaseId: string;
  }) => Promise<{
    readonly agencyReceipt: ActionReceipt;
    readonly receipt: AgentExchangeReceipt;
  }>;
  readonly issueLease: (exchangeId: string) => Promise<ExecutionLease>;
  readonly request: (
    input: AgentExchangeRequestInput,
  ) => Promise<RequestedAgentExchange>;
};

export type AgentExchangeReceiver = {
  readonly receive: (
    delivery: AgentExchangeDelivery,
  ) => Promise<AgentExchangeReceipt>;
};

export type AgentExchangeTelemetry = {
  readonly attributes: Readonly<Record<string, boolean | number | string>>;
  readonly name: "agent_exchange.completed" | "agent_exchange.failed";
};
