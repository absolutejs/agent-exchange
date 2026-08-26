import {
  createAgency,
  createMemoryAgencyStore,
  type Agency,
  type PolicyDecisionPoint,
} from "@absolutejs/agency";
import {
  createWebCryptoEnvelopeProvider,
  generateWebCryptoRecipientKeyPair,
} from "@absolutejs/e2ee-webcrypto";
import {
  createAgentExchangeReceiver,
  createAgentExchangeSender,
  createMemoryAgentExchangeReplayStore,
  createMemoryAgentExchangeStore,
  type AgentExchangeDelivery,
  type AgentExchangeRequestInput,
  type RecipientConsentVerifier,
  type SensitiveValueSink,
  type SensitiveValueSource,
} from "../src";

export const CODE = "482193";

export const requestInput = (
  overrides: Partial<AgentExchangeRequestInput> = {},
): AgentExchangeRequestInput => ({
  expiresAt: Date.now() + 60_000,
  idempotencyKey: crypto.randomUUID(),
  purpose: "email.verification.submit",
  recipient: {
    agentId: "agent-recipient",
    authority: "https://auth.recipient.example",
    deviceId: "device-recipient",
    subject: "user-recipient",
  },
  requester: {
    agentId: "agent-requester",
    authority: "https://auth.requester.example",
    delegationId: "delegation-requester",
    deviceId: "device-requester",
    subject: "user-requester",
  },
  resource: {
    accountRef: "account_01K4Y1",
    challengeId: "challenge_01K4Y2",
    operation: "verification.submit",
    origin: "https://accounts.example.com",
    provider: "gmail",
  },
  risk: "authentication",
  secretKind: "email-one-time-code",
  ...overrides,
});

const approvalPolicy = (): PolicyDecisionPoint => ({
  evaluate: ({ approval, now }) =>
    approval === undefined
      ? {
          decisionId: `decision_${crypto.randomUUID()}`,
          evaluatedAt: now,
          kind: "deny",
          prerequisites: [
            {
              kind: "consent",
              prerequisiteId: "recipient-pairing",
              title: "Approve the exact paired exchange",
            },
          ],
          reason: "Exact approval is required.",
          requestable: true,
        }
      : {
          decisionId: `decision_${crypto.randomUUID()}`,
          evaluatedAt: now,
          kind: "allow",
        },
});

export type ExchangeFixture = Awaited<ReturnType<typeof exchangeFixture>>;

export const exchangeFixture = async (
  options: {
    consent?: RecipientConsentVerifier;
    sink?: SensitiveValueSink;
    source?: SensitiveValueSource;
  } = {},
) => {
  const agencyStore = createMemoryAgencyStore();
  const agency: Agency = createAgency({
    policy: approvalPolicy(),
    store: agencyStore,
  });
  const exchangeStore = createMemoryAgentExchangeStore();
  const replay = createMemoryAgentExchangeReplayStore();
  const keyPair = await generateWebCryptoRecipientKeyPair();
  const e2ee = createWebCryptoEnvelopeProvider({
    maxPlaintextBytes: 256,
    resolveRecipientPrivateKey: async (handle) =>
      handle === "recipient-key" ? keyPair.keyMaterial : undefined,
  });
  const deliveries: AgentExchangeDelivery[] = [];
  const submitted: string[] = [];
  const sourceBuffers: Uint8Array[] = [];
  const source =
    options.source ??
    ({
      read: () => {
        const bytes = new TextEncoder().encode(CODE);
        sourceBuffers.push(bytes);
        return {
          bytes,
          evidence: {
            matchedAt: Date.now(),
            messageId: "gmail-message-1",
            parserId: "gmail-verification-v1",
            provider: "gmail",
          },
        };
      },
    } satisfies SensitiveValueSource);
  const sink =
    options.sink ??
    ({
      submit: ({ plaintext }) => {
        submitted.push(new TextDecoder().decode(plaintext));
        return { reference: "submission-1", status: "submitted" } as const;
      },
    } satisfies SensitiveValueSink);
  const receiver = createAgentExchangeReceiver({
    consent:
      options.consent ??
      ({
        assertAllows: (request) => ({
          consentId: `paired:${request.requester.agentId}:${request.recipient.agentId}`,
          expiresAt: Date.now() + 24 * 60 * 60_000,
        }),
      } satisfies RecipientConsentVerifier),
    e2ee,
    replay,
    sink,
  });
  const sender = createAgentExchangeSender({
    agency,
    e2ee,
    keyDirectory: {
      resolve: () => ({ keyId: "recipient-key", publicKey: keyPair.publicKey }),
    },
    source,
    store: exchangeStore,
    transport: {
      deliver: async (delivery) => {
        deliveries.push(structuredClone(delivery));
        return receiver.receive(delivery);
      },
    },
  });

  return {
    agency,
    agencyStore,
    deliveries,
    e2ee,
    exchangeStore,
    receiver,
    replay,
    sender,
    sourceBuffers,
    submitted,
  };
};

export const approveAndLease = async (
  agency: Agency,
  exchange: { readonly actionId: string; readonly expiresAt: number },
) => {
  await agency.approve({
    actionId: exchange.actionId,
    approvedBy: "user-requester",
    approvedUntil: exchange.expiresAt,
    conditions: { recipientConsentRequired: true },
  });
  return agency.issueLease(exchange.actionId);
};
