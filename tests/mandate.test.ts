import { describe, expect, test } from "bun:test";
import {
  AgentExchangeError,
  agentExchangeMandateApprovalChallenge,
  createAgentExchangeStandingMandateAuthority,
  createMemoryAgentExchangeMandateStore,
  type AgentExchangeMandateJwsSigner,
  type AgentExchangeMandateJwsVerifier,
  type AgentExchangeRequest,
  type AgentExchangeStandingMandateInput,
} from "../src";

const encode = (value: Uint8Array): string =>
  Buffer.from(value).toString("base64url");
const decode = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, "base64url"));

const signer: AgentExchangeMandateJwsSigner = {
  sign: ({ payload, type }) => `${type}.${encode(payload)}.test-signature`,
};

const verifier: AgentExchangeMandateJwsVerifier = {
  verify: ({ compactJws, type }) => {
    const [actualType, payload, signature, extra] = compactJws.split(".");
    if (
      actualType !== type ||
      payload === undefined ||
      signature !== "test-signature" ||
      extra !== undefined
    ) {
      throw new Error("invalid signature");
    }
    return { algorithm: "ES256", keyId: "key-1", payload: decode(payload) };
  },
};

const now = 1_800_000_000_000;
const issuer = { authority: "https://owner.example", subject: "owner-1" };
const requester = {
  agentId: "requester-agent",
  authority: "https://requester.example",
  delegationId: "oauth-delegation-1",
  subject: "requester-owner",
};
const audience = {
  agentId: "recipient-agent",
  authority: "https://recipient.example",
  subject: "recipient-owner",
};

const mandateInput = (
  overrides: Partial<AgentExchangeStandingMandateInput> = {},
): AgentExchangeStandingMandateInput => ({
  approval: {
    credentialIdHash: "sha256:credential",
    method: "webauthn-verifier-bound" as const,
    rpId: "owner.example",
    userVerified: true,
    verifiedAt: now,
    verifierOrigin: issuer.authority,
  },
  audience,
  expiresAt: now + 60_000,
  grants: [
    {
      accountRef: "mailbox-1",
      operation: "retrieve-code",
      origin: "https://accounts.example",
      provider: "gmail",
      purpose: "complete sign-in",
      risk: "authentication",
      secretKind: "email-one-time-code",
    },
  ],
  issuer,
  mandateId: "mandate-1",
  maximumUses: 2,
  notBefore: now,
  requester,
  ...overrides,
});

const request = (
  overrides: Partial<AgentExchangeRequest> = {},
): AgentExchangeRequest => ({
  actionId: "action-1",
  assurance: {
    approval: "standing-mandate",
    credential: "token-confined-broker",
    execution: "purpose-bound",
  },
  createdAt: now,
  exchangeId: "exchange-1",
  expiresAt: now + 30_000,
  maximumUses: 1,
  mandateId: "mandate-1",
  nonce: "nonce-1",
  processingMode: "tool-confined",
  purpose: "complete sign-in",
  recipient: audience,
  requester,
  resource: {
    accountRef: "mailbox-1",
    operation: "retrieve-code",
    origin: "https://accounts.example",
    provider: "gmail",
  },
  risk: "authentication",
  secretKind: "email-one-time-code",
  ...overrides,
});

const setup = () => {
  let clock = now;
  const store = createMemoryAgentExchangeMandateStore();
  const authority = createAgentExchangeStandingMandateAuthority({
    now: () => clock,
    signer,
    store,
    verifier,
  });
  return { authority, setClock: (value: number) => (clock = value) };
};

describe("standing mandates", () => {
  test("issues an unchanged draft after asynchronous user verification", async () => {
    const { authority, setClock } = setup();
    const original = mandateInput();
    const { approval: ignored, ...draft } = original;
    const before = await agentExchangeMandateApprovalChallenge(draft);
    setClock(now + 10000);
    const issued = await authority.issue({
      ...original,
      approval: { ...original.approval, verifiedAt: now + 9000 },
    });
    await expect(
      authority.issue({
        ...original,
        mandateId: "expired-draft",
        expiresAt: now + 1000,
      }),
    ).rejects.toThrow(AgentExchangeError);
    expect(issued.mandate.notBefore).toBe(draft.notBefore);
    expect(issued.mandate.issuedAt).toBe(now + 10000);
    const { approval, issuedAt, version, ...issuedDraft } = issued.mandate;
    expect(await agentExchangeMandateApprovalChallenge(issuedDraft)).toBe(
      before,
    );
    await expect(
      authority.authorize({
        expectedIssuer: issuer,
        request: request({ createdAt: now + 10000 }),
        signedMandate: issued.signedMandate,
      }),
    ).resolves.toMatchObject({ status: "authorized" });
    await expect(
      authority.issue({
        ...original,
        mandateId: "negative-not-before",
        notBefore: -1,
      }),
    ).rejects.toThrow(AgentExchangeError);
  });

  test("binds WebAuthn approval to the complete mandate draft", async () => {
    const { approval: _approval, ...draft } = mandateInput();
    const original = await agentExchangeMandateApprovalChallenge(draft);
    const changed = await agentExchangeMandateApprovalChallenge({
      ...draft,
      maximumUses: draft.maximumUses + 1,
    });
    expect(original).not.toBe(changed);
  });

  test("authorizes exact grants and consumes each exchange once", async () => {
    const { authority } = setup();
    const issued = await authority.issue(mandateInput());

    await expect(
      authority.authorize({
        expectedIssuer: issuer,
        request: request(),
        signedMandate: issued.signedMandate,
      }),
    ).resolves.toMatchObject({ mandateId: "mandate-1", status: "authorized" });

    await expect(
      authority.authorize({
        expectedIssuer: issuer,
        request: request(),
        signedMandate: issued.signedMandate,
      }),
    ).rejects.toMatchObject({ code: "replay_detected" });
  });

  test("rejects scope substitution and does not burn a valid use", async () => {
    const { authority } = setup();
    const issued = await authority.issue(mandateInput());

    await expect(
      authority.authorize({
        expectedIssuer: issuer,
        request: request({ purpose: "reset account" }),
        signedMandate: issued.signedMandate,
      }),
    ).rejects.toMatchObject({ code: "mandate_invalid" });

    await expect(
      authority.authorize({
        expectedIssuer: issuer,
        request: request(),
        signedMandate: issued.signedMandate,
      }),
    ).resolves.toMatchObject({ status: "authorized" });
  });

  test("enforces use exhaustion across different exchanges", async () => {
    const { authority } = setup();
    const issued = await authority.issue(mandateInput({ maximumUses: 1 }));
    await authority.authorize({
      expectedIssuer: issuer,
      request: request(),
      signedMandate: issued.signedMandate,
    });

    await expect(
      authority.authorize({
        expectedIssuer: issuer,
        request: request({
          actionId: "action-2",
          exchangeId: "exchange-2",
          nonce: "nonce-2",
        }),
        signedMandate: issued.signedMandate,
      }),
    ).rejects.toMatchObject({ code: "mandate_exhausted" });
  });

  test("revocation takes effect before another use", async () => {
    const { authority } = setup();
    const issued = await authority.issue(mandateInput());
    await expect(
      authority.revoke({ issuer, mandateId: "mandate-1" }),
    ).resolves.toBe(true);

    await expect(
      authority.authorize({
        expectedIssuer: issuer,
        request: request(),
        signedMandate: issued.signedMandate,
      }),
    ).rejects.toMatchObject({ code: "mandate_revoked" });
  });

  test("rejects expiry, wrong issuer, and invalid signatures", async () => {
    const { authority, setClock } = setup();
    const issued = await authority.issue(mandateInput());
    setClock(now + 60_000);
    await expect(
      authority.authorize({
        expectedIssuer: issuer,
        request: request({ createdAt: now + 1, expiresAt: now + 59_000 }),
        signedMandate: issued.signedMandate,
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });

    const second = setup();
    const secondIssued = await second.authority.issue(mandateInput());
    await expect(
      second.authority.authorize({
        expectedIssuer: { ...issuer, subject: "attacker" },
        request: request(),
        signedMandate: secondIssued.signedMandate,
      }),
    ).rejects.toBeInstanceOf(AgentExchangeError);
    await expect(
      second.authority.authorize({
        expectedIssuer: issuer,
        request: request(),
        signedMandate: {
          compactJws: `${secondIssued.signedMandate.compactJws}x`,
        },
      }),
    ).rejects.toMatchObject({ code: "mandate_invalid" });
  });

  test("rejects stale approval evidence and duplicate ids", async () => {
    const { authority } = setup();
    await expect(
      authority.issue(
        mandateInput({
          approval: { ...mandateInput().approval, verifiedAt: now - 300_001 },
        }),
      ),
    ).rejects.toMatchObject({ code: "mandate_invalid" });

    await authority.issue(mandateInput());
    await expect(authority.issue(mandateInput())).rejects.toMatchObject({
      code: "mandate_invalid",
    });
  });
});
