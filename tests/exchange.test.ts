import { describe, expect, test } from "bun:test";
import {
  AgentExchangeError,
  createAgentExchangeSender,
  createMemoryAgentExchangeStore,
  type SensitiveValueSink,
} from "../src";
import {
  CODE,
  approveAndLease,
  exchangeFixture,
  requestInput,
} from "./fixture";

describe("model-blind agent exchange", () => {
  test("requires approval, executes once, and emits only a safe receipt", async () => {
    const fixture = await exchangeFixture();
    const requested = await fixture.sender.request(requestInput());
    expect(requested.decision.kind).toBe("deny");
    await expect(
      fixture.sender.issueLease(requested.exchange.exchangeId),
    ).rejects.toThrow("Action denied");

    const lease = await approveAndLease(fixture.agency, requested.exchange);
    const completed = await fixture.sender.execute({
      exchangeId: requested.exchange.exchangeId,
      leaseId: lease.leaseId,
    });

    expect(fixture.submitted).toEqual([CODE]);
    expect(completed.receipt).toMatchObject({
      exchangeId: requested.exchange.exchangeId,
      maximumUses: 1,
      modelObservedSecret: false,
      processingMode: "tool-confined",
      status: "submitted",
    });
    expect(JSON.stringify(completed)).not.toContain(CODE);
    expect(JSON.stringify(await fixture.agency.inspect())).not.toContain(CODE);
    expect(fixture.sourceBuffers[0]).toEqual(new Uint8Array(6));

    await expect(
      fixture.sender.execute({
        exchangeId: requested.exchange.exchangeId,
        leaseId: lease.leaseId,
      }),
    ).rejects.toThrow("already been consumed");
    expect(fixture.submitted).toHaveLength(1);
  });

  test("rejects a replay before invoking the sink again", async () => {
    const fixture = await exchangeFixture();
    const requested = await fixture.sender.request(requestInput());
    const lease = await approveAndLease(fixture.agency, requested.exchange);
    await fixture.sender.execute({
      exchangeId: requested.exchange.exchangeId,
      leaseId: lease.leaseId,
    });

    await expect(
      fixture.receiver.receive(fixture.deliveries[0]!),
    ).rejects.toMatchObject({ code: "replay_detected" });
    expect(fixture.submitted).toEqual([CODE]);
  });

  test("binds the encrypted envelope to every request field", async () => {
    const fixture = await exchangeFixture();
    const requested = await fixture.sender.request(requestInput());
    const lease = await approveAndLease(fixture.agency, requested.exchange);
    await fixture.sender.execute({
      exchangeId: requested.exchange.exchangeId,
      leaseId: lease.leaseId,
    });
    const delivery = fixture.deliveries[0]!;

    await expect(
      fixture.receiver.receive({
        ...delivery,
        request: {
          ...delivery.request,
          resource: {
            ...delivery.request.resource,
            origin: "https://attacker.example",
          },
        },
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  test("reuses an idempotent request without creating another exchange", async () => {
    const fixture = await exchangeFixture();
    const input = requestInput({ idempotencyKey: "verification-1" });
    const first = await fixture.sender.request(input);
    const second = await fixture.sender.request(input);

    expect(second.exchange).toEqual(first.exchange);
    expect((await fixture.agency.inspect()).actions).toHaveLength(1);
  });
});

describe("phishing-resistant approval", () => {
  test("binds a user-verified WebAuthn assertion to the complete request", async () => {
    let expectedChallenge = "";
    const fixture = await exchangeFixture({
      approvalProvider: {
        begin: (input) => {
          expectedChallenge = input.challenge;
          return {
            challenge: input.challenge,
            options: {
              challenge: input.challenge,
              userVerification: "required",
            },
          };
        },
        verify: (input) => {
          expect(input.challenge).toBe(expectedChallenge);
          expect(input.response).toEqual({ id: "credential-1" });
          return {
            credentialId: "credential-1",
            rpId: "requester.example",
            subject: input.subject,
            userVerified: true,
            verifierOrigin: input.verifierOrigin,
          };
        },
      },
    });
    const requested = await fixture.sender.request(
      requestInput({
        assurance: {
          approval: "webauthn-verifier-bound",
          credential: "sender-constrained",
          execution: "purpose-bound",
        },
      }),
    );

    await expect(
      fixture.sender.issueLease(requested.exchange.exchangeId),
    ).rejects.toMatchObject({ code: "invalid_request" });
    const options = await fixture.sender.beginApproval(
      requested.exchange.exchangeId,
    );
    expect(options.challenge).toHaveLength(64);
    const evidence = await fixture.sender.approve({
      exchangeId: requested.exchange.exchangeId,
      response: { id: "credential-1" },
    });
    expect(evidence).toMatchObject({
      requestDigest: options.challenge,
      userVerified: true,
      verifierOrigin: "https://auth.requester.example",
    });
    const lease = await fixture.sender.issueLease(
      requested.exchange.exchangeId,
    );
    const completed = await fixture.sender.execute({
      exchangeId: requested.exchange.exchangeId,
      leaseId: lease.leaseId,
    });
    expect(completed.receipt.assurance.approval).toBe(
      "webauthn-verifier-bound",
    );
  });

  test("rejects an assertion for another origin or subject", async () => {
    const fixture = await exchangeFixture({
      approvalProvider: {
        begin: ({ challenge }) => ({ challenge, options: {} }),
        verify: () => ({
          credentialId: "credential-1",
          rpId: "attacker.example",
          subject: "attacker",
          userVerified: true,
          verifierOrigin: "https://attacker.example",
        }),
      },
    });
    const requested = await fixture.sender.request(
      requestInput({
        assurance: {
          approval: "webauthn-verifier-bound",
          credential: "origin-bound",
          execution: "purpose-bound",
        },
      }),
    );
    await expect(
      fixture.sender.approve({
        exchangeId: requested.exchange.exchangeId,
        response: {},
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });
});

describe("safe failure boundaries", () => {
  test("redacts a source error containing the protected value", async () => {
    const fixture = await exchangeFixture({
      source: {
        read: () => {
          throw new Error(`Mailbox failure while reading ${CODE}`);
        },
      },
    });
    const requested = await fixture.sender.request(requestInput());
    const lease = await approveAndLease(fixture.agency, requested.exchange);

    await expect(
      fixture.sender.execute({
        exchangeId: requested.exchange.exchangeId,
        leaseId: lease.leaseId,
      }),
    ).rejects.toMatchObject({ code: "source_failed" });
    const ledger = JSON.stringify(await fixture.agency.inspect());
    expect(ledger).not.toContain(CODE);
    expect(ledger).toContain("Sensitive value retrieval failed");
  });

  test("redacts a sink error containing the protected value", async () => {
    const sink: SensitiveValueSink = {
      submit: ({ plaintext }) => {
        throw new Error(
          `Upstream rejected ${new TextDecoder().decode(plaintext)}`,
        );
      },
    };
    const fixture = await exchangeFixture({ sink });
    const requested = await fixture.sender.request(requestInput());
    const lease = await approveAndLease(fixture.agency, requested.exchange);

    await expect(
      fixture.sender.execute({
        exchangeId: requested.exchange.exchangeId,
        leaseId: lease.leaseId,
      }),
    ).rejects.toMatchObject({ code: "sink_failed" });
    expect(JSON.stringify(await fixture.agency.inspect())).not.toContain(CODE);
    expect(fixture.sourceBuffers[0]).toEqual(new Uint8Array(6));
  });

  test("blocks a sink reference that contains the protected value", async () => {
    const fixture = await exchangeFixture({
      sink: {
        submit: () => ({ reference: `result-${CODE}`, status: "submitted" }),
      },
    });
    const requested = await fixture.sender.request(requestInput());
    const lease = await approveAndLease(fixture.agency, requested.exchange);

    await expect(
      fixture.sender.execute({
        exchangeId: requested.exchange.exchangeId,
        leaseId: lease.leaseId,
      }),
    ).rejects.toMatchObject({ code: "secret_leak_detected" });
    expect(JSON.stringify(await fixture.agency.inspect())).not.toContain(CODE);
  });

  test("denies dangerous risk classes before Agency or source access", async () => {
    let reads = 0;
    const agencyFixture = await exchangeFixture();
    const sender = createAgentExchangeSender({
      agency: agencyFixture.agency,
      e2ee: agencyFixture.e2ee,
      keyDirectory: {
        resolve: () => ({ keyId: "unused", publicKey: new Uint8Array([1]) }),
      },
      source: {
        read: () => {
          reads += 1;
          return { bytes: new TextEncoder().encode(CODE) };
        },
      },
      store: createMemoryAgentExchangeStore(),
      transport: {
        deliver: async () => {
          throw new Error("unused");
        },
      },
    });

    await expect(
      sender.request(requestInput({ risk: "account-recovery" })),
    ).rejects.toBeInstanceOf(AgentExchangeError);
    expect(reads).toBe(0);
    expect((await agencyFixture.agency.inspect()).actions).toHaveLength(0);
  });
});
