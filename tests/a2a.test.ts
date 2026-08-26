import { describe, expect, test } from "bun:test";
import {
  AGENT_EXCHANGE_REQUEST_MEDIA_TYPE,
  ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
  parseA2aAgentExchangeReference,
  toA2aAgentExchangeMessage,
  withAgentExchangeExtension,
} from "../src/a2a";
import { exchangeFixture, requestInput } from "./fixture";

describe("A2A Agent Exchange extension", () => {
  test("puts only an opaque safe reference in task history", async () => {
    const fixture = await exchangeFixture();
    const requested = await fixture.sender.request(requestInput());
    const message = toA2aAgentExchangeMessage(requested.exchange);
    const serialized = JSON.stringify(message);

    expect(message.extensions).toEqual([ABSOLUTE_AGENT_EXCHANGE_EXTENSION]);
    expect(message.parts[0]).toMatchObject({
      mediaType: AGENT_EXCHANGE_REQUEST_MEDIA_TYPE,
    });
    expect(serialized).not.toContain("account_01K4Y1");
    expect(serialized).not.toContain("challenge_01K4Y2");
    expect(serialized).not.toContain("envelope");
    expect(parseA2aAgentExchangeReference(message)).toMatchObject({
      exchangeId: requested.exchange.exchangeId,
      processingMode: "tool-confined",
    });
  });

  test("rejects extra payload fields such as a secret", async () => {
    const fixture = await exchangeFixture();
    const requested = await fixture.sender.request(requestInput());
    const message = toA2aAgentExchangeMessage(requested.exchange);
    const part = message.parts[0]!;
    if (
      !("data" in part) ||
      typeof part.data !== "object" ||
      part.data === null
    ) {
      throw new Error("test fixture did not produce a data part");
    }
    const data = part.data as Record<string, unknown>;

    expect(() =>
      parseA2aAgentExchangeReference({
        ...message,
        parts: [{ ...part, data: { ...data, secret: "forbidden" } }],
      }),
    ).toThrow();
  });

  test("advertises the extension exactly once", () => {
    const card = withAgentExchangeExtension({
      capabilities: { extensions: [] },
      defaultInputModes: ["application/json"],
      defaultOutputModes: ["application/json"],
      description: "Recipient agent",
      name: "recipient",
      skills: [],
      supportedInterfaces: [
        {
          protocolBinding: "JSONRPC",
          protocolVersion: "1.0",
          url: "https://agent.example/a2a",
        },
      ],
      version: "0.1.0",
    });
    const twice = withAgentExchangeExtension(card);

    expect(
      twice.capabilities.extensions?.filter(
        (extension) => extension.uri === ABSOLUTE_AGENT_EXCHANGE_EXTENSION,
      ),
    ).toHaveLength(1);
  });
});
