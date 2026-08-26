import { expect, test } from "bun:test";
import {
  createMemoryAgentExchangeReplayStore,
  createMemoryAgentExchangeStore,
  type AgentExchangeRequest,
} from "../src";
import { requestInput } from "./fixture";

const storedRequest = (): AgentExchangeRequest => ({
  ...requestInput(),
  actionId: "act_1",
  createdAt: Date.now(),
  exchangeId: "xchg_1",
  maximumUses: 1,
  nonce: "nonce_1",
  processingMode: "tool-confined",
});

test("memory store atomically keeps the first request and clones reads", async () => {
  const store = createMemoryAgentExchangeStore();
  const request = storedRequest();
  expect(await store.save(request)).toBe(true);
  expect(await store.save(request)).toBe(false);
  const read = await store.get(request.exchangeId);
  expect(read).toEqual(request);
  expect(read).not.toBe(request);
});

test("memory replay store atomically consumes once and expires entries", async () => {
  const replay = createMemoryAgentExchangeReplayStore();
  expect(
    await replay.consume({
      exchangeId: "xchg_1",
      expiresAt: 2_000,
      nonce: "nonce_1",
      now: 1_000,
    }),
  ).toBe(true);
  expect(
    await replay.consume({
      exchangeId: "xchg_1",
      expiresAt: 2_000,
      nonce: "nonce_1",
      now: 1_001,
    }),
  ).toBe(false);
  expect(
    await replay.consume({
      exchangeId: "xchg_1",
      expiresAt: 4_000,
      nonce: "nonce_1",
      now: 2_000,
    }),
  ).toBe(true);
});
