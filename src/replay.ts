import type { AgentExchangeReplayStore } from "./types";

export type MemoryAgentExchangeReplayStore = AgentExchangeReplayStore & {
  readonly clear: () => void;
};

export const createMemoryAgentExchangeReplayStore =
  (): MemoryAgentExchangeReplayStore => {
    const consumed = new Map<string, number>();

    return Object.freeze({
      clear: () => consumed.clear(),
      consume: async ({ exchangeId, expiresAt, nonce, now }) => {
        for (const [storedKey, storedExpiry] of consumed) {
          if (storedExpiry <= now) consumed.delete(storedKey);
        }
        const key = `${exchangeId}:${nonce}`;
        if (consumed.has(key)) return false;
        consumed.set(key, expiresAt);
        return true;
      },
    });
  };
