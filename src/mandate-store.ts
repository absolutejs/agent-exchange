import type {
  AgentExchangeMandateRegistration,
  AgentExchangeMandateStore,
} from "./types";

type MemoryMandateRecord = AgentExchangeMandateRegistration & {
  readonly exchangeIds: Set<string>;
  revokedAt?: number;
};

export type MemoryAgentExchangeMandateStore = AgentExchangeMandateStore & {
  readonly clear: () => void;
};

export const createMemoryAgentExchangeMandateStore =
  (): MemoryAgentExchangeMandateStore => {
    const records = new Map<string, MemoryMandateRecord>();

    return Object.freeze({
      clear: () => records.clear(),
      consume: async ({ exchangeId, mandateId, now }) => {
        const record = records.get(mandateId);
        if (record === undefined || record.expiresAt <= now) return "unknown";
        if (record.revokedAt !== undefined) return "revoked";
        if (record.exchangeIds.has(exchangeId)) return "replay";
        if (record.exchangeIds.size >= record.maximumUses) return "exhausted";
        record.exchangeIds.add(exchangeId);
        return "consumed";
      },
      register: async (registration) => {
        if (records.has(registration.mandateId)) return false;
        records.set(registration.mandateId, {
          ...structuredClone(registration),
          exchangeIds: new Set(),
        });
        return true;
      },
      revoke: async ({ issuer, mandateId, now }) => {
        const record = records.get(mandateId);
        if (
          record === undefined ||
          record.issuer.authority !== issuer.authority ||
          record.issuer.subject !== issuer.subject
        ) {
          return false;
        }
        record.revokedAt ??= now;
        return true;
      },
    });
  };
