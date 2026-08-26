import type {
  AgentExchangeReceipt,
  AgentExchangeRequest,
  AgentExchangeStore,
} from "./types";

const clone = <Value>(value: Value): Value => structuredClone(value);

export type MemoryAgentExchangeStore = AgentExchangeStore & {
  readonly clear: () => void;
};

export const createMemoryAgentExchangeStore = (): MemoryAgentExchangeStore => {
  const requests = new Map<string, AgentExchangeRequest>();
  const actionIds = new Map<string, string>();
  const receipts = new Map<string, AgentExchangeReceipt>();

  return Object.freeze({
    clear: () => {
      requests.clear();
      actionIds.clear();
      receipts.clear();
    },
    get: async (exchangeId) => {
      const request = requests.get(exchangeId);
      return request === undefined ? undefined : clone(request);
    },
    getByActionId: async (actionId) => {
      const exchangeId = actionIds.get(actionId);
      const request =
        exchangeId === undefined ? undefined : requests.get(exchangeId);
      return request === undefined ? undefined : clone(request);
    },
    getReceipt: async (exchangeId) => {
      const receipt = receipts.get(exchangeId);
      return receipt === undefined ? undefined : clone(receipt);
    },
    save: async (request) => {
      if (requests.has(request.exchangeId) || actionIds.has(request.actionId)) {
        return false;
      }
      requests.set(request.exchangeId, clone(request));
      actionIds.set(request.actionId, request.exchangeId);
      return true;
    },
    saveReceipt: async (receipt) => {
      if (receipts.has(receipt.exchangeId)) return false;
      receipts.set(receipt.exchangeId, clone(receipt));
      return true;
    },
  });
};
