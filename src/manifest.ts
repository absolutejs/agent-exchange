import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  maxSecretBytes?: number;
  maxTtlMs?: number;
}>()({
  contract: 2,
  discovery: {
    audiences: ["agent-hosts", "app-developers", "security-teams"],
    intents: [
      "authorize a sensitive agent exchange",
      "bind an agent approval to a WebAuthn assertion",
      "deliver a value without exposing it to an agent model",
      "submit a purpose-bound email verification code",
    ],
    keywords: [
      "agent exchange",
      "E2EE",
      "model blind",
      "OTP",
      "replay protection",
      "single-use lease",
      "WebAuthn",
    ],
    protocols: ["A2A", "HPKE", "MLS", "WebAuthn Level 3"],
  },
  identity: {
    accent: "#7c3aed",
    category: "security",
    description:
      "Verified, purpose-bound sensitive-value exchange for humans and agents using explicit assurance, WebAuthn-bound Agency authorization, E2EE envelopes, recipient consent, replay protection, and model-blind trusted tools.",
    docsUrl: "https://github.com/absolutejs/agent-exchange",
    name: "@absolutejs/agent-exchange",
    tagline: "Let agents request protected actions without seeing the secret.",
  },
  settings: Type.Object(
    {
      maxSecretBytes: Type.Optional(
        Type.Integer({
          default: 256,
          description:
            "Maximum protected bytes accepted from a source or envelope.",
          minimum: 1,
          title: "Maximum secret bytes",
        }),
      ),
      maxTtlMs: Type.Optional(
        Type.Integer({
          default: 300000,
          description: "Maximum lifetime of an exchange request.",
          minimum: 1,
          title: "Maximum exchange lifetime",
        }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
