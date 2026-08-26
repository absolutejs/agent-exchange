# `@absolutejs/agent-exchange`

Verified, purpose-bound, model-blind sensitive-value exchange for humans and
agents. It composes existing AbsoluteJS primitives instead of creating another
permission or transport system:

```text
Auth identity and delegation
        ↓
Agency approval and single-use execution lease
        ↓
deterministic source tool → E2EE envelope → deterministic recipient sink
        ↓
A2A carries an opaque exchange reference and redacted receipt
```

The default processing mode is `tool-confined`. Protected bytes are supplied to
trusted tools, wiped on every completion path, and excluded from the request,
Agency ledger, A2A task history, errors, telemetry, and receipts.

> This is an experimental `0.x` release and has not been independently audited.
> Phishing resistance is available only when every declared assurance requirement
> is actually satisfied; email and SMS codes remain bearer credentials.

## Explicit assurance

Every request declares three independent assurances. The phishing-resistant shape
is intentionally unrepresentable with a bearer credential or general execution:

```ts
assurance: {
  approval: "webauthn-verifier-bound",
  credential: "sender-constrained",
  execution: "purpose-bound",
}
```

For this mode, `beginApproval()` derives a domain-separated SHA-256 challenge from
the complete immutable exchange. `approve()` accepts only a configured approval
provider's verified WebAuthn result for the requester's exact subject and authority
origin. The resulting Agency approval stores a hash of the credential identifier,
never the assertion or raw identifier. Both lease issuance and execution re-check
that evidence against the current request.

This follows WebAuthn's requirements to validate the challenge, origin, RP ID hash,
user-presence flag, and—when requested—the user-verification flag. The provider
must request user verification and perform the cryptographic assertion validation.

## Security invariants

- Every request binds requester, recipient, purpose, service origin, account
  reference, operation, assurance, expiry, nonce, processing mode, and
  `maximumUses: 1`.
- Agency authorizes the metadata-only action and consumes the execution lease
  before a source is read.
- Recipient consent is checked against the same request.
- The receiver authenticates the envelope, then atomically consumes the nonce
  before sink execution. Invalid ciphertext cannot burn a legitimate exchange.
- Source, envelope, transport, and sink failures become allowlisted error codes;
  dependency error messages never cross the boundary.
- Receipts and sink references are scanned for direct, UTF-8, hexadecimal, base64,
  and base64url representations of the protected value.
- High-risk recovery, administrative, security-setting, money movement, and export
  flows are denied unless the host explicitly opts them in.

## A2A boundary

`@absolutejs/agent-exchange/a2a` adds the Agent Exchange extension to an Agent
Card and creates request messages containing only an opaque exchange reference and
safe metadata. Envelopes are delivered through the configured exchange transport,
not persisted in ordinary A2A task history.

See [SECURITY.md](./SECURITY.md) before using real protected data.

## Interchangeable sources

Source integrations live in the public
[`absolutejs/agent-exchange-sources`](https://github.com/absolutejs/agent-exchange-sources)
monorepo so this core never depends on mailbox, SMS, vault, or device-provider
SDKs.

The first adapter is `@absolutejs/agent-exchange-email`. It binds deterministic
Gmail, Microsoft Graph, or IMAP retrieval from `@absolutejs/email` to the same
`SensitiveValueSource` API:

```bash
bun add @absolutejs/agent-exchange @absolutejs/agent-exchange-email @absolutejs/email
```

Verification-code retrieval remains absent from model-facing manifests. The
adapter hands mutable bytes directly to this package for encryption, and this
package wipes them after delivery.

## License

Apache-2.0
