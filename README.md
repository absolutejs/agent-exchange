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

> This is an experimental `0.x` release. It is not an audited production OTP
> service, identity provider, or replacement for phishing-resistant authorization.
> Prefer OAuth delegation, passkeys, and provider-native authorization over
> relaying bearer codes whenever possible.

## Security invariants

- Every request binds requester, recipient, purpose, service origin, account
  reference, operation, expiry, nonce, processing mode, and `maximumUses: 1`.
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

## License

Apache-2.0
