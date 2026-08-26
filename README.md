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

When an upstream provider issues bearer access tokens but Absolute PaaS confines
them to a deterministic broker, the request uses a separate, deliberately weaker
shape:

```ts
assurance: {
  approval: "webauthn-verifier-bound",
  credential: "token-confined-broker",
  execution: "purpose-bound",
}
```

This means the token is inaccessible to both agents and restricted to one approved
tool operation, but the upstream resource itself does not cryptographically bind
the access token to the broker. It must never be described as equivalent to a
sender-constrained DPoP or mTLS token.

### Standing mandates

Long-running agent-to-agent automation uses a separate assurance value:

```ts
assurance: {
  approval: "standing-mandate",
  credential: "token-confined-broker",
  execution: "purpose-bound",
}
```

`createAgentExchangeStandingMandateAuthority()` issues and verifies a compact JWS
whose canonical payload binds the owner, requesting agent, executing agent, exact
OAuth agent delegation, account, provider, origin, operation, purpose, risk class, secret kind, activation
window, expiry, and total use limit. Issuance requires fresh, user-verified WebAuthn
evidence. Authorization additionally requires the request's `delegationId` to be
present as its independently authenticated agent delegation, requires the
request's separate `mandateId` to equal the signed mandate ID, and atomically
consumes the exchange ID in a revocation
store. The JWS is not placed in A2A task history.

The core accepts interchangeable JWS signer, verifier, and durable store
implementations. Production verifiers must authenticate the trusted issuer and
key ID, enforce the explicit JWS type and allowed algorithm, and reject unknown or
revoked registrations. The memory store is for tests and local development only.

This design uses the signed-payload format from
[RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), canonical JSON rules from
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), the narrow actions and
locations model from [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396), and the
separate subject/actor semantics described by
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693). It does not make the wire
contract depend on an unfinished transaction-token or chain-delegation draft.

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
- Standing mandates are exact-match allowlists, never wildcard scopes. Revocation,
  replay prevention, expiry, and total use limits are enforced by one atomic store.

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

## Release compatibility

The `0.5.x` line uses the version-bound `@absolutejs/e2ee@0.5.x`
certification contract and the separately certified provider runtimes. Provider
admission remains the host's responsibility; a compatible type does not replace
release-specific security evidence.
