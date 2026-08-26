# Security policy

`@absolutejs/agent-exchange` is an early `0.x` orchestration package. It composes
Agency authorization, an E2EE envelope provider, recipient consent, deterministic
source/sink tools, and replay storage. It is not itself a cryptographic primitive.

The initial release is experimental and has not been independently audited. A
deployment is only as strong as its E2EE provider, durable Agency and replay stores,
identity verification, source/sink isolation, and application policy.

The `webauthn-verifier-bound` approval mode requires a cryptographically verifying
approval provider. Structural evidence alone is not proof. The package binds the
provider result to the complete request, exact requester authority origin and
subject, an RP ID valid for that origin, user verification, and the exchange
lifetime. Deployments must still use an audited WebAuthn implementation and secure
credential store.

The `standing-mandate` mode is not an unattended substitute for WebAuthn. A fresh,
user-verified WebAuthn ceremony authorizes the bounded mandate once; every later
execution must verify its JWS with a trusted issuer key and atomically check and
consume durable revocation state. Keep signing keys in a managed KMS/HSM, rotate
them with overlapping verification windows, authenticate agent-to-agent requests
at the transport boundary, and never place the compact JWS or broker credentials
in model-visible context. The included memory mandate store is not suitable for
multiple processes or production.

Standing mandates intentionally support only exact grants. Do not add wildcard
origins, redirectable destinations, free-form operations, unbounded lifetimes, or
unlimited uses. A signed mandate proves owner authorization; it does not by itself
authenticate the requesting agent's network connection.

Do not describe an exchange as phishing-resistant when its credential assurance is
`bearer`. NIST explicitly excludes manually entered OTP and out-of-band outputs
because they can be relayed to a legitimate verifier.

Report vulnerabilities privately to security@absolutejs.com. Never attach real
credentials, one-time codes, private keys, or user content.
