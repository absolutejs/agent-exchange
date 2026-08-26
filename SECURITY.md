# Security policy

`@absolutejs/agent-exchange` is an early `0.x` orchestration package. It composes
Agency authorization, an E2EE envelope provider, recipient consent, deterministic
source/sink tools, and replay storage. It is not itself a cryptographic primitive.

The initial release is experimental and has not been independently audited. A
deployment is only as strong as its E2EE provider, durable Agency and replay stores,
identity verification, source/sink isolation, and application policy.

Report vulnerabilities privately to security@absolutejs.com. Never attach real
credentials, one-time codes, private keys, or user content.
