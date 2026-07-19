# provenex-ingest (superseded evaluation forwarder)

This source mirror is retained for historical and audit purposes. It is not the
current customer evaluation path.

The binary forwards raw or field-hashed OTLP to a central `/v1/receipts`
endpoint. Even in hash mode, topology-bearing resource URIs can remain raw. It
also lacks the customer-local receipt workspace, Data Custody contract view,
and reverse-proxy enforcement proof required by ADR-008.

Do not point this binary at `https://provenex-verdict.fly.dev` or use it for
customer telemetry. Do not publish a new release from this mirror until its
protocol is deliberately redesigned for the local edge.

## Current path

Use `provenex-edge` and `provenex-egress-proxy` from the ADR-008 evaluation
bundle:

- telemetry enters the authenticated customer-local `/v1/traces` receiver;
- discovery, graph state, receipts, and signed PEP evidence stay local;
- the edge authenticates to the common scorer with the customer's
  `pvx_trial_*` key; and
- only the bounded, HMAC-minimized `/v1/score-closure` DTO goes centrally.

See the customer-facing
[onboarding guide](../provenex-public/docs/onboarding.md) and
[installation guide](../provenex-public/docs/install.md).

## Historical source contents

The crate remains Apache-2.0 source so prior artifacts can be audited. Its
`send`, `batch`, `watch`, and `listen` commands document the previous central
forwarding model; they are intentionally not reproduced here as current setup
instructions.

Security disclosures: security@provenex.ai.
