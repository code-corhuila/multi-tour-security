# multi-tour-security

> Transversal security microservice: identity, sign-in and JWT issuing (Annex J)

Part of the **Multi Tour** distributed system — team `multi-tour`, Grupo 2.
Governance and documentation live in [`multi-tour-docs`](https://github.com/code-corhuila/multi-tour-docs).

## What it is

The transversal security microservice (Annex J): accounts, sign-in, tokens and revocation. Written in Go; its data lives in the schema `security` of the single PostgreSQL instance.

## How to start it

To be written with the skeleton, once the service starts (task T-07).

## Where the data is

Schema `security`, user `security_app`, in the instance of `multi-tour-infra-postgres`.

## How to test it

`go test ./...`; the integration tests need `TEST_DATABASE_URL`.

## What is missing

The skeleton and the seven stories of the domain: see `07-api/specs/multi-tour-security/` in `multi-tour-docs`.

## Branching

Three permanent branches. **None of them accepts a direct commit** — you enter through a child
branch and leave through a Pull Request.

```
develop  <--PR--  feat/... fix/... chore/...
qa       <--PR--  qa/...
main     <--PR--  release/...  hotfix/...
```

Promotion happens **by re-application** (`git cherry-pick -x`), never by merging one permanent
branch into another: `merge develop -> qa` and `merge qa -> main` do not exist in this model.

`main` requires **1 approval from `ariel5253`**. On `develop` and `qa` the team sets its own review
rule.

Full policy: `00-governance/branching-policy.md` in `multi-tour-docs`.
