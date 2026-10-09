# multi-tour-security

> Transversal security microservice: identity, sign-in and JWT issuing (Annex J)

Part of the **Multi Tour** distributed system — team `multi-tour`, Grupo 2.
Governance and documentation live in [`multi-tour-docs`](https://github.com/code-corhuila/multi-tour-docs).

## What it is

The transversal security microservice (Annex J): accounts, sign-in, tokens and revocation. It is the only service that holds the private key; every other service validates the tokens it issues with the public key. Written in Go with the standard `net/http`, in a hexagon whose core imports only the standard library. It has no `-db` repository: its schema `security` and its migrations live here, in `db/`, inside the single PostgreSQL instance of `multi-tour-infra-postgres`.

Today it answers `GET /health` without a token, and answers `401` with the common error envelope on every other route that has no valid RS256 token. The stories (sign-in, tokens, revocation) add their routes one by one.

## How to start it

Needs Go 1.26 and the infrastructure of `multi-tour-infra-postgres` (the instance and the user `security_app`, created by its `postgres/init/01-instance.sh`; run that script again by hand if the instance already existed, Annex J, J.5.5).

1. Migrate the schema once per environment, with the runner of `deploy/compose.yml`, from the root composition: `docker compose --env-file env/dev.env run --rm security-db-migrate`. A second run changes nothing.
2. Copy `.env.example` to `.env`, which is never versioned, and fill it. `DATABASE_URL` connects as `security_app`, never as the administrator. The key pair is a PKCS#8 private key and a PKIX public key, RSA of at least 2048 bits. Until `scripts/dev-keys.sh` of the infrastructure repository exists, a development pair is made with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private.pem` and `openssl pkey -in keys/private.pem -pubout -out keys/public.pem`; `keys/` is ignored by git.
3. `go run ./cmd/security`. It refuses to start with a missing or weak key, a database URL without password or a bad `HTTP_PORT` (default 8086), and it stops in order on `SIGINT` or `SIGTERM`.

## Where the data is

Schema `security`, user `security_app` (it can write only there), in the instance of `multi-tour-infra-postgres`. The control tables are `databasechangelog_security` and `databasechangeloglock_security`. For now the schema holds the table `outbox_event`; the accounts arrive with their stories.

## How to test it

```sh
go test ./...                # unit, contract and import tests; no database needed
sh db/tests/db-ci.sh         # the schema from empty, rerun, rollback and rebuild; needs Docker
```

`go test` validates every answer against `openapi/openapi.yaml` and fails if an operation of the contract was never exercised. The `db-ci` starts its own throwaway PostgreSQL and Liquibase containers. Both run on every pull request to `develop` and `qa` (`ci.yml`).

## What is missing

The first Platform Administrator command (`bootstrap-platform-admin`, AC-00.4) and the seven stories of the domain: see `07-api/specs/multi-tour-security/` in `multi-tour-docs`.

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
