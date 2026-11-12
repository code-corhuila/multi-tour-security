# multi-tour-security

> Transversal security microservice: identity, sign-in and JWT issuing (Annex J)

Part of the **Multi Tour** distributed system — team `multi-tour`, Grupo 2.
Governance and documentation live in [`multi-tour-docs`](https://github.com/code-corhuila/multi-tour-docs).

## What it is

The transversal security microservice (Annex J): accounts, sign-in, tokens and revocation. It is the only service that holds the private key; every other service validates the tokens it issues with the public key. Written in Go with the standard `net/http`, in a hexagon whose core imports only the standard library. It has no `-db` repository: its schema `security` and its migrations live here, in `db/`, inside the single PostgreSQL instance of `multi-tour-infra-postgres`.

It answers `GET /health` without a token; the sign-in, platform sign-in and renewal routes need none either; every other route answers `401` with the common error envelope unless it carries a valid RS256 token. The routes are in `openapi/openapi.yaml`.

## How to start it

Needs Go 1.26 and the infrastructure of `multi-tour-infra-postgres` (the instance and the user `security_app`, created by its `postgres/init/01-instance.sh`; run that script again by hand if the instance already existed, Annex J, J.5.5).

1. Migrate the schema once per environment, with the runner of `deploy/compose.yml`, from the root composition: `docker compose --env-file env/dev.env run --rm security-db-migrate`. A second run changes nothing.
2. Copy `.env.example` to `.env`, which is never versioned, and fill it. `DATABASE_URL` connects as `security_app`, never as the administrator. The key pair is a PKCS#8 private key and a PKIX public key, RSA of at least 2048 bits. Until `scripts/dev-keys.sh` of the infrastructure repository exists, a development pair is made with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private.pem` and `openssl pkey -in keys/private.pem -pubout -out keys/public.pem`; `keys/` is ignored by git.
3. `go run ./cmd/security`. It refuses to start with a missing or weak key, a database URL without password or a bad `HTTP_PORT` (default 8086), and it stops in order on `SIGINT` or `SIGTERM`.

## E-mail of the verification links

A Final Customer registers as `PENDING` and receives a link that lasts 24 hours and works once; the account cannot sign in (`403 EMAIL_NOT_VERIFIED`) until the person confirms it with the link and the password of the account (HU-SEC-003). The service reads these variables and **refuses to start** when one is missing or cannot send safely:

| Variable | Meaning |
|---|---|
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM` | Mail server and sender |
| `SMTP_USER`, `SMTP_PASSWORD` | Both or none; PLAIN authentication only over TLS or to a local server |
| `SMTP_REQUIRE_TLS` | `true` by default. `false` is accepted only for a local host (`localhost`, a loopback address or a name without dots such as `mailpit`) |
| `PUBLIC_BASE_URL` | Origin of the portal in the link, `https` unless the mail server is local |

In development nothing is sent: the `mail-capture` profile of `deploy/compose.yml` starts [Mailpit](https://mailpit.axllent.org), which keeps every e-mail. Set `SMTP_HOST=mailpit`, `SMTP_PORT=1025`, `SMTP_REQUIRE_TLS=false`, `PUBLIC_BASE_URL=http://localhost:4200` and `COMPOSE_PROFILES=mail-capture` in `env/dev.env` of `multi-tour-infra-postgres`, then run `scripts/up.sh dev`. Mailpit publishes no port to the host; read the mailbox from inside the network, for example `docker exec multi-tour-dev-front-1 wget -qO- http://mailpit:8025/api/v1/messages`. The link carries the value after `#`, so it never reaches a server log: `{PUBLIC_BASE_URL}/t/{identifier}/verificar-correo#token=...`.

Try it through the gateway (`http://localhost:8080`):

1. `POST /api/v1/security/public/tenants/{identifier}/accounts` registers the customer (`201`, `PENDING`); the first link is in the mailbox.
2. `POST .../sessions` with the right password answers `403 EMAIL_NOT_VERIFIED`.
3. `POST .../email-verifications/confirmations` with the token and the password answers `204`; the account is `ACTIVE`, signs in, and `AccountEmailVerified` is in the outbox. A wrong password answers `401` and counts as a failed sign-in; reusing, expiring or replacing the link answers `422`.
4. `POST .../email-verifications` asks for another link and always answers `202`, whether or not the e-mail exists. At most 3 links per hour per account (the first one counts); a new link retires the earlier ones.

A failed send never fails the registration: it is recorded in `email_verification.send_failed_at` and `send_error` (never with the link) and the person asks again.

## Where the data is

Schema `security`, user `security_app` (it can write only there), in the instance of `multi-tour-infra-postgres`. The control tables are `databasechangelog_security` and `databasechangeloglock_security`. The schema holds the accounts, memberships, sessions, renewal values, the copy of the tenants and the outbox.

## How to test it

```sh
go test ./...                # unit, contract and import tests; the persistence tests need TEST_DATABASE_URL and are skipped without it
sh db/tests/db-ci.sh         # the schema from empty, rerun, rollback and rebuild; needs Docker
```

`go test` validates every answer against `openapi/openapi.yaml` and fails if an operation of the contract was never exercised. The `db-ci` starts its own throwaway PostgreSQL and Liquibase containers. Both run on every pull request to `develop` and `qa` (`ci.yml`).

## Commands

Run beside the server, with the same binary and the variables exported in the shell (the binary does not read `.env` itself): `security <command>`.

- `bootstrap-platform-admin` makes the first Platform Administrator, once. It reads `PLATFORM_ADMIN_EMAIL` and `DATABASE_URL`, takes the temporary password from the first line of the console (never from an argument or a variable) and does nothing if the platform already has an Administrator.
- `issue-service-token <name> [duration]` prints one line, the token of a worker or a saga: `sub` is the name, role `SERVICE`, no tenant. It needs only `JWT_PRIVATE_KEY_FILE`. The duration is a Go duration between 1 minute and 30 days (24 hours by default). Keep the token as a secret of the environment; never version it.

## Still to come

The stories that recover the password and grant permissions: see `07-api/specs/multi-tour-security/` in `multi-tour-docs`.

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
