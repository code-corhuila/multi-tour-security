# multi-tour-security

> Transversal security microservice: identity, sign-in and JWT issuing (Annex J)

Part of the **Multi Tour** distributed system — team `multi-tour`, Grupo 2.
Governance and documentation live in [`multi-tour-docs`](https://github.com/code-corhuila/multi-tour-docs).

## What it is

The transversal security microservice (Annex J): accounts, sign-in, tokens and revocation. It is the only service that holds the private key; every other service validates the tokens it issues with the public key. Written in Go with the standard `net/http`, in a hexagon whose core imports only the standard library. It has no `-db` repository: its schema `security` and its migrations live here, in `db/`, inside the single PostgreSQL instance of `multi-tour-infra-postgres`.

It answers `GET /health` without a token; the sign-in, platform sign-in and renewal routes need none either; every other route answers `401` with the common error envelope unless it carries a valid RS256 token. The routes are in `openapi/openapi.yaml`.

A Tenant Administrator registers the internal users of their tenant with `POST /api/v1/security/users` (HU-SEC-005): the password they type and its confirmation are a temporary credential of 72 hours that only allows the user to choose their own at the first sign-in, and the user then holds the role they were given and no other. The tenant is always the one of the credential. A taken e-mail is refused saying whose it is.

The same Administrator manages those users (HU-SEC-005): `GET /api/v1/security/users` lists them, newest first, with the listing envelope and the filters `role` and `status`; `POST /api/v1/security/users/{accountId}/inactivation` and `.../reactivation` cut and give back their access with a reason, and an inactivation also cuts every session the user had and writes `AccountSessionsRevoked` with the actor and the reason. The last active Administrator of a tenant cannot be inactivated. `POST /api/v1/security/users/{accountId}/temporary-credential` gives a user whose first temporary credential expired a new one of 72 hours, typed by the issuer: a Tenant Administrator may issue it to anyone of their tenant except the first Administrator, and the Platform Administrator to the first Administrator and, when no Administrator of the tenant can sign in, to any active one. Who did each change, when and why is kept with the account and shown in the list; no answer carries a password or a hash. Which of these the other services honor (the refusal of a revoked session) is described in `07-api/specs/multi-tour-security/` of `multi-tour-docs`.

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

## Password recovery

A person who forgot the password asks for a code of 8 digits and chooses a new password with it (HU-SEC-004). The code is sent by e-mail with the same SMTP variables as the verification link, lasts 30 minutes, works once, and only the newest code of an account works. Five wrong tries retire the code; at most 3 codes per hour per account. The database keeps only an HMAC of the code, never the code.

| Variable | Meaning |
|---|---|
| `RECOVERY_CODE_KEY` | Secret of the HMAC of the codes, at least 32 bytes (`openssl rand -base64 32`), different in each environment; the service stops at start without it. Never versioned |

Public routes, with no token, for a tenant and, under `/platform/`, for the Platform Administrator:

1. `POST /api/v1/security/public/tenants/{identifier}/password-recoveries` asks for a code and always answers `202`, whether or not the e-mail has an account.
2. `POST .../password-recoveries/resets` takes `email`, `code`, `newPassword` and `newPasswordConfirmation`. It answers `204`: the password is replaced, the failed-sign-in block is lifted, every session of the account ends and a pending account becomes `ACTIVE`. Every refused code (wrong, used, expired, retired, no account, inactive, other tenant) is the same `422`; a bad shape is `400` with the field.

The facts `PasswordRecoveryRequested`, `PasswordReset`, `PasswordResetFailed` (administrative accounts only) and `AccountSessionsRevoked` go to the outbox in the same statement. What is not built: the e-mail notice to the administrators when an administrative password is reset (HU-WRK-004, job 4).

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
- `issue-service-token <name> [duration]` prints one line, the token of a worker or a saga: `sub` is the name, role `SERVICE`, no tenant. It needs only `JWT_PRIVATE_KEY_FILE`. The duration is a Go duration between 1 minute and 90 days (24 hours by default; ADR-004 D5 asks for 90 days in each environment). Keep the token as a secret of the environment; never version it.

## Still to come

The e-mail notice to the administrators of a password reset (HU-WRK-004): see `07-api/specs/multi-tour-security/` in `multi-tour-docs`.

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
