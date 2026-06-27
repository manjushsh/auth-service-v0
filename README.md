# auth-service

A Go HTTP service implementing authentication strategies. Currently supports Basic Auth with a PostgreSQL store. JWT support coming.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/api/basic/register` | Register a new user |
| POST | `/api/basic/login` | Login |

## Local dev

```bash
cp .env.example .env
docker compose up --build -d
docker compose logs -f app
```

Air watches for `.go` file changes and rebuilds automatically inside the container.

## Prod

Change `target` in `docker-compose.yml` from `dev` to `prod`, then:

```bash
docker compose up --build -d
```

## Cleanup

```bash
# stop containers
docker compose down

# stop containers and delete volumes (wipes DB)
docker compose down -v
```

## Migrations

Migrations run automatically on server start. Files live in `db/migrations/` and follow the `golang-migrate` naming convention:

```
001_create_users.up.sql
001_create_users.down.sql
```
