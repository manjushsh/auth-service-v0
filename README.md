# auth-service

A Go HTTP service implementing authentication strategies. Currently supports Basic Auth with a PostgreSQL store. You can use APIs or Inbuilt login with `redirect_uri` if you have created a app in auth service for callback.
You need to extract one time code and get JWT with API call in your service.

### TODO
1. Role (Authorization) 
2. Can't think any other feature as of now.. will add later


## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/api/basic/register` | Register a new user |
| POST | `/api/basic/login` | Login |
more.. check router.

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
## Note
Add client entry which is allowed to use auth service
```bash
INSERT INTO clients (name, redirect_uri) VALUES ('my-app', 'https://app.example.com/callback');
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
