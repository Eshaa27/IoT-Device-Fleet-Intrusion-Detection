# Database Setup

Copy `.env.example` to `.env` and set `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` before starting the PostgreSQL service:

```powershell
docker compose --env-file .env -f infrastructure\docker-compose.yml up -d postgres
```

Apply the project schema by piping it to `psql`:

```powershell
Get-Content database\schema.sql | docker compose --env-file .env -f infrastructure\docker-compose.yml exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

`schema.sql` defines the project tables; `cowrie_schema.sql` is for Cowrie's database output integration and is separate. Use `queries.sql` for example analysis queries. The logger loads database settings from the root `.env` file. Credentials are for local development only; use unique values and do not expose PostgreSQL publicly.