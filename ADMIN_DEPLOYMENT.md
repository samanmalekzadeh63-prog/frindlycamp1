# Friendly Camp Management Console

The management console is available at `/admin` and also activates automatically on any hostname beginning with `admin.`.

## Recommended two-domain deployment

Deploy the same production bundle on the dashboard domain, for example `https://admin.example.com`, and reverse-proxy `/api` to the main Friendly Camp Express server. This keeps authentication cookies first-party on the management domain and avoids exposing an API secret in the browser.

Example Nginx location on the dashboard host:

```nginx
location /api/ {
  proxy_pass https://friendlycamp.ir/api/;
  proxy_set_header Host friendlycamp.ir;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Set `ADMIN_ORIGINS=https://admin.example.com`. Keep `VITE_ADMIN_API_URL` empty for this reverse-proxy configuration. If both hosts are subdomains of one site and direct API calls are desired, set `VITE_ADMIN_API_URL=https://friendlycamp.ir` before building.

## First administrator

Copy `.env.example` to `.env`, set a unique `SESSION_SECRET` and the `ADMIN_BOOTSTRAP_*` values, then start the server once. The account is created or promoted to `admin`. Remove `ADMIN_BOOTSTRAP_PASSWORD` from the runtime environment after the first successful start. No default administrator password is included in the repository.

## Security controls already enforced

- Admin APIs require an authenticated account with the `admin` role.
- Cross-origin access is allowlisted through `ADMIN_ORIGINS`.
- All create/update operations are persisted to `data/admin.json` and recorded in its audit stream.
- Sessions use signed HttpOnly cookies; production requires a 32+ character secret.
- Global, authentication and AI rate limits remain active.

For high-volume production, migrate `data/admin.json`, `data/users.json`, and `data/profiles.json` to PostgreSQL before enabling real payments or concurrent back-office teams.
