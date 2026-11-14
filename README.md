# npm-mirror

A single-process npm registry that caches the public npm registry (so installs keep working
when npm is unreachable) and hosts our private packages. No dependencies, no build step; Node 20.6+.

## Local development

```sh
npm run dev                     # = node --env-file=dev.env src/main.js serve
```

`dev.env` sets `BASE_URL=http://localhost:4873`, `PORT=4873` and `PRIVATE_SCOPES=@fotros-internal`.
To publish or read private packages locally, create a token (stored as a hash in `config.json`):

```sh
node src/main.js token create --user me --access write
echo "//localhost:4873/:_authToken=<printed token>" >> ~/.npmrc
npm install --registry http://localhost:4873 <pkg>
```

## Configuration

Environment variables override `config.json`. `config.json` is optional and never created
automatically; `config.example.json` lists the tunables it can hold.

| Variable | Required | Default | |
|---|---|---|---|
| `BASE_URL` | **yes** | — | Public URL; written into every tarball URL. Startup fails without it. |
| `PRIVATE_SCOPES` | **yes** | — | Comma-separated, e.g. `@fotros-internal`. Startup fails without it. |
| `PORT` | no | `4873` | |
| `LISTEN_HOST` | no | `127.0.0.1` | |
| `UPSTREAM_URL` | no | `https://registry.npmjs.org` | |
| `TOKENS` | no | none | `user:access:sha256,...` — see below. **Secret.** |

`BASE_URL` and `PRIVATE_SCOPES` may also come from `config.json` (`baseUrl`, `privateScopes`);
timeouts, TTLs, breaker settings and `bodyLimitBytes` only from `config.json`.

### Tokens

Authentication fails closed: with no tokens configured, publishing and reading private-scope
packages are denied (401) for everyone. Public packages are always readable; publishing a
public name is always 403. Unpublish is not supported.

`TOKENS` holds SHA-256 hashes, never the tokens themselves. To make one:

```sh
node src/main.js token env --user ci --access write
```

It prints the token (hand it to the user; it is not stored) and a `ci:write:<sha256>` entry
for `TOKENS`. Tokens in `config.json` (`token create/list/revoke`) are also honoured and are
reloaded without a restart; changes to `TOKENS` need a redeploy.

## Data

Everything is under `./data/`: `data/private/` is the source of truth for our packages and must
be backed up; `data/cache/` is disposable. Both, and `config.json`, are excluded from deploys.

## Deploy

Every push to `release` deploys via `.gitlab-ci.yml`. The job requires a GitLab **File** variable
`ENV_FILE` (sourced by `sh`) and starts pm2 with only `PATH`, `HOME`, `PORT` and `ENV_FILE`'s
variables in its environment.
