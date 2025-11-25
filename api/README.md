# Todo API

A protected API providing basic Todo CRUD. Access is granted only with a PingOne Advanced Identity Cloud token.

### Stack

| Role | Name | Description |
| :--- | :--- | :--- |
| **Platform** | [Cloudflare Workers](https://workers.cloudflare.com) | Serverless execution |
| **Framework** | [Hono](https://hono.dev) | Lightweight API endpoints |
| **Data Storage** | [Cloudflare Workers KV](https://developers.cloudflare.com/kv) | User-scoped Todo list data |

### Requirements

* Node.js (v20+)
* PingOne Advanced Identity Cloud tenant
* Cloudflare account & [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update)

### Structure

```text
api/
├── src/
│   ├── index.ts           # Worker entry point, defines the routes
│   ├── config.ts          # Worker bindings, request-scoped variables, and scopes
│   ├── todoService.ts     # Todo CRUD with Cloudflare KV
│   └── auth.ts            # PingOne AIC token verification
├── package.json           # Dependencies and scripts
├── tsconfig.json          # TypeScript compiler settings
└── wrangler.jsonc         # Worker configuration
```

## 🚀 Deploy to Cloudflare

1. Install dependencies and build
    ```zsh
    npm install
    npm run build
    ```

2. Set remote environment variables using wrangler

    | Name | Description | Example |
    | :--- | :--- | :--- |
    | API_ISSUER | PingOne AIC tenant domain | `https://<ENV>.forgeblocks.com:443/am/oauth2/alpha` |
    | API_AUDIENCE | `aud` claim this API expects in JWTs | `https://todo-api-ping-aic.<ENV>.workers.dev` |

    ```bash
    wrangler secret put PING_AIC_ISSUER
    wrangler secret put PING_AIC_AUDIENCE
    ```

3. Configure remote KV storage using wrangler

    ```bash
    wrangler kv namespace create TODO_KV_PING_AIC
    ```

    > Note: After running this command, you must update `wrangler.jsonc` with the generated KV namespace ID

4. Deploy

    ```bash
    npm run deploy
    ```
