# @mks2508/auth-oidc-elysia

Pocket ID OIDC plugin for Elysia. PKCE Authorization Code flow, JWKS validation, session JWT (HS256), `requireAuth()` guard.

## Install

```bash
bun add @mks2508/auth-oidc-elysia elysia @elysiajs/jwt
```

## Usage

```typescript
import { Elysia } from 'elysia'
import { createAuthPlugin, requireAuth } from '@mks2508/auth-oidc-elysia'

const app = new Elysia()
  .use(createAuthPlugin({
    issuerUrl: 'https://auth-provider.example.com',
    clientId: 'my-app',
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    redirectUri: 'https://admin.example.com/auth/callback/oidc',
    sessionSecret: process.env.OIDC_SESSION_SECRET!,
    adminSubs: ['<allowed-user-uuid>'],
    adminUiUrl: 'https://admin.example.com',
    cookieDomain: '.example.com',
  }))
  .get('/admin/data', () => ({ secret: 42 }), { beforeHandle: requireAuth() })
  .listen(3000)
```

## Config options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `issuerUrl` | string | Yes | — | Pocket ID issuer URL |
| `clientId` | string | Yes | — | OIDC client_id |
| `clientSecret` | string | No | — | OIDC client_secret (omit for PKCE-only public clients) |
| `redirectUri` | string | Yes | — | OIDC callback URI registered in Pocket ID |
| `sessionSecret` | string | Yes | — | HS256 secret for session JWT (32+ chars) |
| `adminSubs` | string[] | No | [] | Allowed Pocket ID user subs. Empty = any authenticated user |
| `adminUiUrl` | string | No | `/` | Post-login redirect URL |
| `cookieDomain` | string | No | host-only | Cookie domain for cross-subdomain sessions |
| `bypass` | boolean | No | `false` | Bypass auth entirely (local dev only) |
| `sessionTtl` | number | No | `604800` | Session JWT TTL in seconds (7 days) |

## Auth routes

| Route | Method | Auth | Description |
|-------|--------|------|-------------|
| `/auth/health` | GET | Public | Health check + issuer URL |
| `/auth/status` | GET | Public | Returns session info |
| `/auth/login/oidc` | GET | Public | Initiate PKCE flow |
| `/auth/callback/oidc` | GET | Public | Exchange code, set session |
| `/auth/logout` | POST | Public | Clear session cookie |

## CLI loopback (PKCE only)

For CLI tools (gh-style device auth): pass `?token_mode=true&return_to=http://127.0.0.1:54321/cb` to `/auth/login/oidc`. The callback returns the session token in a URL fragment instead of setting a cookie — safe for local server capture.

```
GET /auth/login/oidc?token_mode=true&return_to=http://127.0.0.1:54321/cb
→ 302 https://auth-provider.example.com/authorize?...
→ 302 http://127.0.0.1:54321/cb#token=<session_jwt>
```

## Exports

```typescript
import {
  createAuthPlugin,    // Main plugin factory
  requireAuth,         // beforeHandle guard
  AuthErrorCode,       // Error code enum
  authError,           // Result<never, ResultError> factory
  type IAuthConfig,    // Plugin config interface
  type IAuthContext,   // Request context after middleware
  type IAuthStatusResponse, // /auth/status response shape
  type ISessionPayload,     // Session JWT payload shape
} from '@mks2508/auth-oidc-elysia'
```

## License

MIT
