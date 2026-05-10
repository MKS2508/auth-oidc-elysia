/**
 * Main plugin factory for Pocket ID OIDC auth.
 *
 * Composes session JWT + auth middleware + auth routes into a single
 * Elysia plugin that consumers `.use()` once.
 *
 * @module plugin
 */

import { Elysia } from 'elysia';
import { createSessionJwtPlugin } from './jwt.js';
import { createAuthMiddleware } from './middleware.js';
import { createAuthRoutes } from './routes.js';
import type { IAuthConfig } from './types.js';

/**
 * Create the Pocket ID OIDC auth plugin for Elysia.
 *
 * Registers:
 * - Session JWT plugin (decorates `ctx.session`)
 * - Auth middleware (derives `IAuthContext` from every request)
 * - Auth routes at `{routePrefix}` (default `/auth`)
 *
 * @param config - Auth configuration (issuerUrl, clientId, redirectUri, sessionSecret...)
 * @param opts - Optional settings
 * @param opts.routePrefix - Route prefix for auth endpoints. Default: `/auth`
 * @returns Elysia plugin
 *
 * @example
 * ```typescript
 * import { Elysia } from 'elysia'
 * import { createAuthPlugin, requireAuth } from '@mks2508/auth-oidc-elysia'
 *
 * const app = new Elysia()
 *   .use(createAuthPlugin({
 *     issuerUrl: 'https://auth-provider.example.com',
 *     clientId: 'my-app',
 *     clientSecret: process.env.OIDC_CLIENT_SECRET,
 *     redirectUri: 'https://admin.example.com/auth/callback/oidc',
 *     sessionSecret: process.env.OIDC_SESSION_SECRET!,
 *     adminSubs: ['<allowed-user-uuid>'],
 *     adminUiUrl: 'https://admin.example.com',
 *     cookieDomain: '.example.com',
 *   }))
 *   .get('/admin/data', () => ({ secret: 42 }), { beforeHandle: requireAuth() })
 * ```
 */
export function createAuthPlugin(
  config: IAuthConfig,
  opts?: { routePrefix?: string },
) {
  const prefix = opts?.routePrefix ?? '/auth';
  return new Elysia({ name: 'mks-auth-oidc' })
    .use(createSessionJwtPlugin(config))
    .use(createAuthMiddleware(config))
    .group(prefix, (app) => app.use(createAuthRoutes(config)));
}
