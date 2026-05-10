/**
 * Auth middleware for Elysia + requireAuth guard.
 *
 * Bridges Pocket ID OIDC sessions into IAuthContext:
 * - Supports bypass mode (config.bypass === true) for local dev
 * - Reads session JWT from httpOnly cookie (oidc_session)
 * - Falls back to Authorization: Bearer header (session JWT or raw access_token)
 * - Falls back to ?token= query param (for SSE/WebSocket clients)
 * - Verifies access_token against Pocket ID JWKS when session JWT unavailable
 *
 * The createSessionJwtPlugin() must be registered BEFORE this middleware.
 *
 * @module middleware
 */

import { Elysia } from 'elysia';
import { component } from '@mks2508/better-logger';
import { createSessionJwtPlugin } from './jwt.js';
import { verifyAccessToken } from './oidc-client.js';
import type { IAuthConfig, IAuthContext } from './types.js';

const log = component('AuthMiddleware');

/**
 * Create an Elysia middleware that derives IAuthContext from the incoming request.
 *
 * Auth resolution order:
 * 1. bypass mode → isAuthenticated: true (for local dev)
 * 2. oidc_session cookie → verify as session JWT
 * 3. Authorization: Bearer → try as session JWT first, then as Pocket ID access_token
 * 4. ?token= query param → same as Bearer (for SSE/WebSocket)
 * 5. Default → isAuthenticated: false
 *
 * @param config - Auth config
 * @returns Elysia plugin with IAuthContext derived on every request
 */
export function createAuthMiddleware(config: IAuthConfig) {
  return new Elysia({ name: 'mks-auth-middleware' })
    .use(createSessionJwtPlugin(config))
    .derive({ as: 'global' }, async ({ session, cookie, headers, query }) => {
      const defaultCtx: IAuthContext = { isAuthenticated: false };

      // Bypass mode for local development
      if (config.bypass === true) {
        return { isAuthenticated: true, sub: 'dev-bypass', email: 'dev@local', name: 'Dev User' } satisfies IAuthContext;
      }

      const extractFromSessionPayload = (payload: unknown): { sub?: string; accessToken?: string; email?: string; name?: string; picture?: string } => {
        if (!payload || typeof payload !== 'object') return {};
        const obj = payload as Record<string, unknown>;
        return {
          sub: typeof obj.sub === 'string' ? obj.sub : undefined,
          accessToken: typeof obj.access_token === 'string' ? obj.access_token : undefined,
          email: typeof obj.email === 'string' ? obj.email : undefined,
          name: typeof obj.name === 'string' ? obj.name : undefined,
          picture: typeof obj.picture === 'string' ? obj.picture : undefined,
        };
      };

      let sessionSub: string | undefined;
      let accessToken: string | undefined;
      let sessionEmail: string | undefined;
      let sessionName: string | undefined;
      let sessionPicture: string | undefined;

      // Try session cookie first
      if (cookie.oidc_session.value) {
        try {
          const payload = await session.verify(cookie.oidc_session.value as string);
          const extracted = extractFromSessionPayload(payload);
          sessionSub = extracted.sub;
          accessToken = extracted.accessToken;
          sessionEmail = extracted.email;
          sessionName = extracted.name;
          sessionPicture = extracted.picture;
        } catch (err) {
          log.debug('Session cookie verify failed', { error: err instanceof Error ? err.message : String(err) });
        }
      }

      // Build bearer token — from header or ?token= query param (SSE/WS fallback)
      const authHeader = headers['authorization'];
      const queryToken = (() => {
        const q = (query as Record<string, unknown> | undefined)?.token;
        return typeof q === 'string' && q.length > 0 ? q : undefined;
      })();
      const bearer = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : queryToken;

      // Try Bearer as session JWT first (token-mode cross-origin admin)
      if (!sessionSub && bearer) {
        try {
          const payload = await session.verify(bearer);
          const extracted = extractFromSessionPayload(payload);
          if (extracted.sub) {
            sessionSub = extracted.sub;
            accessToken = extracted.accessToken;
            sessionEmail = extracted.email;
            sessionName = extracted.name;
            sessionPicture = extracted.picture;
          }
        } catch (err) {
          log.debug('Bearer as session JWT failed, will try as access_token', {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }

      if (!accessToken && bearer) {
        accessToken = bearer;
      }

      // If we have a valid session JWT, authenticate (enrich with live JWKS claims if possible)
      if (sessionSub) {
        if (accessToken) {
          try {
            const claims = await verifyAccessToken(accessToken, config);
            if (claims.ok) {
              // Check adminSubs whitelist if configured
              if (config.adminSubs?.length && !config.adminSubs.includes(claims.value.sub)) {
                log.debug('Sub not in adminSubs, denying', { sub: claims.value.sub });
                return defaultCtx;
              }
              return {
                isAuthenticated: true,
                sub: claims.value.sub,
                email: claims.value.email ?? sessionEmail,
                name: sessionName,
                picture: sessionPicture,
              } satisfies IAuthContext;
            }
          } catch (err) {
            log.debug('Access token expired/invalid, falling back to session JWT claims', {
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }
        // Check adminSubs for session-only path
        if (config.adminSubs?.length && !config.adminSubs.includes(sessionSub)) {
          log.debug('Sub not in adminSubs (session-only path), denying', { sub: sessionSub });
          return defaultCtx;
        }
        return { isAuthenticated: true, sub: sessionSub, email: sessionEmail, name: sessionName, picture: sessionPicture } satisfies IAuthContext;
      }

      // No session JWT — try raw Pocket ID access_token via JWKS
      if (!accessToken) return defaultCtx;

      const claims = await verifyAccessToken(accessToken, config);
      if (!claims.ok) {
        log.debug('Bearer access token verify failed');
        return defaultCtx;
      }

      // Check adminSubs whitelist
      if (config.adminSubs?.length && !config.adminSubs.includes(claims.value.sub)) {
        log.debug('Sub not in adminSubs (raw token path), denying', { sub: claims.value.sub });
        return defaultCtx;
      }

      return {
        isAuthenticated: true,
        sub: claims.value.sub,
        email: claims.value.email,
        name: claims.value.name,
      } satisfies IAuthContext;
    });
}

/**
 * Guard that requires authentication before proceeding.
 * Use as `beforeHandle` in protected routes.
 *
 * Returns HTTP 401 with { error: 'UNAUTHORIZED' } if not authenticated.
 *
 * @returns beforeHandle handler function
 *
 * @example
 * ```typescript
 * app.get('/admin/data', () => ({ secret: 42 }), { beforeHandle: requireAuth() })
 * ```
 */
export const requireAuth = () => {
  return ({ isAuthenticated, set }: IAuthContext & { set: { status: number } }) => {
    if (!isAuthenticated) {
      set.status = 401;
      throw new Error('UNAUTHORIZED: Authentication required');
    }
  };
};
