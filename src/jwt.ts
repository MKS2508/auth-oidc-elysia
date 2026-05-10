/**
 * Session JWT plugin factory for Elysia.
 * Wraps @elysiajs/jwt configured for Pocket ID session management.
 *
 * @module jwt
 */

import { Elysia } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import type { IAuthConfig, ISessionPayload } from './types.js';

/**
 * Methods exposed on `ctx.session` once the plugin is `.use()`-d.
 * Manually typed to avoid TS2883 declaration emit issues (jose's bun-specific path).
 */
export interface ISessionJwtMethods {
  /** Sign a session payload with HS256 + config.sessionSecret */
  sign(payload: Partial<ISessionPayload>): Promise<string>;
  /** Verify and decode a session JWT. Returns false on invalid or expired token. */
  verify(token?: string): Promise<ISessionPayload | false>;
}

/**
 * Create Elysia JWT plugin configured for session management.
 *
 * The plugin decorates Elysia context with `session.sign()` and `session.verify()`.
 * Share by reference across plugin, middleware, and routes — Elysia deduplicates
 * by plugin name so initialization runs only once.
 *
 * @param config - Auth config with sessionSecret and optional sessionTtl
 * @returns Elysia plugin decorated with { session: ISessionJwtMethods }
 *
 * @example
 * ```typescript
 * const app = new Elysia()
 *   .use(createSessionJwtPlugin({ sessionSecret: 'my-32-char-secret', ... }))
 *   .get('/sign', async ({ session }) => session.sign({ sub: 'user-1', access_token: 'tok' }))
 * ```
 */
export function createSessionJwtPlugin(config: IAuthConfig): Elysia<
  '',
  {
    decorator: { session: ISessionJwtMethods };
    store: Record<string, unknown>;
    derive: Record<string, unknown>;
    resolve: Record<string, unknown>;
  }
> {
  const ttlSeconds = config.sessionTtl ?? 604800;
  // @elysiajs/jwt expects a duration string (e.g. '7d', '3600s') or omit for no expiry.
  // Convert seconds to a duration string to avoid being interpreted as UNIX timestamp.
  const expStr = `${ttlSeconds}s`;
  return jwt({
    name: 'session',
    secret: config.sessionSecret,
    exp: expStr,
  }) as unknown as Elysia<
    '',
    {
      decorator: { session: ISessionJwtMethods };
      store: Record<string, unknown>;
      derive: Record<string, unknown>;
      resolve: Record<string, unknown>;
    }
  >;
}
