/**
 * @mks2508/auth-oidc-elysia
 *
 * Pocket ID OIDC plugin for Elysia.
 * PKCE Authorization Code flow, JWKS validation, session JWT (HS256), requireAuth() guard.
 *
 * @module @mks2508/auth-oidc-elysia
 */

export { createAuthPlugin } from './plugin.js';
export { requireAuth } from './middleware.js';
export { AuthErrorCode, authError, type AuthErrorCodeT } from './errors.js';
export type {
  IAuthConfig,
  IAuthContext,
  IAuthStatusResponse,
  ISessionPayload,
} from './types.js';
