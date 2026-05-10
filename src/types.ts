/**
 * Auth configuration and context types for Pocket ID OIDC integration.
 *
 * @module types
 */

import type { JWTPayloadSpec } from '@elysiajs/jwt';

/**
 * Configuration object for createAuthPlugin().
 * All fields except sessionSecret are optional for dev (bypass mode).
 */
export interface IAuthConfig {
  /** Pocket ID issuer URL, e.g. https://auth-provider.mks2508.systems */
  issuerUrl: string;
  /** OIDC client_id registered in Pocket ID */
  clientId: string;
  /** OIDC client_secret. Optional for public clients (PKCE only). */
  clientSecret?: string;
  /** Redirect URI registered in Pocket ID */
  redirectUri: string;
  /** Secret to sign session JWT (HS256). 32+ bytes random. */
  sessionSecret: string;
  /** Allowed Pocket ID subs (user IDs). If empty → any authenticated user passes. */
  adminSubs?: string[];
  /** Admin SPA base URL for post-login redirect. Default: / */
  adminUiUrl?: string;
  /** Cookie domain for session JWT cross-subdomain, e.g. .example.com */
  cookieDomain?: string;
  /** Total auth bypass for local dev. Default: false */
  bypass?: boolean;
  /** Session JWT TTL in seconds. Default: 604800 (7 days) */
  sessionTtl?: number;
}

/**
 * Auth context derived from request (attached by middleware via Elysia derive).
 * Available in all route handlers after createAuthMiddleware() is registered.
 */
export interface IAuthContext {
  /** Whether the request is authenticated */
  isAuthenticated: boolean;
  /** Pocket ID user sub (subject) */
  sub?: string;
  /** User email from OIDC claims */
  email?: string;
  /** Display name from OIDC */
  name?: string;
  /** Avatar URL from OIDC */
  picture?: string;
  /** Original Pocket ID access_token */
  accessToken?: string;
  /** Index signature for Elysia derive compatibility */
  [key: string]: unknown;
}

/**
 * Auth status response shape for /auth/status endpoint.
 */
export interface IAuthStatusResponse {
  /** Whether the request is authenticated */
  authenticated: boolean;
  /** Pocket ID user sub */
  sub?: string;
  /** User email */
  email?: string;
  /** Display name */
  name?: string;
  /** Preferred username from OIDC preferred_username claim */
  preferred_username?: string;
  /** Avatar URL */
  picture?: string;
  /** Given name from OIDC given_name claim */
  given_name?: string;
  /** Family name from OIDC family_name claim */
  family_name?: string;
  /** Whether auth was bypassed (config.bypass === true) */
  bypass?: boolean;
}

/**
 * Session JWT payload stored in httpOnly cookie (signed by HS256).
 * Wraps OIDC tokens and profile claims so the cookie is opaque to clients.
 */
export interface ISessionPayload extends JWTPayloadSpec {
  /** Pocket ID access_token (RS256 from provider) */
  access_token: string;
  /** Pocket ID refresh_token (opaque) */
  refresh_token?: string;
  /** Subject from id_token */
  sub: string;
  /** Email from OIDC */
  email?: string;
  /** Display name */
  name?: string;
  /** Preferred username */
  preferred_username?: string;
  /** Avatar URL */
  picture?: string;
  /** Given name */
  given_name?: string;
  /** Family name */
  family_name?: string;
}
