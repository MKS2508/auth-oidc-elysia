/**
 * OIDC Pocket ID client using oauth4webapi and jose.
 *
 * Provides:
 * - OIDC discovery and lazy initialization (per config instance)
 * - PKCE authorization URL building
 * - Authorization code exchange (oauth4webapi v3 validateAuthResponse flow)
 * - Access token verification via JWKS (RS256)
 * - Profile extraction from id_token (without re-verification)
 *
 * All functions receive config: IAuthConfig — NO process.env reads.
 * The discovery cache is stored per config.issuerUrl (WeakMap-keyed).
 *
 * @module oidc-client
 */

import * as oauth from 'oauth4webapi';
import * as jose from 'jose';
import { component } from '@mks2508/better-logger';
import { tryCatchAsync, ok, isOk } from '@mks2508/no-throw';
import type { Result, ResultError } from '@mks2508/no-throw';
import { authError, AuthErrorCode, type AuthErrorCodeT } from './errors.js';
import type { IAuthConfig } from './types.js';

const log = component('OidcClient');

/**
 * Profile claims extracted from a Pocket ID id_token.
 * `scope='openid profile email'` populates these fields.
 */
export interface IIdTokenProfile {
  sub: string;
  email?: string;
  name?: string;
  preferred_username?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
}

/**
 * Per-issuer OIDC discovery cache.
 * Keyed by issuerUrl so multiple plugin instances can coexist.
 */
interface IOidcCache {
  as: oauth.AuthorizationServer;
  client: oauth.Client;
  jwks: jose.JWTVerifyGetKey;
}

const oidcCache = new Map<string, IOidcCache>();

/**
 * Get or build the client auth method based on config.
 *
 * @param config - Auth config
 * @returns ClientAuth (ClientSecretPost if secret present, None otherwise)
 */
function getClientAuth(config: IAuthConfig): oauth.ClientAuth {
  return config.clientSecret ? oauth.ClientSecretPost(config.clientSecret) : oauth.None();
}

/**
 * Initialize OIDC discovery and JWKS for the given config.
 * Lazy — runs only once per issuerUrl, then returns cached result.
 * Must be called before any OIDC operation; throws on discovery failure.
 *
 * @param config - Auth config with issuerUrl and clientId
 * @throws ResultError(DiscoveryFailed) if discovery fails
 */
export async function initializeOidc(config: IAuthConfig): Promise<void> {
  if (oidcCache.has(config.issuerUrl)) return;
  const issuer = new URL(config.issuerUrl);
  log.info('Discovering OIDC issuer...', { issuer: config.issuerUrl });
  const result = await tryCatchAsync(async () => {
    const discoveryResponse = await oauth.discoveryRequest(issuer);
    const as = await oauth.processDiscoveryResponse(issuer, discoveryResponse);
    const client: oauth.Client = { client_id: config.clientId };
    const jwks = jose.createRemoteJWKSet(new URL(as.jwks_uri!));
    return { as, client, jwks };
  }, AuthErrorCode.DiscoveryFailed);

  if (!isOk(result)) {
    log.error('OIDC discovery failed', { issuer: config.issuerUrl });
    throw result.error;
  }

  oidcCache.set(config.issuerUrl, result.value);
  log.info('OIDC initialized', {
    issuer: config.issuerUrl,
    authorization_endpoint: result.value.as.authorization_endpoint,
    token_endpoint: result.value.as.token_endpoint,
  });
}

/**
 * Get cached OIDC auth server (throws if not initialized).
 *
 * @param config - Auth config
 * @returns IOidcCache
 */
function getCache(config: IAuthConfig): IOidcCache {
  const cache = oidcCache.get(config.issuerUrl);
  if (!cache) throw new Error('OIDC not initialized — call initializeOidc(config) first');
  return cache;
}

/**
 * Verify Pocket ID access token using JWKS (RS256).
 * Returns the decoded claims on success.
 *
 * Does NOT check adminSubs — that is the middleware's responsibility.
 *
 * @param token - Access token from OIDC provider
 * @param config - Auth config with issuerUrl for JWKS verification
 * @returns Result with { sub, email?, name? } or AuthErrorCodeT
 */
export async function verifyAccessToken(
  token: string,
  config: IAuthConfig,
): Promise<Result<{ sub: string; email?: string; name?: string }, ResultError<AuthErrorCodeT>>> {
  const result = await tryCatchAsync(async () => {
    const cache = getCache(config);
    const { payload } = await jose.jwtVerify(token, cache.jwks, { issuer: config.issuerUrl });
    return {
      sub: payload.sub as string,
      email: payload.email as string | undefined,
      name: payload.name as string | undefined,
    };
  }, AuthErrorCode.InvalidToken);

  if (!isOk(result)) {
    const msg = result.error.message ?? '';
    if (msg.toLowerCase().includes('exp') || msg.toLowerCase().includes('expired')) {
      return authError(AuthErrorCode.TokenExpired, 'Access token expired');
    }
    return authError(AuthErrorCode.InvalidToken, `Token verification failed: ${msg}`);
  }

  return ok(result.value);
}

/**
 * Build authorization URL with PKCE parameters.
 * Requires initializeOidc() to have been called first.
 *
 * @param state - Random state string for CSRF protection
 * @param codeChallenge - PKCE code challenge (S256 method)
 * @param redirectUri - OIDC redirect URI (must match registered)
 * @param config - Auth config with clientId
 * @returns Full authorization URL to redirect the user to
 */
export function buildAuthorizeUrl(
  state: string,
  codeChallenge: string,
  redirectUri: string,
  config: IAuthConfig,
): string {
  const cache = getCache(config);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });
  return `${cache.as.authorization_endpoint}?${params}`;
}

/**
 * Exchange authorization code for tokens.
 *
 * Uses oauth4webapi v3 flow: validateAuthResponse() first (checks iss, state,
 * error params), then authorizationCodeGrantRequest() + processAuthorizationCodeResponse().
 *
 * @param callbackParams - Raw URLSearchParams from /auth/callback/oidc (all query params)
 * @param expectedState - State previously stored in oidc_state cookie
 * @param codeVerifier - PKCE code verifier (matches challenge sent on /login)
 * @param redirectUri - OIDC redirect URI (must match the original)
 * @param config - Auth config
 * @returns Result with token response or AuthErrorCodeT
 */
export async function exchangeCode(
  callbackParams: URLSearchParams,
  expectedState: string,
  codeVerifier: string,
  redirectUri: string,
  config: IAuthConfig,
): Promise<Result<{ access_token: string; id_token: string; refresh_token?: string; expires_in: number }, ResultError<AuthErrorCodeT>>> {
  const result = await tryCatchAsync(async () => {
    const { as, client } = getCache(config);
    // Step 1: validate the auth response. Throws on iss/state/error mismatch.
    const validated = oauth.validateAuthResponse(as, client, callbackParams, expectedState);
    // Step 2: exchange the validated code for tokens.
    const clientAuth = getClientAuth(config);
    const response = await oauth.authorizationCodeGrantRequest(as, client, clientAuth, validated, redirectUri, codeVerifier);
    const tokenResponse = await oauth.processAuthorizationCodeResponse(as, client, response);
    return {
      access_token: tokenResponse.access_token,
      id_token: tokenResponse.id_token!,
      refresh_token: tokenResponse.refresh_token,
      expires_in: tokenResponse.expires_in ?? 3600,
    };
  }, AuthErrorCode.CodeExchangeFailed);

  if (!isOk(result)) {
    return authError(AuthErrorCode.CodeExchangeFailed, `Code exchange failed: ${result.error.message}`);
  }
  return ok(result.value);
}

/**
 * Extract profile claims from id_token WITHOUT re-verification.
 * The id_token is already validated by exchangeCode via oauth4webapi.
 *
 * @param idToken - id_token string (JWS format: header.payload.sig)
 * @returns IIdTokenProfile with sub and optional profile claims
 * @throws Error if id_token is malformed or missing sub
 */
export function extractProfileFromIdToken(idToken: string): IIdTokenProfile {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Invalid id_token format');
  const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString()) as Record<string, unknown>;
  const asString = (key: string): string | undefined => {
    const v = payload[key];
    return typeof v === 'string' && v.length > 0 ? v : undefined;
  };
  const sub = asString('sub');
  if (!sub) throw new Error('id_token missing sub claim');
  return {
    sub,
    email: asString('email'),
    name: asString('name'),
    preferred_username: asString('preferred_username'),
    picture: asString('picture'),
    given_name: asString('given_name'),
    family_name: asString('family_name'),
  };
}

/**
 * Validate a return_to URL against a list of trusted origins.
 * Strict exact-origin comparison to prevent open-redirect attacks.
 *
 * @param returnTo - URL to validate (must be absolute http/https)
 * @param trustedOrigins - Whitelist of origin or full URL strings
 * @returns true if returnTo's origin matches a whitelisted entry
 */
export function validateReturnTo(returnTo: string, trustedOrigins: readonly string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(returnTo);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  const candidateOrigin = parsed.origin;
  return trustedOrigins.some((trusted) => {
    try {
      return new URL(trusted).origin === candidateOrigin;
    } catch {
      return false;
    }
  });
}

/**
 * Get the cached OIDC AuthorizationServer metadata.
 * Useful for accessing end_session_endpoint etc.
 *
 * @param config - Auth config
 * @returns AuthorizationServer metadata or null if not initialized
 */
export function getOidcAs(config: IAuthConfig): oauth.AuthorizationServer | null {
  return oidcCache.get(config.issuerUrl)?.as ?? null;
}
