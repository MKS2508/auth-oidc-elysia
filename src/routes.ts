/**
 * Auth routes for Pocket ID OIDC integration.
 *
 * Provides:
 * - GET /auth/health — Health check with issuer info
 * - GET /auth/status — Auth status (reads session cookie or Bearer)
 * - GET /auth/login/oidc — Initiate PKCE flow. Supports ?token_mode=true&return_to=URL
 * - GET /auth/callback/oidc — Exchange code, set session cookie or redirect with fragment
 * - POST /auth/logout — Clear session cookie
 *
 * Routes receive config: IAuthConfig — NO process.env reads.
 *
 * @module routes
 */

import { Elysia } from 'elysia';
import * as oauth from 'oauth4webapi';
import {
  buildAuthorizeUrl,
  exchangeCode,
  extractProfileFromIdToken,
  getOidcAs,
  initializeOidc,
  validateReturnTo,
  verifyAccessToken,
} from './oidc-client.js';
import { createSessionJwtPlugin } from './jwt.js';
import type { IAuthConfig, IAuthStatusResponse } from './types.js';
import { component } from '@mks2508/better-logger';

const log = component('AuthRoutes');

/**
 * Create Elysia plugin with all auth routes.
 * Registers session JWT plugin internally — no external `.use()` required.
 *
 * @param config - Auth config (issuerUrl, clientId, redirectUri, sessionSecret, etc.)
 * @returns Elysia plugin with /health, /status, /login/oidc, /callback/oidc, /logout
 *
 * @example
 * ```typescript
 * app.group('/auth', (app) => app.use(createAuthRoutes(config)))
 * ```
 */
export function createAuthRoutes(config: IAuthConfig) {
  return new Elysia({ name: 'mks-auth-routes' })
    .use(createSessionJwtPlugin(config))

    /**
     * Health check — returns ok + issuer URL.
     */
    .get('/health', () => ({
      ok: true,
      issuer: config.issuerUrl,
      timestamp: new Date().toISOString(),
    }))

    /**
     * Auth status — reads session cookie or Bearer header.
     * Returns IAuthStatusResponse with authenticated flag + profile claims.
     */
    .get('/status', async (context): Promise<IAuthStatusResponse> => {
      type SessionPayload = {
        sub?: string;
        access_token?: string;
        email?: string;
        name?: string;
        preferred_username?: string;
        picture?: string;
        given_name?: string;
        family_name?: string;
      };

      let sessionData: SessionPayload | false = false;

      // Try session cookie
      if (context.cookie.oidc_session.value) {
        try {
          sessionData = await context.session.verify(context.cookie.oidc_session.value as string) as SessionPayload | false;
        } catch {
          sessionData = false;
        }
      }

      // Try Authorization Bearer as session JWT (cross-origin token-mode)
      if (!sessionData) {
        const authHeader = context.headers['authorization'];
        const bearer = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : undefined;
        if (bearer) {
          try {
            sessionData = await context.session.verify(bearer) as SessionPayload | false;
          } catch {
            sessionData = false;
          }
        }
      }

      if (!sessionData) {
        return { authenticated: false, bypass: config.bypass === true };
      }

      // Enrich email from live access_token if available (may have expired)
      let emailFromAccessToken: string | undefined;
      if (sessionData.access_token) {
        const liveResult = await verifyAccessToken(sessionData.access_token, config);
        if (liveResult.ok) {
          emailFromAccessToken = liveResult.value.email;
        }
      }

      return {
        authenticated: true,
        sub: sessionData.sub,
        email: sessionData.email ?? emailFromAccessToken,
        name: sessionData.name,
        preferred_username: sessionData.preferred_username,
        picture: sessionData.picture,
        given_name: sessionData.given_name,
        family_name: sessionData.family_name,
        bypass: false,
      };
    })

    /**
     * Initiate PKCE OIDC flow.
     *
     * Query params:
     * - token_mode=true: CLI loopback mode — callback returns token in URL fragment
     * - return_to=URL: CLI callback URL (required if token_mode=true)
     *
     * Validates return_to against http://127.0.0.1/* and https://{adminUiUrl host}
     * to prevent open-redirect.
     */
    .get('/login/oidc', async ({ query, cookie, redirect, set }) => {
      const q = query as Record<string, string | undefined>;
      const tokenMode = q.token_mode === 'true';
      const returnTo = q.return_to;

      if (tokenMode) {
        // Build trusted origins for loopback CLI — allow localhost:* ports
        const trustedOrigins: string[] = [
          'http://127.0.0.1:54321',
          'http://127.0.0.1:54322',
          'http://127.0.0.1:54323',
          'http://localhost:54321',
          'http://localhost:54322',
          'http://localhost:54323',
        ];
        if (config.adminUiUrl) trustedOrigins.push(config.adminUiUrl);

        if (!returnTo || !validateReturnTo(returnTo, trustedOrigins)) {
          set.status = 400;
          return { success: false, error: 'INVALID_RETURN_TO' };
        }
      }

      // Lazy OIDC initialization (cached per issuerUrl)
      await initializeOidc(config);

      const state = oauth.generateRandomState();
      const codeVerifier = oauth.generateRandomCodeVerifier();
      const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);

      cookie.oidc_state.set({
        value: {
          state,
          verifier: codeVerifier,
          ...(tokenMode ? { return_to: returnTo, token_mode: true } : {}),
        } as unknown as string,
        domain: config.cookieDomain,
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 600, // 10 minutes
      });

      return redirect(await buildAuthorizeUrl(state, codeChallenge, config.redirectUri, config));
    })

    /**
     * OIDC callback — exchange authorization code for tokens, set session.
     *
     * If token_mode was set on /login/oidc: redirects to return_to with
     * #token=<session_jwt> in the fragment (not visible in server logs).
     *
     * Otherwise: sets httpOnly oidc_session cookie + redirects to adminUiUrl.
     */
    .get('/callback/oidc', async ({ query, cookie, session, redirect }) => {
      const q = query as Record<string, string | undefined>;

      if (q.error) {
        log.warn('OIDC callback error', { error: q.error, description: q.error_description });
        return { success: false, error: q.error, error_description: q.error_description };
      }

      if (!q.code || !q.state) {
        return { success: false, error: 'missing_params' };
      }

      const stateValue = cookie.oidc_state.value as unknown as {
        state: string;
        verifier: string;
        return_to?: string;
        token_mode?: boolean;
      } | undefined;

      if (!stateValue) {
        return { success: false, error: 'no_state_cookie' };
      }

      // Reconstruct URLSearchParams — pass ALL query params including `iss` (RFC 9207)
      const callbackParams = new URLSearchParams();
      for (const [k, v] of Object.entries(q)) {
        if (typeof v === 'string') callbackParams.set(k, v);
      }

      const tokensResult = await exchangeCode(
        callbackParams,
        stateValue.state,
        stateValue.verifier,
        config.redirectUri,
        config,
      );

      if (!tokensResult.ok) {
        log.error('Code exchange failed', { error: tokensResult.error.message });
        return { success: false, error: 'OIDC_CODE_EXCHANGE_FAILED' };
      }

      const tokens = tokensResult.value;
      const profile = extractProfileFromIdToken(tokens.id_token);

      // Check adminSubs if configured
      if (config.adminSubs?.length && !config.adminSubs.includes(profile.sub)) {
        log.warn('Login denied — sub not in adminSubs', { sub: profile.sub });
        return { success: false, error: 'ADMIN_SUB_MISMATCH' };
      }

      // Build session payload — jose@6.x rejects undefined values → filter before signing
      const sessionPayload: Record<string, string> = {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token ?? '',
        sub: profile.sub,
      };
      if (profile.email) sessionPayload.email = profile.email;
      if (profile.name) sessionPayload.name = profile.name;
      if (profile.preferred_username) sessionPayload.preferred_username = profile.preferred_username;
      if (profile.picture) sessionPayload.picture = profile.picture;
      if (profile.given_name) sessionPayload.given_name = profile.given_name;
      if (profile.family_name) sessionPayload.family_name = profile.family_name;

      const sessionToken = await session.sign(sessionPayload);

      // Clear state cookie in both modes
      cookie.oidc_state.remove();

      // Token mode: redirect with session JWT in fragment (not sent to server)
      if (stateValue.token_mode === true && stateValue.return_to) {
        const trustedOrigins: string[] = [
          'http://127.0.0.1:54321',
          'http://127.0.0.1:54322',
          'http://127.0.0.1:54323',
          'http://localhost:54321',
          'http://localhost:54322',
          'http://localhost:54323',
        ];
        if (config.adminUiUrl) trustedOrigins.push(config.adminUiUrl);

        if (!validateReturnTo(stateValue.return_to, trustedOrigins)) {
          return { success: false, error: 'INVALID_RETURN_TO' };
        }
        const sep = stateValue.return_to.includes('#') ? '&' : '#';
        return redirect(`${stateValue.return_to}${sep}token=${encodeURIComponent(sessionToken)}`);
      }

      // Cookie mode: set httpOnly session cookie + redirect to adminUiUrl
      cookie.oidc_session.set({
        value: sessionToken,
        domain: config.cookieDomain,
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: config.sessionTtl ?? 604800,
      });

      return redirect(config.adminUiUrl ?? '/');
    })

    /**
     * Logout — clear session cookie.
     * Optionally redirects to Pocket ID end_session_endpoint if available.
     */
    .post('/logout', async ({ cookie, redirect }) => {
      cookie.oidc_session.remove();
      const as = getOidcAs(config);
      if (as?.end_session_endpoint && config.adminUiUrl) {
        return redirect(`${as.end_session_endpoint}?post_logout_redirect_uri=${encodeURIComponent(config.adminUiUrl)}`);
      }
      return { success: true };
    });
}
