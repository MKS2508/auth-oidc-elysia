/**
 * Auth error codes and Result helpers using @mks2508/no-throw.
 *
 * @module errors
 */

import { fail } from '@mks2508/no-throw';

/**
 * Error codes for auth failures.
 * Used with Result<T, ResultError<AuthErrorCodeT>> from @mks2508/no-throw.
 *
 * @example
 * ```typescript
 * import { AuthErrorCode, authError } from '@mks2508/auth-oidc-elysia'
 *
 * return authError(AuthErrorCode.Unauthorized, 'No valid session found')
 * ```
 */
export const AuthErrorCode = {
  /** No valid session or token found */
  Unauthorized: 'UNAUTHORIZED',
  /** Token malformed or signature invalid */
  InvalidToken: 'INVALID_TOKEN',
  /** Token expired */
  TokenExpired: 'TOKEN_EXPIRED',
  /** OIDC discovery failed */
  DiscoveryFailed: 'OIDC_DISCOVERY_FAILED',
  /** OAuth state mismatch (CSRF protection) */
  StateMismatch: 'OIDC_STATE_MISMATCH',
  /** Authorization code exchange failed */
  CodeExchangeFailed: 'OIDC_CODE_EXCHANGE_FAILED',
  /** User not in adminSubs whitelist */
  AdminSubMismatch: 'ADMIN_SUB_MISMATCH',
} as const;

/** Union type of all auth error codes */
export type AuthErrorCodeT = typeof AuthErrorCode[keyof typeof AuthErrorCode];

/**
 * Create a typed ResultError for auth failures.
 *
 * @param code - Error code from AuthErrorCode
 * @param message - Human-readable message
 * @param cause - Optional original Error (for error chaining)
 * @returns Err Result containing the ResultError
 *
 * @example
 * ```typescript
 * return authError(AuthErrorCode.Unauthorized, 'No token provided')
 * ```
 */
export function authError(code: AuthErrorCodeT, message?: string, cause?: Error) {
  return fail(code, message ?? code, cause);
}
