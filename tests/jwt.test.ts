import { describe, it, expect } from 'vitest';
import { Elysia } from 'elysia';
import { createSessionJwtPlugin } from '../src/jwt.js';

describe('session jwt', () => {
  it('signs and verifies a payload roundtrip', async () => {
    // Use a shared variable to avoid JSON serialization issues with Elysia responses
    let capturedToken = '';

    const app = new Elysia()
      .use(createSessionJwtPlugin({
        issuerUrl: '',
        clientId: '',
        redirectUri: '',
        sessionSecret: 'b'.repeat(32),
      }))
      .get('/sign', async ({ session }) => {
        const token = await session.sign({ sub: 'user-1', access_token: 'xyz' });
        capturedToken = token;
        return { token };
      })
      .get('/verify', async ({ session, query }) => {
        const t = query.t as string;
        const result = await session.verify(t);
        return result;
      });

    const signRes = await app.handle(new Request('http://localhost/sign'));
    const signBody = await signRes.json();
    const token = signBody.token as string;
    expect(token).toBeTruthy();
    expect(capturedToken).toBe(token);

    const verifyRes = await app.handle(new Request(`http://localhost/verify?t=${encodeURIComponent(token)}`));
    const payload = await verifyRes.json();
    expect(payload.sub).toBe('user-1');
  });

  it('returns false for an invalid token', async () => {
    const app = new Elysia()
      .use(createSessionJwtPlugin({
        issuerUrl: '',
        clientId: '',
        redirectUri: '',
        sessionSecret: 'c'.repeat(32),
      }))
      .get('/verify', async ({ session, query }) => {
        const result = await session.verify(query.t as string);
        return { valid: result !== false };
      });

    const res = await app.handle(new Request('http://localhost/verify?t=invalid.token.here'));
    const body = await res.json();
    expect(body.valid).toBe(false);
  });
});
