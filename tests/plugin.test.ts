import { describe, it, expect } from 'vitest';
import { Elysia } from 'elysia';
import { createAuthPlugin, requireAuth } from '../src/index.js';

describe('createAuthPlugin', () => {
  it('mounts /auth/health and returns issuer', async () => {
    const app = new Elysia().use(createAuthPlugin({
      issuerUrl: 'https://example.com',
      clientId: 'test',
      redirectUri: 'http://localhost/cb',
      sessionSecret: 'a'.repeat(32),
    }));
    const res = await app.handle(new Request('http://localhost/auth/health'));
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.issuer).toBe('https://example.com');
  });

  it('requireAuth returns 401 without auth', async () => {
    const app = new Elysia()
      .use(createAuthPlugin({
        issuerUrl: 'https://example.com',
        clientId: 'test',
        redirectUri: 'http://localhost/cb',
        sessionSecret: 'a'.repeat(32),
      }))
      .get('/protected', () => 'ok', { beforeHandle: requireAuth() });
    const res = await app.handle(new Request('http://localhost/protected'));
    expect(res.status).toBe(401);
  });

  it('bypass mode allows access to protected route', async () => {
    const app = new Elysia()
      .use(createAuthPlugin({
        issuerUrl: 'https://example.com',
        clientId: 'test',
        redirectUri: 'http://localhost/cb',
        sessionSecret: 'a'.repeat(32),
        bypass: true,
      }))
      .get('/protected', () => 'ok', { beforeHandle: requireAuth() });
    const res = await app.handle(new Request('http://localhost/protected'));
    expect(res.status).toBe(200);
  });

  it('/auth/status returns authenticated: false when no session', async () => {
    const app = new Elysia().use(createAuthPlugin({
      issuerUrl: 'https://example.com',
      clientId: 'test',
      redirectUri: 'http://localhost/cb',
      sessionSecret: 'a'.repeat(32),
    }));
    const res = await app.handle(new Request('http://localhost/auth/status'));
    const body = await res.json();
    expect(body.authenticated).toBe(false);
  });
});
