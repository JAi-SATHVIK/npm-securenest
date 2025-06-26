import { describe, it, expect, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { z } from 'zod';
import { restGuard, clearRestGuardRateLimitStore } from '../src';
import crypto from 'crypto';
import { Buffer } from 'buffer';

// Helper to create an Express app with RestGuard
function createApp(config: Parameters<typeof restGuard>[0]) {
  const app = express();
  app.set('trust proxy', true);
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.all('/test/:id', restGuard(config), (req, res) => {
    res.json({ ok: true });
  });
  return app;
}

// Ensure rate limiter store is cleared after each test for isolation
afterEach(() => {
  clearRestGuardRateLimitStore();
});

describe('RestGuard - Schema Validation (Express)', () => {
  it('should allow valid body', async () => {
    const schema = { body: z.object({ email: z.string().email() }) };
    const app = createApp({ schema });
    const res = await request(app)
      .post('/test/123')
      .send({ email: 'user@example.com' });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('should reject invalid body with 400 and error format', async () => {
    const schema = { body: z.object({ email: z.string().email() }) };
    const app = createApp({ schema });
    const res = await request(app)
      .post('/test/123')
      .send({ email: 'not-an-email' });
    expect(res.status).toBe(400);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(400);
    expect(res.body.message).toMatch(/Validation failed/);
  });

  it('should allow valid query', async () => {
    const schema = { query: z.object({ q: z.string().min(2) }) };
    const app = createApp({ schema });
    const res = await request(app)
      .post('/test/123?q=ok')
      .send();
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('should reject invalid query', async () => {
    const schema = { query: z.object({ q: z.string().min(2) }) };
    const app = createApp({ schema });
    const res = await request(app)
      .post('/test/123?q=x')
      .send();
    expect(res.status).toBe(400);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(400);
    expect(res.body.message).toMatch(/Validation failed/);
  });

  it('should allow valid params', async () => {
    const schema = { params: z.object({ id: z.string().regex(/^\d+$/) }) };
    const app = createApp({ schema });
    const res = await request(app)
      .post('/test/123')
      .send();
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('should reject invalid params', async () => {
    const schema = { params: z.object({ id: z.string().regex(/^\d+$/) }) };
    const app = createApp({ schema });
    const res = await request(app)
      .post('/test/abc')
      .send();
    expect(res.status).toBe(400);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(400);
    expect(res.body.message).toMatch(/Validation failed/);
  });
});

describe('RestGuard - Rate Limiting (Express)', () => {
  it('should allow requests under the limit', async () => {
    const app = createApp({ rateLimit: { windowMs: 100, max: 2 } });
    const res1 = await request(app).post('/test/1').send();
    const res2 = await request(app).post('/test/1').send();
    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
  });

  it('should block requests over the limit with 429', async () => {
    const app = createApp({ rateLimit: { windowMs: 100, max: 2 } });
    await request(app).post('/test/2').send();
    await request(app).post('/test/2').send();
    const res3 = await request(app).post('/test/2').send();
    expect(res3.status).toBe(429);
    expect(res3.body.status).toBe('error');
    expect(res3.body.code).toBe(429);
    expect(res3.body.message).toMatch(/Rate limit exceeded/);
  });

  it('should reset limit after window expires', async () => {
    const app = createApp({ rateLimit: { windowMs: 100, max: 1 } });
    await request(app).post('/test/3').send();
    const res2 = await request(app).post('/test/3').send();
    expect(res2.status).toBe(429);
    // Wait for window to expire
    await new Promise(r => setTimeout(r, 120));
    const res3 = await request(app).post('/test/3').send();
    expect(res3.status).toBe(200);
  });
});

describe('RestGuard - HTTP Method Enforcement (Express)', () => {
  it('should allow only specified methods', async () => {
    const app = createApp({ allowMethods: ['POST'] });
    const res = await request(app).post('/test/1').send();
    expect(res.status).toBe(200);
  });

  it('should reject disallowed methods with 405', async () => {
    const app = createApp({ allowMethods: ['POST'] });
    const res = await request(app).get('/test/1');
    expect(res.status).toBe(405);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(405);
    expect(res.body.message).toMatch(/not allowed/);
  });

  it('should allow multiple methods if specified', async () => {
    const app = createApp({ allowMethods: ['POST', 'GET'] });
    const res1 = await request(app).post('/test/1').send();
    const res2 = await request(app).get('/test/1');
    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
  });
});

describe('RestGuard - Token-Based Authentication (Express)', () => {
  // Helper to create a minimal JWT
  function createJwt(payload: object, secret: string) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encode = (obj: object) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const headerB64 = encode(header);
    const payloadB64 = encode(payload);
    const data = `${headerB64}.${payloadB64}`;
    const sig = crypto.createHmac('sha256', secret).update(data).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `${data}.${sig}`;
  }
  const secret = 'test_secret';

  it('should reject missing Authorization header', async () => {
    const app = createApp({ auth: { required: true, strategy: 'jwt', secret } });
    const res = await request(app).post('/test/1').send();
    expect(res.status).toBe(401);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(401);
    expect(res.body.message).toMatch(/Missing|malformed/i);
  });

  it('should reject malformed Authorization header', async () => {
    const app = createApp({ auth: { required: true, strategy: 'jwt', secret } });
    const res = await request(app).post('/test/1').set('Authorization', 'Bearer').send();
    expect(res.status).toBe(401);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(401);
    expect(res.body.message).toMatch(/Missing|malformed/i);
  });

  it('should reject invalid JWT', async () => {
    const app = createApp({ auth: { required: true, strategy: 'jwt', secret } });
    const res = await request(app).post('/test/1').set('Authorization', 'Bearer invalid.token.value').send();
    expect(res.status).toBe(401);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(401);
    expect(res.body.message).toMatch(/Malformed|Invalid/i);
  });

  it('should reject expired JWT', async () => {
    const expired = Math.floor(Date.now() / 1000) - 10;
    const token = createJwt({ sub: 'user', exp: expired }, secret);
    const app = createApp({ auth: { required: true, strategy: 'jwt', secret } });
    const res = await request(app).post('/test/1').set('Authorization', `Bearer ${token}`).send();
    expect(res.status).toBe(401);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(401);
    expect(res.body.message).toMatch(/expired/i);
  });

  it('should allow valid JWT', async () => {
    const exp = Math.floor(Date.now() / 1000) + 60;
    const token = createJwt({ sub: 'user', exp }, secret);
    const app = createApp({ auth: { required: true, strategy: 'jwt', secret } });
    const res = await request(app).post('/test/1').set('Authorization', `Bearer ${token}`).send();
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('should allow valid Bearer token with custom verify', async () => {
    const app = createApp({ auth: { required: true, strategy: 'bearer', verify: (token) => { if (token !== 'abc') throw new Error('bad'); } } });
    const res = await request(app).post('/test/1').set('Authorization', 'Bearer abc').send();
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('should reject Bearer token if custom verify fails', async () => {
    const app = createApp({ auth: { required: true, strategy: 'bearer', verify: (token) => { if (token !== 'abc') throw new Error('bad'); } } });
    const res = await request(app).post('/test/1').set('Authorization', 'Bearer wrong').send();
    expect(res.status).toBe(401);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(401);
    expect(res.body.message).toMatch(/bad|Invalid/i);
  });
});

describe('RestGuard - CORS Control (Express)', () => {
  it('should set default CORS headers', async () => {
    const app = createApp({ cors: {} });
    const res = await request(app).post('/test/1').send();
    expect(res.headers['access-control-allow-origin']).toBe('*');
    expect(res.headers['access-control-allow-methods']).toMatch(/GET/);
    expect(res.headers['access-control-allow-headers']).toMatch(/Authorization/);
  });

  it('should set custom CORS origin and methods', async () => {
    const app = createApp({ cors: { origin: ['https://a.com'], methods: ['POST'] } });
    const res = await request(app).post('/test/1').send();
    expect(res.headers['access-control-allow-origin']).toBe('https://a.com');
    expect(res.headers['access-control-allow-methods']).toBe('POST');
  });

  it('should set custom allowed and exposed headers', async () => {
    const app = createApp({ cors: { allowedHeaders: ['X-Custom'], exposedHeaders: ['X-Expose'] } });
    const res = await request(app).post('/test/1').send();
    expect(res.headers['access-control-allow-headers']).toBe('X-Custom');
    expect(res.headers['access-control-expose-headers']).toBe('X-Expose');
  });

  it('should handle preflight OPTIONS request', async () => {
    const app = createApp({ cors: { origin: ['https://b.com'] } });
    const res = await request(app).options('/test/1');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('https://b.com');
  });
});

describe('RestGuard - IP Whitelist / Blacklist (Express)', () => {
  it('should block IPs in block list', async () => {
    const app = createApp({ ipRules: { block: ['1.2.3.4'] } });
    const res = await request(app).post('/test/1').set('X-Forwarded-For', '1.2.3.4').send();
    expect(res.status).toBe(403);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(403);
    expect(res.body.message).toMatch(/blocked/);
  });

  it('should allow IPs not in block list', async () => {
    const app = createApp({ ipRules: { block: ['1.2.3.4'] } });
    const res = await request(app).post('/test/1').set('X-Forwarded-For', '5.6.7.8').send();
    expect(res.status).toBe(200);
  });

  it('should allow only IPs in allow list', async () => {
    const app = createApp({ ipRules: { allow: ['5.6.7.8'] } });
    const res = await request(app).post('/test/1').set('X-Forwarded-For', '5.6.7.8').send();
    expect(res.status).toBe(200);
  });

  it('should block IPs not in allow list', async () => {
    const app = createApp({ ipRules: { allow: ['5.6.7.8'] } });
    const res = await request(app).post('/test/1').set('X-Forwarded-For', '1.2.3.4').send();
    expect(res.status).toBe(403);
    expect(res.body.status).toBe('error');
    expect(res.body.code).toBe(403);
    expect(res.body.message).toMatch(/not allowed/);
  });

  it('should block IPs in CIDR block', async () => {
    const app = createApp({ ipRules: { block: ['10.0.0.0/8'] } });
    const res = await request(app).post('/test/1').set('X-Forwarded-For', '10.1.2.3').send();
    expect(res.status).toBe(403);
  });

  it('should allow IPs in CIDR allow', async () => {
    const app = createApp({ ipRules: { allow: ['192.168.1.0/24'] } });
    const res = await request(app).post('/test/1').set('X-Forwarded-For', '192.168.1.42').send();
    expect(res.status).toBe(200);
  });
}); 