import { ZodSchema, ZodError } from 'zod';
import { RequestHandler, Request, Response, NextFunction } from 'express';
import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify';
import crypto from 'crypto';
import { Buffer } from 'buffer';

/**
 * Zod schemas for request validation.
 */
export type SecureNestSchema = {
  body?: ZodSchema<any>;
  query?: ZodSchema<any>;
  params?: ZodSchema<any>;
};

/**
 * Authentication strategies for SecureNest.
 */
export type SecureNestAuth =
  | {
      required: true;
      strategy: 'jwt';
      secret: string;
      verify?: (token: string) => any | Promise<any>;
    }
  | {
      required: true;
      strategy: 'bearer';
      verify: (token: string) => any | Promise<any>;
    }
  | {
      required?: false;
    };

/**
 * Rate limiting configuration.
 */
export type SecureNestRateLimit = {
  windowMs: number;
  max: number;
};

/**
 * CORS configuration.
 */
export type SecureNestCors = {
  origin?: string[] | string;
  methods?: string[];
  allowedHeaders?: string[];
  exposedHeaders?: string[];
};

/**
 * IP allow/block rules.
 */
export type SecureNestIpRules = {
  allow?: string[];
  block?: string[];
};

/**
 * Main configuration object for SecureNest.
 */
export interface SecureNestConfig {
  schema?: SecureNestSchema;
  auth?: SecureNestAuth;
  rateLimit?: SecureNestRateLimit;
  cors?: SecureNestCors;
  allowMethods?: string[];
  ipRules?: SecureNestIpRules;
}

/**
 * Standardized error format returned by SecureNest.
 */
export interface SecureNestError {
  status: 'error';
  code: number;
  message: string;
}

// --- In-memory Rate Limiter Store ---
const rateLimitStore: Record<string, { count: number; expiresAt: number }> = {};

/**
 * Clears the in-memory rate limiter store. Useful for test isolation.
 */
export function clearSecureNestRateLimitStore() {
  Object.keys(rateLimitStore).forEach(key => delete rateLimitStore[key]);
}

// --- Private Helper Functions ---

function handleSchemaValidation(schema: SecureNestSchema | undefined, req: Request, res: Response): SecureNestError | void {
  if (!schema) return;
  // Validate body
  if (schema.body) {
    const result = schema.body.safeParse(req.body);
    if (!result.success) {
      const message = (result.error as ZodError).errors.map(e => e.message).join('; ');
      return { status: 'error', code: 400, message: `Validation failed: ${message}` };
    }
  }
  // Validate query
  if (schema.query) {
    const result = schema.query.safeParse(req.query);
    if (!result.success) {
      const message = (result.error as ZodError).errors.map(e => e.message).join('; ');
      return { status: 'error', code: 400, message: `Validation failed: ${message}` };
    }
  }
  // Validate params
  if (schema.params) {
    const result = schema.params.safeParse(req.params);
    if (!result.success) {
      const message = (result.error as ZodError).errors.map(e => e.message).join('; ');
      return { status: 'error', code: 400, message: `Validation failed: ${message}` };
    }
  }
}

function handleRateLimit(rateLimit: SecureNestRateLimit | undefined, req: Request, res: Response): SecureNestError | void {
  if (!rateLimit) return;
  const ip = req.ip || req.connection.remoteAddress || '';
  const route = req.baseUrl + req.path;
  const key = `${ip}_${route}`;
  const now = Date.now();
  const { windowMs, max } = rateLimit;
  const entry = rateLimitStore[key];
  if (!entry || entry.expiresAt < now) {
    rateLimitStore[key] = { count: 1, expiresAt: now + windowMs };
  } else {
    entry.count++;
    if (entry.count > max) {
      return { status: 'error', code: 429, message: 'Rate limit exceeded. Try again later.' };
    }
  }
}

function handleMethodEnforcement(allowMethods: string[] | undefined, req: Request): SecureNestError | void {
  if (allowMethods && !allowMethods.includes(req.method)) {
    return {
      status: 'error',
      code: 405,
      message: `Method ${req.method} not allowed. Allowed: ${allowMethods.join(', ')}`,
    };
  }
}

function handleAuth(auth: SecureNestAuth | undefined, req: Request, res: Response, next: NextFunction): SecureNestError | void | Promise<void> {
  if (!auth || !auth.required) return;
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader || typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
    return { status: 'error', code: 401, message: 'Missing or malformed Authorization header' };
  }
  const token = authHeader.slice(7).trim();
  if (auth.strategy === 'jwt') {
    try {
      const [headerB64, payloadB64, signatureB64] = token.split('.');
      if (!headerB64 || !payloadB64 || !signatureB64) throw new Error('Malformed JWT');
      const base64url = (str: Buffer | string) => Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const data = `${headerB64}.${payloadB64}`;
      const expectedSig = crypto.createHmac('sha256', auth.secret).update(data).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      if (expectedSig !== signatureB64) throw new Error('Invalid signature');
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
      if (payload.exp && Date.now() / 1000 > payload.exp) throw new Error('Token expired');
      if (auth.verify) {
        const result = auth.verify(token);
        if (result instanceof Promise) {
          return result.then(() => next()).catch((err: any) => {
            res.status(401).json({ status: 'error', code: 401, message: err?.message || 'Invalid token' });
            return;
          });
        }
      }
    } catch (err: any) {
      return { status: 'error', code: 401, message: err?.message || 'Invalid token' };
    }
  } else if (auth.strategy === 'bearer') {
    try {
      const result = auth.verify(token);
      if (result instanceof Promise) {
        return result.then(() => next()).catch((err: any) => {
          res.status(401).json({ status: 'error', code: 401, message: err?.message || 'Invalid token' });
          return;
        });
      }
    } catch (err: any) {
      return { status: 'error', code: 401, message: err?.message || 'Invalid token' };
    }
  }
}

function handleCors(cors: SecureNestCors | undefined, req: Request, res: Response): void | 'preflight' {
  if (!cors) return;
  const origin = cors.origin || '*';
  const methods = (cors.methods || ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']).join(',');
  const allowedHeaders = (cors.allowedHeaders || ['Content-Type', 'Authorization']).join(',');
  const exposedHeaders = cors.exposedHeaders ? cors.exposedHeaders.join(',') : undefined;
  res.setHeader('Access-Control-Allow-Origin', Array.isArray(origin) ? origin.join(',') : origin);
  res.setHeader('Access-Control-Allow-Methods', methods);
  res.setHeader('Access-Control-Allow-Headers', allowedHeaders);
  if (exposedHeaders) {
    res.setHeader('Access-Control-Expose-Headers', exposedHeaders);
  }
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return 'preflight';
  }
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [range, bits = '32'] = cidr.split('/');
  const ipBuf = ip.split('.').map(Number);
  const rangeBuf = range.split('.').map(Number);
  const mask = ~(2 ** (32 - Number(bits)) - 1);
  const ipInt = ipBuf.reduce((acc, oct) => (acc << 8) + oct, 0);
  const rangeInt = rangeBuf.reduce((acc, oct) => (acc << 8) + oct, 0);
  return (ipInt & mask) === (rangeInt & mask);
}

function handleIpRules(ipRules: SecureNestIpRules | undefined, req: Request): SecureNestError | void {
  if (!ipRules) return;
  const ip = req.ip || req.connection.remoteAddress || '';
  if (ipRules.block && ipRules.block.some(rule => rule === ip || ipInCidr(ip, rule))) {
    return { status: 'error', code: 403, message: 'Your IP is blocked' };
  }
  if (ipRules.allow && !ipRules.allow.some(rule => rule === ip || ipInCidr(ip, rule))) {
    return { status: 'error', code: 403, message: 'Your IP is not allowed' };
  }
}

/**
 * Main SecureNest middleware factory
 * Returns a middleware for Express or Fastify based on usage
 */
export function secureNest(config: SecureNestConfig): RequestHandler {
  const expressMiddleware: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    // 1. Schema Validation
    const schemaError = handleSchemaValidation(config.schema, req, res);
    if (schemaError) return res.status(schemaError.code).json(schemaError);

    // 2. Rate Limiting
    const rateLimitError = handleRateLimit(config.rateLimit, req, res);
    if (rateLimitError) return res.status(rateLimitError.code).json(rateLimitError);

    // 3. HTTP Method Enforcement
    const methodError = handleMethodEnforcement(config.allowMethods, req);
    if (methodError) return res.status(methodError.code).json(methodError);

    // 4. Token-Based Authentication
    const authResult = handleAuth(config.auth, req, res, next);
    if (authResult instanceof Promise) return authResult;
    if (authResult) return res.status(authResult.code).json(authResult);

    // 5. CORS Control
    const corsResult = handleCors(config.cors, req, res);
    if (corsResult === 'preflight') return;

    // 6. IP Whitelist / Blacklist
    const ipError = handleIpRules(config.ipRules, req);
    if (ipError) return res.status(ipError.code).json(ipError);

    // Next middleware
    next();
  };

  // TODO: Add Fastify support

  return expressMiddleware;
} 