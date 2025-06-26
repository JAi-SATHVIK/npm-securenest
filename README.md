# SecureNest

[![npm version](https://img.shields.io/npm/v/@jaya-sathvik/securenest.svg?style=flat)](https://www.npmjs.com/package/@jaya-sathvik/securenest)
[![build status](https://img.shields.io/github/actions/workflow/status/your-org/securenest/ci.yml?branch=main)](https://github.com/your-org/securenest/actions)
[![test status](https://img.shields.io/badge/tests-passing-brightgreen)](#)

**SecureNest** is a secure, pluggable, and developer-friendly middleware for Express and Fastify that wraps REST API endpoints with built-in validation and protection. It provides schema validation, rate limiting, authentication, CORS, method enforcement, and IP filtering—all with a simple, unified config.

---

## ✨ Features
- **Schema Validation** (Zod-powered for `body`, `query`, `params`)
- **Rate Limiting** (IP-based, per-endpoint, in-memory)
- **HTTP Method Enforcement** (allow only specific HTTP methods)
- **Token-Based Authentication** (JWT or Bearer, with secret or custom verify)
- **CORS Control** (per-route, customizable)
- **IP Whitelist / Blacklist** (allow/block specific IPs or CIDRs)
- **Universal Error Format** (standardized JSON errors)
- **Works with Express and Fastify**
- **Zero/minimal runtime dependencies**
- **Fully unit tested**

---

## 📦 Installation

```bash
npm install @jaya-sathvik/securenest zod
```

> **Note:** You must also have `express` or `fastify` installed in your project.

---

## 🚀 Usage

### Express Example
```ts
import express from 'express';
import { z } from 'zod';
import { secureNest } from '@jaya-sathvik/securenest';

const app = express();
app.use(express.json());

app.post('/login',
  secureNest({
    schema: { body: z.object({ email: z.string().email(), password: z.string().min(6) }) },
    auth: { required: true, strategy: 'jwt', secret: 'my_jwt_secret' },
    rateLimit: { windowMs: 60000, max: 10 },
    cors: { origin: ['https://myapp.com'] },
    allowMethods: ['POST'],
    ipRules: { allow: ['1.2.3.4'], block: ['5.6.7.0/24'] },
  }),
  (req, res) => {
    res.json({ status: 'ok' });
  }
);

app.listen(3000);
```

### Fastify Example
> **Note:** Fastify support is in progress and will be available soon.

---

## ⚙️ Configuration Schema

```ts
secureNest({
  schema: {
    body?: ZodSchema<any>,
    query?: ZodSchema<any>,
    params?: ZodSchema<any>,
  },
  auth?: {
    required: boolean,
    strategy: 'jwt' | 'bearer',
    secret?: string, // for JWT
    verify?: (token: string) => any | Promise<any>, // for custom logic
  },
  rateLimit?: {
    windowMs: number, // e.g. 60000 for 1 minute
    max: number,      // max requests per window
  },
  cors?: {
    origin?: string[] | string,
    methods?: string[],
    allowedHeaders?: string[],
    exposedHeaders?: string[],
  },
  allowMethods?: string[], // e.g. ['POST']
  ipRules?: {
    allow?: string[], // IPs or CIDRs
    block?: string[], // IPs or CIDRs
  },
})
```

---

## ❗ Error Format
All errors are returned as standardized JSON:
```json
{
  "status": "error",
  "code": 400,
  "message": "Validation failed: email is required"
}
```

---

## 🧪 Testing

Run the full test suite with:
```bash
npm test
```

---

## 📚 API & Types

See the [TypeScript types](./src/index.ts) for full config and error interfaces.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or pull request.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a pull request

---

## 📄 License

MIT 