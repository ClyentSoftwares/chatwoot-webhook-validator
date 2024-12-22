# @clyent/chatwoot-webhook-validator

A secure webhook validation library for Chatwoot, supporting Express and Fastify.

## Installation

```bash
npm install @clyent/chatwoot-webhook-validator
```

## Usage

### Core Validator

```typescript
import { ChatwootWebhookValidator } from '@clyent/chatwoot-webhook-validator';

const validator = new ChatwootWebhookValidator('your-hmac-token');
const result = validator.validate(rawBody, signature, timestamp);

if (result.isValid) {
  // Process webhook
} else {
  // Handle invalid webhook
}
```

### Express Middleware

```typescript
import express from 'express';
import { createChatwootWebhookMiddleware } from '@clyent/chatwoot-webhook-validator';

const app = express();
const webhookMiddleware = createChatwootWebhookMiddleware('your-hmac-token');

// Important: You need to use the raw body for HMAC validation
app.use('/webhook', webhookMiddleware, (req, res) => {
  // Your webhook handler
});
```

### Fastify Plugin

```typescript
import Fastify from 'fastify';
import chatwootWebhookPlugin from '@clyent/chatwoot-webhook-validator';

const fastify = Fastify();

// Register the plugin
await fastify.register(chatwootWebhookPlugin, {
  hmacToken: 'your-hmac-token',
});

// Define your route
fastify.post('/webhook', {
  config: {
    validateChatwootWebhook: true, // Enable webhook validation for this route
  },
  handler: async (request, reply) => {
    // Your webhook handler
  },
});
```

## Configuration Options

```typescript
interface ValidatorOptions {
  maxAge?: number; // Maximum age of webhook timestamp in seconds (default: 300)
  signatureHeader?: string; // Custom signature header (default: 'x-chatwoot-signature')
  timestampHeader?: string; // Custom timestamp header (default: 'x-chatwoot-timestamp')
}
```

## Fork Information

This package is specifically designed for use with our fork of Chatwoot: [github.com/clyentsoftwares/chatwoot](https://github.com/clyentsoftwares/chatwoot)

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

## Contributing

We welcome contributions! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details
