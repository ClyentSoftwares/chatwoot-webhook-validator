import { describe, it, expect } from '@jest/globals';
import Fastify from 'fastify';
import chatwootWebhookPlugin from '../src/fastify/plugin';
import crypto from 'crypto';

describe('Fastify Plugin', () => {
  const hmacToken = 'test-token';

  it('validates webhook requests correctly', async () => {
    const fastify = Fastify();
    await fastify.register(chatwootWebhookPlugin, { hmacToken });

    const body = { test: 'data' };
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = crypto
      .createHmac('sha256', hmacToken)
      .update(`${timestamp}.${JSON.stringify(body)}`)
      .digest('hex');

    fastify.post('/webhook', {
      config: { validateChatwootWebhook: true },
      handler: async () => ({ success: true }),
    });

    const response = await fastify.inject({
      method: 'POST',
      url: '/webhook',
      headers: {
        'x-chatwoot-signature': signature,
        'x-chatwoot-timestamp': timestamp.toString(),
      },
      payload: body,
    });

    expect(response.statusCode).toBe(200);
  });

  it('handles missing headers', async () => {
    const fastify = Fastify();
    await fastify.register(chatwootWebhookPlugin, { hmacToken });

    fastify.post('/webhook', {
      config: { validateChatwootWebhook: true },
      handler: async () => ({ success: true }),
    });

    const response = await fastify.inject({
      method: 'POST',
      url: '/webhook',
      payload: { test: 'data' },
    });

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.payload)).toEqual({
      error: 'Missing required webhook headers',
    });
  });

  it('handles invalid signatures', async () => {
    const fastify = Fastify();
    await fastify.register(chatwootWebhookPlugin, { hmacToken });

    fastify.post('/webhook', {
      config: { validateChatwootWebhook: true },
      handler: async () => ({ success: true }),
    });

    const response = await fastify.inject({
      method: 'POST',
      url: '/webhook',
      headers: {
        'x-chatwoot-signature': 'invalid',
        'x-chatwoot-timestamp': Date.now().toString(),
      },
      payload: { test: 'data' },
    });

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.payload)).toEqual({
      error: 'Invalid signature format',
    });
  });

  it('handles routes without validation', async () => {
    const fastify = Fastify();
    await fastify.register(chatwootWebhookPlugin, { hmacToken });

    fastify.post('/webhook', {
      config: { validateChatwootWebhook: false },
      handler: async () => ({ success: true }),
    });

    const response = await fastify.inject({
      method: 'POST',
      url: '/webhook',
      payload: { test: 'data' },
    });

    expect(response.statusCode).toBe(200);
  });
});
