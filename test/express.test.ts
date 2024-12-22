import { describe, it, expect, jest } from '@jest/globals';
import { createChatwootWebhookMiddleware } from '../src/express/middleware';
import crypto from 'crypto';

describe('Express Middleware', () => {
  const hmacToken = 'test-token';
  const middleware = createChatwootWebhookMiddleware(hmacToken);

  const mockResponse = () => {
    const res: any = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    return res;
  };

  const mockNext = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('handles missing headers', () => {
    const req = {
      get: jest.fn().mockReturnValue(null),
      body: { test: 'data' },
    };
    const res = mockResponse();

    middleware(req as any, res as any, mockNext);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Missing required webhook headers',
    });
  });

  it('processes Buffer body correctly', () => {
    const body = Buffer.from(JSON.stringify({ test: 'data' }));
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = crypto
      .createHmac('sha256', hmacToken)
      .update(`${timestamp}.${body.toString('utf8')}`)
      .digest('hex');

    const req = {
      get: jest.fn((header) => {
        if (header === 'x-chatwoot-signature') return signature;
        if (header === 'x-chatwoot-timestamp') return timestamp.toString();
        return null;
      }),
      body,
    };
    const res = mockResponse();

    middleware(req as any, res as any, mockNext);
    expect(mockNext).toHaveBeenCalled();
  });

  it('processes string body correctly', () => {
    const body = 'raw string data';
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = crypto
      .createHmac('sha256', hmacToken)
      .update(`${timestamp}.${body}`)
      .digest('hex');

    const req = {
      get: jest.fn((header) => {
        if (header === 'x-chatwoot-signature') return signature;
        if (header === 'x-chatwoot-timestamp') return timestamp.toString();
        return null;
      }),
      body,
    };
    const res = mockResponse();

    middleware(req as any, res as any, mockNext);
    expect(mockNext).toHaveBeenCalled();
  });

  it('handles invalid signature', () => {
    const req = {
      get: jest.fn((header) => {
        if (header === 'x-chatwoot-signature') return 'invalid';
        if (header === 'x-chatwoot-timestamp') return Date.now().toString();
        return null;
      }),
      body: { test: 'data' },
    };
    const res = mockResponse();

    middleware(req as any, res as any, mockNext);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Invalid signature format',
    });
  });
});
