import { describe, it, expect } from '@jest/globals';
import crypto from 'crypto';
import { ChatwootWebhookValidator } from '../src/core/validator';

describe('ChatwootWebhookValidator', () => {
  const hmacToken = 'test-token';
  const validator = new ChatwootWebhookValidator(hmacToken);

  it('validates a correct signature', () => {
    const body = JSON.stringify({ test: 'data' });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = crypto
      .createHmac('sha256', hmacToken)
      .update(`${timestamp}.${body}`)
      .digest('hex');

    const result = validator.validate(body, signature, timestamp);
    expect(result.isValid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('rejects expired timestamps', () => {
    const body = JSON.stringify({ test: 'data' });
    const timestamp = Math.floor(Date.now() / 1000) - 301; // Expired
    const signature = crypto
      .createHmac('sha256', hmacToken)
      .update(`${timestamp}.${body}`)
      .digest('hex');

    const result = validator.validate(body, signature, timestamp);
    expect(result.isValid).toBe(false);
    expect(result.error).toBe('Timestamp expired');
  });

  it('handles invalid signature format', () => {
    const body = JSON.stringify({ test: 'data' });
    const timestamp = Math.floor(Date.now() / 1000);

    const result = validator.validate(body, 'invalid-signature', timestamp);
    expect(result.isValid).toBe(false);
    expect(result.error).toBe('Invalid signature format');
  });

  it('uses custom options correctly', () => {
    const customValidator = new ChatwootWebhookValidator(hmacToken, {
      maxAge: 600,
      signatureHeader: 'custom-signature',
      timestampHeader: 'custom-timestamp',
    });

    expect(customValidator.signatureHeader).toBe('custom-signature');
    expect(customValidator.timestampHeader).toBe('custom-timestamp');
  });
});
