import crypto from 'crypto';
import { ValidatorOptions, ValidationResult } from './types';

export class ChatwootWebhookValidator {
  private readonly maxAge: number;
  private readonly hmacToken: string;

  readonly signatureHeader: string;
  readonly timestampHeader: string;

  constructor(hmacToken: string, options?: ValidatorOptions) {
    this.hmacToken = hmacToken;
    this.maxAge = options?.maxAge ?? 300;
    this.signatureHeader = options?.signatureHeader ?? 'x-chatwoot-signature';
    this.timestampHeader = options?.timestampHeader ?? 'x-chatwoot-timestamp';
  }

  public validate(rawBody: string, signature: string, timestamp: number): ValidationResult {
    try {
      const timestampAge = Math.floor(Date.now() / 1000) - timestamp;

      if (timestampAge > this.maxAge) {
        return { isValid: false, error: 'Timestamp expired' };
      }

      const signaturePayload = `${timestamp}.${rawBody}`;
      const expectedSignature = crypto
        .createHmac('sha256', this.hmacToken)
        .update(signaturePayload)
        .digest('hex');

      const isValid = crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      );

      return { isValid };
    } catch {
      return { isValid: false, error: 'Invalid signature format' };
    }
  }
}
