import { Request, Response, NextFunction, RequestHandler } from 'express';
import { ChatwootWebhookValidator } from '../core/validator';
import { ValidatorOptions } from '../core/types';

export function createChatwootWebhookMiddleware(
  hmacToken: string,
  options?: ValidatorOptions
) {
  const validator = new ChatwootWebhookValidator(hmacToken, options);
  return function validateChatwootWebhook(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    const signature = req.get(validator.signatureHeader);
    const timestamp = parseInt(req.get(validator.timestampHeader) || '', 10);
    const rawBody = req.body;

    if (!signature || !timestamp || !rawBody) {
      return res.status(401).json({
        error: 'Missing required webhook headers',
      });
    }

    let bodyStr: string;
    if (Buffer.isBuffer(rawBody)) {
      bodyStr = rawBody.toString('utf8');
    } else if (typeof rawBody === 'string') {
      bodyStr = rawBody;
    } else {
      bodyStr = JSON.stringify(rawBody);
    }

    const result = validator.validate(bodyStr, signature, timestamp);

    if (!result.isValid) {
      return res.status(401).json({
        error: result.error || 'Invalid webhook signature',
      });
    }

    next();
  } as RequestHandler;
}
