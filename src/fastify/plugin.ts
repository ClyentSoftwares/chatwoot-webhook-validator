import { FastifyPluginCallback } from 'fastify';
import fp from 'fastify-plugin';
import { ChatwootWebhookValidator } from '../core/validator';
import { ValidatorOptions } from '../core/types';

interface ChatwootWebhookOptions extends ValidatorOptions {
  hmacToken: string;
}

declare module 'fastify' {
  interface FastifyContextConfig {
    validateChatwootWebhook?: boolean;
  }
}

const chatwootWebhookPlugin: FastifyPluginCallback<ChatwootWebhookOptions> = (
  fastify,
  options,
  done
) => {
  const validator = new ChatwootWebhookValidator(options.hmacToken, options);

  fastify.addHook('onRoute', (routeOptions) => {
    if (routeOptions.config?.validateChatwootWebhook) {
      const preHandler = Array.isArray(routeOptions.preHandler)
        ? routeOptions.preHandler
        : routeOptions.preHandler
        ? [routeOptions.preHandler]
        : [];

      routeOptions.preHandler = [
        ...preHandler,
        async (request, reply) => {
          const signature =
            request.headers[validator.signatureHeader.toLowerCase()];
          const timestamp = parseInt(
            request.headers[validator.timestampHeader.toLowerCase()] as string,
            10
          );
          const rawBody = request.body;

          if (!signature || !timestamp || !rawBody) {
            reply.code(401).send({
              error: 'Missing required webhook headers',
            });
            return;
          }

          const result = validator.validate(
            typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody),
            Array.isArray(signature) ? signature[0] : signature,
            timestamp
          );

          if (!result.isValid) {
            reply.code(401).send({
              error: result.error || 'Invalid webhook signature',
            });
            return;
          }
        },
      ];
    }
  });

  done();
};

export default fp(chatwootWebhookPlugin, {
  name: '@clyent/chatwoot-webhook-validator',
  fastify: '5.x',
});
