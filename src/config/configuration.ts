import { Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface AppConfig {
  port: number;
  issuer: string;
  rsa: {
    privateKey: string;
    publicKey: string;
    keyId: string;
  };
  tokens: {
    accessTtl: number;
    refreshTtl: number;
  };
  clients: Array<{
    clientId: string;
    clientSecret: string;
    grantTypes: string[];
  }>;
}

export default (): AppConfig => {
  const logger = new Logger('Configuration');

  let privateKey: string;
  let publicKey: string;

  if (process.env.RSA_PRIVATE_KEY_B64) {
    privateKey = Buffer.from(process.env.RSA_PRIVATE_KEY_B64, 'base64').toString('utf8');
    const keyObj = crypto.createPrivateKey(privateKey);
    publicKey = crypto.createPublicKey(keyObj).export({ type: 'spki', format: 'pem' }) as string;
  } else {
    logger.warn(
      'RSA_PRIVATE_KEY_B64 not set — generating ephemeral RSA-2048 key pair. DO NOT use in production.',
    );
    const generated = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    privateKey = generated.privateKey;
    publicKey = generated.publicKey;
  }

  const rawClients = process.env.CLIENTS_JSON;
  const clients: AppConfig['clients'] = rawClients
    ? JSON.parse(rawClients)
    : [
        {
          clientId: process.env.CLIENT_ID ?? 'fhir-client',
          clientSecret: process.env.CLIENT_SECRET ?? 'secret',
          grantTypes: [
            'authorization_code',
            'client_credentials',
            'refresh_token',
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
          ],
        },
      ];

  return {
    port: parseInt(process.env.PORT ?? '3000', 10),
    issuer: process.env.ISSUER ?? 'http://localhost:3000',
    rsa: {
      privateKey,
      publicKey,
      keyId: 'fhir-auth-poc-key-1',
    },
    tokens: {
      accessTtl: parseInt(process.env.ACCESS_TTL ?? '300', 10),    // 5 min default
      refreshTtl: parseInt(process.env.REFRESH_TTL ?? '86400', 10), // 24 h default
    },
    clients,
  };
};
