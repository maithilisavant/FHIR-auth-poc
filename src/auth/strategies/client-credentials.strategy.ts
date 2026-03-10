import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../../config/configuration';

type ClientConfig = AppConfig['clients'][number];

@Injectable()
export class ClientCredentialsStrategy {
  private readonly clients: ClientConfig[];

  constructor(config: ConfigService<AppConfig>) {
    this.clients = config.get<AppConfig['clients']>('clients') ?? [];
  }

  validateClient(clientId: string, clientSecret: string): boolean {
    const client = this.findClient(clientId);
    return client !== undefined && client.clientSecret === clientSecret;
  }

  findClient(clientId: string): ClientConfig | undefined {
    return this.clients.find((c) => c.clientId === clientId);
  }

  clientSupportsGrant(clientId: string, grantType: string): boolean {
    const client = this.findClient(clientId);
    return client !== undefined && client.grantTypes.includes(grantType);
  }
}
