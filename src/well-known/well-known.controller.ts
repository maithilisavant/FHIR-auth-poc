import { Controller, Get } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/configuration';
import { TokenService } from '../auth/token/token.service';

@Controller('.well-known')
export class WellKnownController {
  private readonly issuer: string;

  constructor(
    private readonly tokenService: TokenService,
    private readonly config: ConfigService<AppConfig>,
  ) {
    this.issuer = this.config.get<string>('issuer')!;
  }

  /**
   * GET /.well-known/smart-configuration
   * SMART on FHIR v2 discovery document (HL7 SMART App Launch / RFC 8414).
   * Clients fetch this to discover the authorization and token endpoints.
   */
  @Get('smart-configuration')
  smartConfiguration(): object {
    return {
      issuer: this.issuer,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      authorization_endpoint: `${this.issuer}/auth/authorize`,
      token_endpoint: `${this.issuer}/auth/token`,
      introspection_endpoint: `${this.issuer}/auth/introspect`,
      grant_types_supported: [
        'authorization_code',
        'client_credentials',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:jwt-bearer',
      ],
      scopes_supported: [
        'openid',
        'profile',
        'fhirUser',
        'launch',
        'launch/patient',
        'patient/*.read',
        'patient/*.write',
        'user/*.read',
        'user/*.write',
        'system/*.read',
        'system/*.write',
      ],
      response_types_supported: ['code'],
      token_endpoint_auth_methods_supported: [
        'client_secret_post',
        'private_key_jwt',
      ],
      code_challenge_methods_supported: ['S256'],
      capabilities: [
        'launch-ehr',
        'launch-standalone',
        'client-public',
        'client-confidential-symmetric',
        'sso-openid-connect',
        'context-ehr-patient',
        'permission-patient',
        'permission-user',
        'permission-offline',
      ],
    };
  }

  /**
   * GET /.well-known/jwks.json
   * Public key set used to verify JWTs issued by this server.
   * Consumers (resource servers, clients) fetch this to validate token signatures.
   */
  @Get('jwks.json')
  jwks(): object {
    return this.tokenService.getJwks();
  }
}