import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import { AppConfig } from '../config/configuration';
import { AuthorizeDto } from './dto/authorize.dto';
import { TokenRequestDto } from './dto/token-request.dto';
import { TokenService, TokenPayload } from './token/token.service';
import { ClientCredentialsStrategy } from './strategies/client-credentials.strategy';

@Injectable()
export class AuthService {
  private readonly issuer: string;

  constructor(
    private readonly tokenService: TokenService,
    private readonly clientStrategy: ClientCredentialsStrategy,
    private readonly config: ConfigService<AppConfig>,
  ) {
    this.issuer = this.config.get<string>('issuer')!;
  }

  // ── GET /auth/authorize ────────────────────────────────────────────────────

  buildAuthorizationRedirect(dto: AuthorizeDto): string {
    if (dto.response_type !== 'code') {
      throw new BadRequestException('Only response_type=code is supported');
    }
    if (!this.clientStrategy.findClient(dto.client_id)) {
      throw new BadRequestException(`Unknown client_id: ${dto.client_id}`);
    }

    const launchContext: Record<string, unknown> | undefined = dto.launch
      ? { launch: dto.launch, iss: dto.iss ?? '' }
      : undefined;

    const code = this.tokenService.storeAuthCode({
      clientId: dto.client_id,
      redirectUri: dto.redirect_uri,
      scope: dto.scope,
      sub: 'user-001', // POC: hardcoded subject; real system uses authenticated session
      launchContext,
    });

    const url = new URL(dto.redirect_uri);
    url.searchParams.set('code', code);
    url.searchParams.set('state', dto.state);
    return url.toString();
  }

  // ── POST /auth/token dispatcher ────────────────────────────────────────────

  handleTokenRequest(dto: TokenRequestDto): object {
    switch (dto.grant_type) {
      case 'authorization_code':
        return this.handleAuthorizationCode(dto);
      case 'client_credentials':
        return this.handleClientCredentials(dto);
      case 'refresh_token':
        return this.handleRefreshToken(dto);
      case 'urn:ietf:params:oauth:grant-type:jwt-bearer':
        return this.handleJwtBearer(dto);
      default:
        throw new BadRequestException(`Unsupported grant_type: ${dto.grant_type}`);
    }
  }

  // ── authorization_code ─────────────────────────────────────────────────────

  private handleAuthorizationCode(dto: TokenRequestDto): object {
    if (!dto.code) throw new BadRequestException('Missing code');
    if (!dto.client_id) throw new BadRequestException('Missing client_id');

    const record = this.tokenService.consumeAuthCode(dto.code);
    if (!record) {
      throw new BadRequestException('Invalid or expired authorization code');
    }
    if (record.clientId !== dto.client_id) {
      throw new UnauthorizedException('client_id mismatch');
    }
    if (record.redirectUri !== dto.redirect_uri) {
      throw new BadRequestException('redirect_uri mismatch');
    }

    const accessToken = this.tokenService.createAccessToken({
      sub: record.sub,
      audience: `${this.issuer}/fhir`,
      scope: record.scope,
      clientId: record.clientId,
      launchContext: record.launchContext,
    });

    const refreshToken = this.tokenService.createRefreshToken({
      sub: record.sub,
      clientId: record.clientId,
      scope: record.scope,
    });

    const { jti } = jwt.decode(refreshToken) as { jti: string };
    this.tokenService.trackRefreshToken(jti, {
      sub: record.sub,
      clientId: record.clientId,
      scope: record.scope,
    });

    return this.buildTokenResponse(accessToken, record.scope, refreshToken);
  }

  // ── client_credentials ─────────────────────────────────────────────────────

  private handleClientCredentials(dto: TokenRequestDto): object {
    if (!dto.client_id || !dto.client_secret) {
      throw new UnauthorizedException('Missing client credentials');
    }
    if (!this.clientStrategy.validateClient(dto.client_id, dto.client_secret)) {
      throw new UnauthorizedException('Invalid client credentials');
    }

    const scope = dto.scope ?? 'system/*.read';
    const accessToken = this.tokenService.createAccessToken({
      sub: dto.client_id,
      audience: `${this.issuer}/fhir`,
      scope,
      clientId: dto.client_id,
    });

    // RFC 6749 §4.4.3: no refresh token for client_credentials
    return this.buildTokenResponse(accessToken, scope);
  }

  // ── refresh_token ──────────────────────────────────────────────────────────

  private handleRefreshToken(dto: TokenRequestDto): object {
    if (!dto.refresh_token) throw new BadRequestException('Missing refresh_token');

    let decoded: TokenPayload;
    try {
      decoded = this.tokenService.verify(dto.refresh_token, { tokenUse: 'refresh' });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    if (this.tokenService.isRefreshTokenRevoked(decoded.jti)) {
      throw new UnauthorizedException('Refresh token has been revoked');
    }

    // Rotate: revoke old, issue new AT + RT
    this.tokenService.revokeRefreshToken(decoded.jti);

    const accessToken = this.tokenService.createAccessToken({
      sub: decoded.sub,
      audience: `${this.issuer}/fhir`,
      scope: decoded.scope,
      clientId: decoded.client_id,
    });

    const newRefreshToken = this.tokenService.createRefreshToken({
      sub: decoded.sub,
      clientId: decoded.client_id ?? '',
      scope: decoded.scope,
    });

    const { jti: newJti } = jwt.decode(newRefreshToken) as { jti: string };
    this.tokenService.trackRefreshToken(newJti, {
      sub: decoded.sub,
      clientId: decoded.client_id ?? '',
      scope: decoded.scope,
    });

    return this.buildTokenResponse(accessToken, decoded.scope, newRefreshToken);
  }

  // ── jwt-bearer (service-to-service) ───────────────────────────────────────

  private handleJwtBearer(dto: TokenRequestDto): object {
    if (!dto.assertion) throw new BadRequestException('Missing assertion');

    // POC: verify the assertion with this server's own public key.
    // Production: fetch the client's registered JWKS URI to get its public key.
    let decoded: { sub?: string; iss?: string };
    try {
      decoded = jwt.verify(dto.assertion, this.tokenService.publicKeyPem, {
        algorithms: ['RS384'],
      }) as { sub?: string; iss?: string };
    } catch {
      throw new UnauthorizedException('Invalid jwt-bearer assertion');
    }

    const clientId = decoded.sub ?? decoded.iss ?? '';
    if (!clientId || !this.clientStrategy.findClient(clientId)) {
      throw new UnauthorizedException('Unknown client in jwt-bearer assertion');
    }

    const scope = dto.scope ?? 'system/*.read';
    const accessToken = this.tokenService.createAccessToken({
      sub: clientId,
      audience: `${this.issuer}/fhir`,
      scope,
      clientId,
    });

    return this.buildTokenResponse(accessToken, scope);
  }

  // ── POST /auth/introspect ──────────────────────────────────────────────────

  introspectToken(token: string): object {
    try {
      const payload = this.tokenService.verify(token);
      return {
        active: true,
        sub: payload.sub,
        scope: payload.scope,
        client_id: payload.client_id,
        token_type: 'Bearer',
        exp: payload.exp,
        iat: payload.iat,
        iss: payload.iss,
        jti: payload.jti,
      };
    } catch {
      // RFC 7662: always return { active: false } — never expose the reason
      return { active: false };
    }
  }

  // ── GET /auth/launch (EHR contextual launch) ──────────────────────────────

  buildEhrLaunchRedirect(launchParam: string, issParam: string, clientId: string): string {
    if (!launchParam) throw new BadRequestException('Missing launch parameter');

    const url = new URL(`${this.issuer}/auth/authorize`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', `${this.issuer}/auth/callback`);
    url.searchParams.set('scope', 'launch openid fhirUser patient/*.read');
    url.searchParams.set('state', 'ehr-launch-state');
    url.searchParams.set('launch', launchParam);
    url.searchParams.set('iss', issParam);
    return url.toString();
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private buildTokenResponse(
    accessToken: string,
    scope: string,
    refreshToken?: string,
  ): object {
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.tokenService.accessTokenTtl,
      scope,
      ...(refreshToken ? { refresh_token: refreshToken } : {}),
    };
  }
}