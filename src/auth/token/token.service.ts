import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { AppConfig } from '../../config/configuration';
import {
  TokenStoreService,
  AuthCodeParams,
  RefreshTokenParams,
} from './token-store.service';

export type { AuthCodeParams, RefreshTokenParams };

// ─── Payload ─────────────────────────────────────────────────────────────────

export interface TokenPayload {
  sub: string;
  iss: string;
  aud: string | string[];
  iat: number;
  exp: number;
  jti: string;
  scope: string;
  client_id?: string;
  launch_context?: Record<string, unknown>;
  token_use: 'access' | 'refresh';
}

// ─── Options ─────────────────────────────────────────────────────────────────

export interface CreateAccessTokenOptions {
  sub: string;
  audience: string | string[];
  scope: string;
  clientId?: string;
  launchContext?: Record<string, unknown>;
}

export interface CreateRefreshTokenOptions {
  sub: string;
  clientId: string;
  scope: string;
}

export interface VerifyOptions {
  tokenUse?: 'access' | 'refresh';
}

// ─── Service ──────────────────────────────────────────────────────────────────

@Injectable()
export class TokenService {
  private readonly _privateKey: string;
  private readonly _publicKey: string;
  private readonly _keyId: string;
  private readonly _issuer: string;
  private readonly _accessTtl: number;
  private readonly _refreshTtl: number;

  constructor(
    private readonly config: ConfigService<AppConfig>,
    private readonly store: TokenStoreService,
  ) {
    const rsa = this.config.get<AppConfig['rsa']>('rsa')!;
    this._privateKey = rsa.privateKey;
    this._publicKey = rsa.publicKey;
    this._keyId = rsa.keyId;

    this._issuer = this.config.get<string>('issuer')!;

    const tokens = this.config.get<AppConfig['tokens']>('tokens')!;
    this._accessTtl = tokens.accessTtl;
    this._refreshTtl = tokens.refreshTtl;
  }

  // ─── Token creation ────────────────────────────────────────────────────────

  createAccessToken(opts: CreateAccessTokenOptions): string {
    const { sub, audience, scope, clientId, launchContext } = opts;

    const extra: Record<string, unknown> = { scope, token_use: 'access' };
    if (clientId) extra.client_id = clientId;
    if (launchContext) extra.launch_context = launchContext;

    return jwt.sign(extra, this._privateKey, {
      algorithm: 'RS384',
      keyid: this._keyId,
      subject: sub,
      issuer: this._issuer,
      audience,
      expiresIn: this._accessTtl,
      jwtid: uuidv4(),
    });
  }

  createRefreshToken(opts: CreateRefreshTokenOptions): string {
    const { sub, clientId, scope } = opts;

    return jwt.sign(
      { scope, token_use: 'refresh', client_id: clientId },
      this._privateKey,
      {
        algorithm: 'RS384',
        keyid: this._keyId,
        subject: sub,
        issuer: this._issuer,
        audience: this._issuer, // aud = issuer for refresh tokens
        expiresIn: this._refreshTtl,
        jwtid: uuidv4(),
      },
    );
  }

  // ─── Verification ──────────────────────────────────────────────────────────

  verify(token: string, opts: VerifyOptions = {}): TokenPayload {
    // jwt.verify throws JsonWebTokenError / TokenExpiredError on any failure
    const decoded = jwt.verify(token, this._publicKey, {
      algorithms: ['RS384'],
      issuer: this._issuer,
    }) as TokenPayload;

    if (opts.tokenUse && decoded.token_use !== opts.tokenUse) {
      throw new Error(
        `token_use mismatch: expected '${opts.tokenUse}', got '${decoded.token_use}'`,
      );
    }

    return decoded;
  }

  // ─── JWKS ──────────────────────────────────────────────────────────────────

  getJwks(): { keys: Record<string, unknown>[] } {
    const jwk = crypto
      .createPublicKey(this._publicKey)
      .export({ format: 'jwk' }) as Record<string, unknown>;

    return {
      keys: [{ ...jwk, use: 'sig', alg: 'RS384', kid: this._keyId }],
    };
  }

  // ─── Getters ───────────────────────────────────────────────────────────────

  get publicKeyPem(): string {
    return this._publicKey;
  }

  get keyIdValue(): string {
    return this._keyId;
  }

  get issuerUrl(): string {
    return this._issuer;
  }

  get accessTokenTtl(): number {
    return this._accessTtl;
  }

  // ─── Auth code store (delegated) ───────────────────────────────────────────

  storeAuthCode(params: AuthCodeParams): string {
    return this.store.storeAuthCode(params);
  }

  consumeAuthCode(code: string): AuthCodeParams | null {
    return this.store.consumeAuthCode(code);
  }

  // ─── Refresh token JTI store (delegated) ───────────────────────────────────

  trackRefreshToken(jti: string, params: RefreshTokenParams): void {
    this.store.trackRefreshToken(jti, params);
  }

  isRefreshTokenRevoked(jti: string): boolean {
    return this.store.isRefreshTokenRevoked(jti);
  }

  revokeRefreshToken(jti: string): void {
    this.store.revokeRefreshToken(jti);
  }
}