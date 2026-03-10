import { Injectable } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';

// ─── Public interfaces ────────────────────────────────────────────────────────

export interface AuthCodeParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  sub: string;
  launchContext?: Record<string, unknown>;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

export interface RefreshTokenParams {
  sub: string;
  clientId: string;
  scope: string;
}

// ─── Internal ─────────────────────────────────────────────────────────────────

interface StoredAuthCode {
  params: AuthCodeParams;
  expiresAt: number;
}

const AUTH_CODE_TTL_MS = 60_000; // 60 s per spec

// ─── Service ──────────────────────────────────────────────────────────────────

@Injectable()
export class TokenStoreService {
  private readonly authCodes = new Map<string, StoredAuthCode>();
  private readonly refreshJtis = new Map<string, RefreshTokenParams>();

  // ─── Auth code store ───────────────────────────────────────────────────────

  storeAuthCode(params: AuthCodeParams): string {
    const code = uuidv4();
    this.authCodes.set(code, { params, expiresAt: Date.now() + AUTH_CODE_TTL_MS });
    return code;
  }

  /**
   * Consume is single-use and replay-safe: the entry is deleted *before*
   * inspecting expiry, so any duplicate call for the same code gets null
   * regardless of timing.
   */
  consumeAuthCode(code: string): AuthCodeParams | null {
    const entry = this.authCodes.get(code);
    this.authCodes.delete(code); // delete first — replay protection

    if (!entry) return null;
    if (Date.now() > entry.expiresAt) return null;

    return entry.params;
  }

  // ─── Refresh token JTI tracking ───────────────────────────────────────────

  trackRefreshToken(jti: string, params: RefreshTokenParams): void {
    this.refreshJtis.set(jti, params);
  }

  /** A JTI absent from the map is treated as revoked (unknown = revoked). */
  isRefreshTokenRevoked(jti: string): boolean {
    return !this.refreshJtis.has(jti);
  }

  revokeRefreshToken(jti: string): void {
    this.refreshJtis.delete(jti);
  }
}