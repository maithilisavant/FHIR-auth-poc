import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { TokenService, TokenPayload } from '../token/token.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(tokenService: TokenService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: tokenService.publicKeyPem,
      algorithms: ['RS384'],
      issuer: tokenService.issuerUrl,
    });
  }

  validate(payload: TokenPayload): TokenPayload {
    if (payload.token_use !== 'access') {
      throw new UnauthorizedException('Invalid token_use: access token required');
    }
    return payload; // attached to request.user
  }
}