import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TokenService } from './token/token.service';
import { TokenStoreService } from './token/token-store.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { ClientCredentialsStrategy } from './strategies/client-credentials.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ScopesGuard } from './guards/scopes.guard';

@Module({
  imports: [PassportModule.register({ defaultStrategy: 'jwt' })],
  providers: [
    AuthService,
    TokenService,
    TokenStoreService,
    JwtStrategy,
    ClientCredentialsStrategy,
    JwtAuthGuard,
    ScopesGuard,
  ],
  controllers: [AuthController],
  exports: [TokenService, JwtAuthGuard, ScopesGuard],
})
export class AuthModule {}