import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class ScopesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredScopes = this.reflector.getAllAndOverride<string[]>(
      'required_scopes',
      [context.getHandler(), context.getClass()],
    );

    if (!requiredScopes || requiredScopes.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const userScopes: string[] = (request.user?.scope ?? '').split(' ').filter(Boolean);

    const missingScopes = requiredScopes.filter((s) => !userScopes.includes(s));

    if (missingScopes.length > 0) {
      throw new ForbiddenException(
        `Insufficient scopes. Required: [${requiredScopes.join(', ')}]. Missing: [${missingScopes.join(', ')}].`,
      );
    }

    return true;
  }
}