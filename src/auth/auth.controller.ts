import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { AuthorizeDto } from './dto/authorize.dto';
import { IntrospectDto } from './dto/introspect.dto';
import { TokenRequestDto } from './dto/token-request.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * GET /auth/authorize
   * OAuth2 Authorization Code flow entry point.
   * POC: auto-approves and redirects immediately with code.
   * Real system: render login/consent UI, then redirect on approval.
   */
  @Get('authorize')
  authorize(@Query() query: AuthorizeDto, @Res() res: Response): void {
    const redirectUrl = this.authService.buildAuthorizationRedirect(query);
    res.redirect(302, redirectUrl);
  }

  /**
   * POST /auth/token
   * Token endpoint — handles all grant types:
   *   - authorization_code
   *   - client_credentials
   *   - refresh_token
   *   - urn:ietf:params:oauth:grant-type:jwt-bearer
   *
   * Accepts application/x-www-form-urlencoded per OAuth2 spec (RFC 6749).
   */
  @Post('token')
  @HttpCode(200)
  token(@Body() body: TokenRequestDto): object {
    return this.authService.handleTokenRequest(body);
  }

  /**
   * POST /auth/introspect
   * RFC 7662 token introspection — returns { active: true|false }.
   * Always returns 200; never throws on invalid tokens.
   */
  @Post('introspect')
  @HttpCode(200)
  introspect(@Body() body: IntrospectDto): object {
    return this.authService.introspectToken(body.token);
  }

  /**
   * GET /auth/launch
   * EHR contextual launch entry point.
   * The EHR system redirects here with ?launch=<token>&iss=<ehr-url>&client_id=<id>
   * This endpoint validates the launch token and kicks off the authorization code flow.
   */
  @Get('launch')
  launch(
    @Query('launch') launchParam: string,
    @Query('iss') issParam: string,
    @Query('client_id') clientId: string,
    @Res() res: Response,
  ): void {
    const redirectUrl = this.authService.buildEhrLaunchRedirect(
      launchParam,
      issParam,
      clientId,
    );
    res.redirect(302, redirectUrl);
  }
}