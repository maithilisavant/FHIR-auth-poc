import { Controller, Get, UseGuards } from '@nestjs/common';
import { FhirApiService } from './fhir-api.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ScopesGuard } from '../auth/guards/scopes.guard';
import { RequireScopes } from '../auth/decorators/scopes.decorator';

@Controller('fhir')
export class FhirApiController {
  constructor(private readonly fhirApiService: FhirApiService) {}

  /**
   * GET /fhir/metadata
   * Public FHIR capability statement — no auth required.
   * Clients read this to discover the OAuth2/SMART endpoints before authenticating.
   */
  @Get('metadata')
  metadata(): object {
    return this.fhirApiService.getCapabilityStatement();
  }

  /**
   * GET /fhir/Patient
   * Protected FHIR resource — requires:
   *   1. A valid RS384-signed Bearer access token  (JwtAuthGuard)
   *   2. The token's scope includes 'patient/*.read' (ScopesGuard)
   */
  @Get('Patient')
  @UseGuards(JwtAuthGuard, ScopesGuard)
  @RequireScopes('patient/*.read')
  getPatients(): object {
    return this.fhirApiService.getMockPatients();
  }
}