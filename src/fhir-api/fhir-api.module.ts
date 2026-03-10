import { Module } from '@nestjs/common';
import { FhirApiController } from './fhir-api.controller';
import { FhirApiService } from './fhir-api.service';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule], // provides JwtAuthGuard and ScopesGuard via exports
  controllers: [FhirApiController],
  providers: [FhirApiService],
})
export class FhirApiModule {}