import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { FhirApiModule } from './fhir-api/fhir-api.module';
import { WellKnownModule } from './well-known/well-known.module';
import configuration from './config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({ load: [configuration], isGlobal: true }),
    AuthModule,
    FhirApiModule,
    WellKnownModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
