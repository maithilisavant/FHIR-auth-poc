import { Module } from '@nestjs/common';
import { WellKnownController } from './well-known.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule], // AuthModule exports TokenService
  controllers: [WellKnownController],
})
export class WellKnownModule {}