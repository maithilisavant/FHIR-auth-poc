import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as express from 'express';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // OAuth2 token endpoint requires application/x-www-form-urlencoded parsing (RFC 6749)
  app.use(express.urlencoded({ extended: false }));

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  console.log(`FHIR Auth POC running on http://localhost:${port}`);
}
bootstrap();