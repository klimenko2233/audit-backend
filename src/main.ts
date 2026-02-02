import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
  );

  app.enableCors({
    origin: 'http://localhost:3000',
    methods: 'GET,POST',
    credentials: true,
  });

  await app.listen(4000);
  console.log('🚀 Audit backend run on http://localhost:4000');
}
bootstrap().catch((error) => {
  console.error('Error when starting the server:', error);
  process.exit(1);
});
