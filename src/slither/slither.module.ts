import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { SlitherController } from './slither.controller';
import { SlitherService } from './slither.service';

@Module({
  imports: [
    HttpModule.register({
      timeout: 60000,
      maxRedirects: 5,
    }),
  ],
  controllers: [SlitherController],
  providers: [SlitherService],
  exports: [SlitherService],
})
export class SlitherModule {}
