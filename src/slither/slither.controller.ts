import { Controller, Post, Body, Get } from '@nestjs/common';
import { SlitherService } from './slither.service';
import { SlitherRequestDto } from './dto/slither-request.dto';

@Controller('slither')
export class SlitherController {
  constructor(private readonly slitherService: SlitherService) {}

  @Post('analyze')
  async analyze(@Body() dto: SlitherRequestDto) {
    return this.slitherService.analyzeWithSlither(dto);
  }

  @Get('health')
  async health() {
    const isHealthy = await this.slitherService.healthCheck();
    return {
      service: 'slither',
      status: isHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
    };
  }
}
