import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { SlitherRequestDto } from './dto/slither-request.dto';
import { SlitherResponse } from './interfaces/slither-vulnerability.interface';

@Injectable()
export class SlitherService {
  private readonly logger = new Logger(SlitherService.name);
  private readonly SLITHER_SERVICE_URL =
    process.env.SLITHER_SERVICE_URL || 'http://localhost:8000';

  constructor(private readonly httpService: HttpService) {}

  async analyzeWithSlither(dto: SlitherRequestDto): Promise<SlitherResponse> {
    try {
      this.logger.debug(
        `Sending contract to Slither service: ${dto.code.length} chars`,
      );

      const response = await firstValueFrom(
        this.httpService.post<SlitherResponse>(
          `${this.SLITHER_SERVICE_URL}/analyze`,
          dto,
          {
            timeout: 45000,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      );

      return response.data;
    } catch (error: unknown) {
      this.logger.error(`Slither service error`);

      // Безопасная обработка ошибок
      if (this.isAxiosError(error)) {
        const axiosError = error as any;

        if (axiosError.response) {
          const response = axiosError.response;
          this.logger.error(`Slither response status: ${response.status}`);

          let errorDetail = 'Unknown error';
          if (response.data) {
            if (typeof response.data === 'string') {
              errorDetail = response.data;
            } else if (typeof response.data === 'object') {
              errorDetail =
                response.data.detail ||
                response.data.error ||
                response.data.message ||
                JSON.stringify(response.data);
            }
          }

          this.logger.error(`Slither response data: ${errorDetail}`);

          throw new HttpException(
            `Slither analysis failed: ${errorDetail}`,
            HttpStatus.BAD_GATEWAY,
          );
        } else if (axiosError.request) {
          throw new HttpException(
            'Slither service is unavailable',
            HttpStatus.SERVICE_UNAVAILABLE,
          );
        }
      }

      // Общая ошибка
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      throw new HttpException(
        `Failed to send request to Slither: ${errorMessage}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  private isAxiosError(error: unknown): boolean {
    return (
      error !== null &&
      typeof error === 'object' &&
      'isAxiosError' in error &&
      (error as any).isAxiosError === true
    );
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await firstValueFrom(
        this.httpService.get<{ status: string }>(
          `${this.SLITHER_SERVICE_URL}/health`,
          {
            timeout: 5000,
          },
        ),
      );

      return response.data.status === 'healthy';
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      this.logger.warn(`Slither health check failed: ${errorMessage}`);
      return false;
    }
  }
}
