import {
  Controller,
  Post,
  Body,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
  Logger,
  Get,
  Query,
  Param,
  ParseIntPipe,
  DefaultValuePipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { AuditService } from './audit.service';
import { AuditRepository } from './audit.repository';
import { AuditContractDto } from './dto/audit-contract.dto';

const logger = new Logger('AuditController');

@Controller('audit')
export class AuditController {
  constructor(
    private readonly auditService: AuditService,
    private readonly auditRepository: AuditRepository,
  ) {}

  @Post('code')
  async auditCode(@Body() dto: AuditContractDto) {
    logger.log(
      `Audit contract ${dto.contractName ? `"${dto.contractName}"` : 'no name'}`,
    );

    try {
      const result = await this.auditService.analyzeContract(
        dto.code,
        dto.contractName,
      );
      logger.log(`Found ${result.summary.total} vulnerabilities`);
      return result;
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      logger.error('Error analyzing contract:', errorMessage);
      throw new BadRequestException('Failed to analyze contract');
    }
  }

  @Post('defi')
  async auditDeFiContract(@Body() dto: AuditContractDto) {
    logger.log(
      `DeFi audit contract ${dto.contractName ? `"${dto.contractName}"` : 'no name'}`,
    );

    try {
      const result = await this.auditService.analyzeDeFiContract(
        dto.code,
        dto.contractName,
      );
      logger.log(
        `Found ${result.summary.total} vulnerabilities and ${result.defiChecks.length} DeFi checks`,
      );
      return result;
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      logger.error('Error analyzing DeFi contract:', errorMessage);
      throw new BadRequestException('Failed to analyze DeFi contract');
    }
  }

  @Post('file')
  @UseInterceptors(FileInterceptor('file'))
  async auditFile(@UploadedFile() file: Express.Multer.File) {
    logger.log(`Uploaded file: ${file.originalname} (${file.size} bytes)`);

    if (!file.originalname.endsWith('.sol')) {
      throw new BadRequestException('File must have .sol extension');
    }

    const code = file.buffer.toString('utf-8');

    if (!code.trim()) {
      throw new BadRequestException('File is empty');
    }

    try {
      const result = await this.auditService.analyzeContract(
        code,
        file.originalname,
      );
      return result;
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      logger.error('Error analyzing file:', errorMessage);
      throw new BadRequestException('Failed to analyze contract file');
    }
  }

  @Get('history')
  async getAuditHistory(
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number = 1,
    @Query('limit', new DefaultValuePipe(10), ParseIntPipe) limit: number = 10,
  ) {
    return await this.auditRepository.getAuditHistory(page, limit);
  }

  @Get('history/:id')
  async getAuditById(@Param('id') id: string) {
    const audit = await this.auditRepository.findOne(id);

    if (!audit) {
      throw new BadRequestException('Audit not found');
    }

    return audit;
  }
}
