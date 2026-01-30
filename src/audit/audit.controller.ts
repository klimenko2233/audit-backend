import {
  Controller,
  Post,
  Body,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
  MaxFileSizeValidator,
  ParseFilePipe,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { AuditService } from './audit.service';
import { AuditContractDto } from './dto/audit-contract.dto';

const logger = new Logger('AuditController');

@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Post('code')
  auditCode(@Body() dto: AuditContractDto) {
    logger.log(
      `Audit contract ${dto.contractName ? `"${dto.contractName}"` : 'no name'}`,
    );

    try {
      const result = this.auditService.analyzeContract(dto.code);
      logger.log(`Found ${result.summary.total} vulnerabilities`);
      return result;
    } catch (error) {
      logger.error('Error analyzing contract:', error);
      throw new BadRequestException('Unable to analyze the contract');
    }
  }

  @Post('file')
  @UseInterceptors(FileInterceptor('file'))
  auditFile(
    @UploadedFile(
      new ParseFilePipe({
        validators: [new MaxFileSizeValidator({ maxSize: 1024 * 100 })],
        errorHttpStatusCode: HttpStatus.BAD_REQUEST,
      }),
    )
    file: Express.Multer.File,
  ) {
    logger.log(`File uploaded: ${file.originalname} (${file.size} bytes)`);

    if (!file.originalname.endsWith('.sol')) {
      throw new BadRequestException('The file must have the extension .sol');
    }

    const code = file.buffer.toString('utf-8');

    if (code.trim().length < 10) {
      throw new BadRequestException('The file is too short or empty.');
    }

    return this.auditService.analyzeContract(code);
  }
}
